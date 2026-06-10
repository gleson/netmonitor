"""Correlação de CVEs conhecidos com serviços/versões detectados pelo nmap.

O port scan já coleta ``service_name``/``service_version`` (-sV); este módulo
consulta a API pública do NVD para essas combinações e gera Vulnerability +
Alert quando há CVE com CVSS acima do mínimo configurado. Não gera nenhum
tráfego na rede local monitorada — apenas consultas HTTPS externas, com cache
em ``cve_cache`` (TTL configurável).

Reforços de precisão e eficiência:

- **API key do NVD** (``NVD_API_KEY``): sem chave o limite é ~5 req/30s; com
  chave sobe para ~50 req/30s, e a pausa entre consultas cai de 6.5s para 0.7s.
- **Filtragem por versão (CPE)**: a busca por palavra-chave do NVD retorna
  muitos CVEs que apenas *citam* o produto mas afetam outra versão. Os
  resultados são filtrados pelas faixas de versão das configurações CPE 2.3 do
  próprio CVE, reduzindo falsos positivos. Quando o CVE não traz dados de
  versão utilizáveis, é mantido (comportamento conservador).
- **CISA KEV**: o catálogo *Known Exploited Vulnerabilities* da CISA (JSON
  público, sem autenticação) marca CVEs sob exploração ativa. CVEs em KEV viram
  alerta CRITICAL com ``is_priority=True`` mesmo que o CVSS fique abaixo do
  mínimo configurado — porque exploração ativa importa mais que o score.

Rate-limit do NVD sem API key: ~5 requisições por 30s. O job dorme entre
consultas não-cacheadas e limita o total por execução
(CVE_MAX_LOOKUPS_PER_RUN); combinações restantes ficam para a próxima rodada.
"""

import json
import logging
import re
import time
import urllib.parse
from urllib import request as urlrequest
from urllib.error import URLError

logger = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Catálogo CISA de vulnerabilidades sob exploração ativa (JSON público).
CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

# Chaves em AppSetting onde o catálogo KEV é cacheado (sem tabela/migração nova).
_KEV_SETTING_KEY = "cve.kev_catalog"
_KEV_FETCHED_KEY = "cve.kev_fetched_at"

# Pausa entre consultas não-cacheadas. Com API key o NVD permite ~50 req/30s.
_NVD_SLEEP_SECONDS = 6.5
_NVD_SLEEP_SECONDS_WITH_KEY = 0.7

# Versões genéricas demais para correlacionar (evita falso-positivo em massa).
_GENERIC_VERSIONS = {"", "unknown", "-"}


def _nvd_api_key() -> str:
    """Lê a API key do NVD da config (string vazia se não configurada)."""
    try:
        from flask import current_app
        return (current_app.config.get("NVD_API_KEY") or "").strip()
    except Exception:
        return ""


def _nvd_sleep_seconds() -> float:
    return _NVD_SLEEP_SECONDS_WITH_KEY if _nvd_api_key() else _NVD_SLEEP_SECONDS


def _extract_cvss(cve: dict) -> float | None:
    """Extrai o melhor baseScore disponível (v3.1 > v3.0 > v2) de um item do NVD."""
    metrics = cve.get("metrics", {}) or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            try:
                return float(entries[0]["cvssData"]["baseScore"])
            except (KeyError, TypeError, ValueError):
                continue
    return None


def _extract_summary(cve: dict) -> str:
    for desc in cve.get("descriptions", []) or []:
        if desc.get("lang") == "en":
            return desc.get("value", "")
    return ""


# ---------------------------------------------------------------------------
# Comparação de versões e correspondência CPE
# ---------------------------------------------------------------------------

def _version_tuple(version: str) -> tuple:
    """Converte 'X.Y.Zp1' em tupla comparável (ignora sufixos não-numéricos).

    Comparação best-effort, sem dependências externas: serve para filtrar
    faixas de versão de CPE, não para precisão semântica completa.
    """
    parts = re.split(r"[^0-9]+", (version or "").strip())
    nums = [int(p) for p in parts if p.isdigit()]
    return tuple(nums)


def _cmp_versions(a: str, b: str) -> int:
    """Retorna -1/0/1 comparando duas strings de versão numericamente."""
    ta, tb = _version_tuple(a), _version_tuple(b)
    # Normaliza comprimento para comparar (1.2 == 1.2.0).
    length = max(len(ta), len(tb))
    ta += (0,) * (length - len(ta))
    tb += (0,) * (length - len(tb))
    return (ta > tb) - (ta < tb)


def _cpe_version(criteria: str) -> str:
    """Extrai o campo 'version' (índice 5) de uma string CPE 2.3."""
    # cpe:2.3:a:vendor:product:version:update:...
    parts = (criteria or "").split(":")
    return parts[5] if len(parts) > 5 else "*"


def _cpe_match_version(cpe_match: dict, version: str) -> bool | None:
    """A versão detectada cai dentro desta entrada cpeMatch?

    Retorna True/False quando há dados de versão utilizáveis, ou None quando
    não há como decidir (CPE com versão curinga e sem faixas).
    """
    if not _version_tuple(version):
        return None  # versão não-numérica → não dá para comparar

    exact = _cpe_version(cpe_match.get("criteria", ""))
    start_inc = cpe_match.get("versionStartIncluding")
    start_exc = cpe_match.get("versionStartExcluding")
    end_inc = cpe_match.get("versionEndIncluding")
    end_exc = cpe_match.get("versionEndExcluding")

    has_range = any((start_inc, start_exc, end_inc, end_exc))

    if not has_range:
        if exact in ("*", "-", ""):
            return None  # curinga sem faixa → indeterminado
        return _cmp_versions(version, exact) == 0

    if start_inc and _cmp_versions(version, start_inc) < 0:
        return False
    if start_exc and _cmp_versions(version, start_exc) <= 0:
        return False
    if end_inc and _cmp_versions(version, end_inc) > 0:
        return False
    if end_exc and _cmp_versions(version, end_exc) >= 0:
        return False
    return True


def _cve_matches_version(cve: dict, version: str) -> bool:
    """O CVE afeta a versão detectada, segundo suas configurações CPE?

    Conservador: se o CVE não traz configurações CPE vulneráveis utilizáveis,
    retorna True (mantém o resultado em vez de descartá-lo por engano).
    """
    determinate: list[bool] = []
    for config in cve.get("configurations", []) or []:
        for node in config.get("nodes", []) or []:
            for cpe_match in node.get("cpeMatch", []) or []:
                if not cpe_match.get("vulnerable"):
                    continue
                result = _cpe_match_version(cpe_match, version)
                if result is not None:
                    determinate.append(result)
    if not determinate:
        return True  # sem dados de versão utilizáveis → mantém (conservador)
    return any(determinate)


def lookup_cves(product: str, version: str, timeout: int = 20) -> list[dict] | None:
    """Consulta o NVD por CVEs de um produto+versão.

    Os resultados são filtrados pelas faixas de versão das configurações CPE de
    cada CVE (quando disponíveis), reduzindo falsos positivos da busca textual.

    Returns:
        Lista de {"id", "cvss", "summary"} (pode ser vazia), ou None em caso
        de falha de rede/API — o chamador NÃO deve cachear None.
    """
    keyword = f"{product} {version}".strip()
    params = urllib.parse.urlencode({
        "keywordSearch": keyword,
        "resultsPerPage": 20,
    })
    url = f"{NVD_API_URL}?{params}"

    headers = {"User-Agent": "NetMonitor CVE correlator"}
    api_key = _nvd_api_key()
    if api_key:
        headers["apiKey"] = api_key

    try:
        req = urlrequest.Request(url, headers=headers)
        with urlrequest.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (URLError, TimeoutError, ValueError, OSError) as exc:
        logger.warning("Consulta CVE falhou para %r: %s", keyword, exc)
        return None

    results = []
    skipped_version = 0
    for item in data.get("vulnerabilities", []) or []:
        cve = item.get("cve", {}) or {}
        cve_id = cve.get("id")
        if not cve_id:
            continue
        if not _cve_matches_version(cve, version):
            skipped_version += 1
            continue
        results.append({
            "id": cve_id,
            "cvss": _extract_cvss(cve),
            "summary": _extract_summary(cve)[:500],
        })
    logger.info(
        "Consulta CVE para %r: %d resultado(s) (%d descartados por versão).",
        keyword, len(results), skipped_version,
    )
    return results


def get_cves_cached(product: str, version: str, ttl_days: int) -> tuple[list[dict] | None, bool]:
    """Retorna (cves, was_cached) usando o cache cve_cache com TTL.

    cves é None apenas quando a consulta à API falhou e não havia cache.
    """
    from datetime import timedelta

    from app.extensions import db
    from app.models import CveCache, _utcnow

    row = CveCache.query.filter_by(product=product, version=version).first()
    if row and row.fetched_at >= _utcnow() - timedelta(days=ttl_days):
        return row.get_cves(), True

    fetched = lookup_cves(product, version)
    if fetched is None:
        # Falha de rede: usa cache vencido se existir, sem atualizar fetched_at.
        return (row.get_cves() if row else None), bool(row)

    payload = json.dumps(fetched, ensure_ascii=False)
    if row:
        row.payload = payload
        row.fetched_at = _utcnow()
    else:
        db.session.add(CveCache(product=product, version=version, payload=payload))
    db.session.commit()
    return fetched, False


# ---------------------------------------------------------------------------
# CISA KEV — catálogo de vulnerabilidades sob exploração ativa
# ---------------------------------------------------------------------------

def update_kev_catalog(timeout: int = 30) -> int | None:
    """Baixa o catálogo CISA KEV e o armazena em AppSetting.

    Não depende de LLM nem de API key — é um feed JSON público. Pode ser
    chamado por ``flask update-kev`` (cron) ou automaticamente no início da
    correlação.

    Returns:
        Número de CVEs no catálogo, ou None em caso de falha de rede.
    """
    from app.models import AppSetting, _utcnow

    try:
        req = urlrequest.Request(
            CISA_KEV_URL, headers={"User-Agent": "NetMonitor KEV updater"},
        )
        with urlrequest.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (URLError, TimeoutError, ValueError, OSError) as exc:
        logger.warning("Atualização do catálogo CISA KEV falhou: %s", exc)
        return None

    ids = sorted({
        (item.get("cveID") or "").strip().upper()
        for item in data.get("vulnerabilities", []) or []
        if item.get("cveID")
    })
    AppSetting.set_value(_KEV_SETTING_KEY, json.dumps(ids))
    AppSetting.set_value(_KEV_FETCHED_KEY, _utcnow().isoformat())
    logger.info("Catálogo CISA KEV atualizado: %d CVEs.", len(ids))
    return len(ids)


def get_kev_set() -> set[str]:
    """Conjunto de CVE IDs (UPPER) do catálogo KEV cacheado (vazio se ausente)."""
    from app.models import AppSetting

    raw = AppSetting.get_value(_KEV_SETTING_KEY, "")
    if not raw:
        return set()
    try:
        ids = json.loads(raw)
        return {str(i).upper() for i in ids} if isinstance(ids, list) else set()
    except (ValueError, TypeError):
        return set()


def _refresh_kev_if_stale(max_age_hours: int) -> None:
    """Atualiza o catálogo KEV se o cache estiver mais velho que max_age_hours."""
    from datetime import datetime, timedelta

    from app.models import AppSetting, _utcnow

    fetched_raw = AppSetting.get_value(_KEV_FETCHED_KEY, "")
    if fetched_raw:
        try:
            fetched = datetime.fromisoformat(fetched_raw)
            if _utcnow() - fetched < timedelta(hours=max_age_hours):
                return
        except ValueError:
            pass
    update_kev_catalog()


def correlate_cves() -> dict:
    """Job diário: correlaciona portas abertas (com versão de serviço) a CVEs.

    Para cada combinação distinta (service_name, service_version) de portas
    abertas, consulta o NVD (com cache) e registra Vulnerability + Alert nos
    devices afetados quando o CVSS máximo >= CVE_MIN_CVSS_ALERT ou quando algum
    CVE está no catálogo CISA KEV (exploração ativa).

    Returns:
        Resumo: {"combos": N, "lookups": N, "vulns_created": N, "alerts": N}.
    """
    from flask import current_app

    from app.extensions import db
    from app.models import (
        Alert, AlertType, Device, Port, Profile, Severity, Vulnerability, _utcnow,
    )
    from app.scanner.scheduling import _maybe_notify

    if not current_app.config.get("CVE_LOOKUP_ENABLED", True):
        logger.info("Correlação CVE desabilitada (CVE_LOOKUP_ENABLED=0).")
        return {"combos": 0, "lookups": 0, "vulns_created": 0, "alerts": 0}

    ttl_days = int(current_app.config.get("CVE_CACHE_TTL_DAYS", 7))
    min_cvss = float(current_app.config.get("CVE_MIN_CVSS_ALERT", 7.0))
    max_lookups = int(current_app.config.get("CVE_MAX_LOOKUPS_PER_RUN", 30))

    # Catálogo KEV (atualizado sem LLM, feed público) — alimenta a priorização.
    kev_set: set[str] = set()
    if current_app.config.get("CVE_KEV_ENABLED", True):
        _refresh_kev_if_stale(int(current_app.config.get("CVE_KEV_REFRESH_HOURS", 24)))
        kev_set = get_kev_set()

    # Combinações distintas de serviço+versão em portas abertas (estado open).
    combos = (
        db.session.query(Port.service_name, Port.service_version)
        .filter(
            Port.last_seen_closed_at.is_(None),
            Port.state == "open",
            Port.service_name != "",
        )
        .distinct()
        .all()
    )

    stats = {"combos": 0, "lookups": 0, "vulns_created": 0, "alerts": 0}
    now = _utcnow()

    for service_name, service_version in combos:
        version = (service_version or "").strip()
        if version.lower() in _GENERIC_VERSIONS:
            continue  # sem versão não dá para correlacionar com segurança
        stats["combos"] += 1

        cves, was_cached = get_cves_cached(service_name.strip(), version, ttl_days)
        if not was_cached:
            stats["lookups"] += 1
            if stats["lookups"] >= max_lookups:
                logger.info("Correlação CVE: limite de %d consultas atingido; restante fica para a próxima rodada.", max_lookups)
            time.sleep(_nvd_sleep_seconds())
        if cves is None:
            continue  # falha de consulta sem cache — tenta de novo amanhã

        # Relevante: CVSS acima do mínimo OU sob exploração ativa (KEV).
        relevant = [
            c for c in cves
            if (c.get("cvss") or 0) >= min_cvss or c["id"].upper() in kev_set
        ]
        if not relevant:
            if stats["lookups"] >= max_lookups:
                break
            continue

        kev_hits = [c["id"] for c in relevant if c["id"].upper() in kev_set]
        is_kev = bool(kev_hits)
        max_cvss = max((c["cvss"] or 0) for c in relevant)
        top = sorted(relevant, key=lambda c: c["cvss"] or 0, reverse=True)[:5]
        cve_ids = ", ".join(c["id"] for c in top)

        # Devices afetados: portas abertas com esse serviço/versão.
        affected = (
            db.session.query(Port, Device)
            .join(Device, Port.device_id == Device.id)
            .filter(
                Port.last_seen_closed_at.is_(None),
                Port.state == "open",
                Port.service_name == service_name,
                Port.service_version == service_version,
            )
            .all()
        )

        for port_row, device in affected:
            script_name = f"cve:{top[0]['id']}"
            existing = Vulnerability.query.filter_by(
                device_id=device.id, port=port_row.port, script_name=script_name,
            ).filter(Vulnerability.resolved_at.is_(None)).first()

            if existing:
                existing.last_seen_at = now
                continue  # já conhecido — sem novo alerta

            kev_note = (
                f" EXPLORAÇÃO ATIVA — CISA KEV: {', '.join(kev_hits)}." if is_kev else ""
            )
            db.session.add(Vulnerability(
                device_id=device.id,
                port=port_row.port,
                protocol=port_row.protocol,
                service=service_name,
                script_name=script_name,
                output=(
                    f"{service_name} {version} — {len(relevant)} CVE(s) relevante(s) "
                    f"(CVSS máx {max_cvss}): {cve_ids}.{kev_note} {top[0]['summary']}"
                ),
                is_vulnerable=True,
            ))
            stats["vulns_created"] += 1

            severity = Severity.CRITICAL if (max_cvss >= 9.0 or is_kev) else Severity.WARNING
            profile = db.session.get(Profile, device.profile_id)
            # IP na mensagem distingue devices com o mesmo nome (ex.: dois
            # gateways "Roteador" em redes diferentes).
            device_ip = device.current_ip or "sem IP"
            kev_prefix = "[CISA KEV — EXPLORAÇÃO ATIVA] " if is_kev else ""
            alert = Alert(
                profile_id=device.profile_id,
                device_id=device.id,
                alert_type=AlertType.VULNERABILITY,
                severity=severity,
                is_priority=is_kev,
                message=(
                    f"{kev_prefix}CVE conhecido em {device.display_name} ({device_ip}): "
                    f"{service_name} {version} "
                    f"na porta {port_row.protocol}/{port_row.port} — "
                    f"CVSS máx {max_cvss} ({cve_ids})"
                ),
            )
            db.session.add(alert)
            if profile:
                _maybe_notify(alert, profile, device)
            stats["alerts"] += 1

        db.session.commit()

        if stats["lookups"] >= max_lookups:
            break

    db.session.commit()
    logger.info(
        "Correlação CVE concluída: %d combinações, %d consultas à API, %d vulnerabilidades novas, %d alertas.",
        stats["combos"], stats["lookups"], stats["vulns_created"], stats["alerts"],
    )
    return stats
