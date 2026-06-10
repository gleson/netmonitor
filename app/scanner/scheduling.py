"""Integração com APScheduler — registra e executa os jobs de scan.

Os jobs rodam em background e NÃO bloqueiam o thread de requisição Flask.
Cada job usa app_context para acessar o banco de dados.
"""

import ipaddress
import logging
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone, timedelta

from flask import Flask

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Filas de port scan por profile
# Persistem entre invocações do scheduler (reiniciadas junto com a app).
# profile_id -> deque[{"device_id", "device_display", "ip", "ports"}]
#
# Todas as mutações devem ocorrer sob _port_scan_queues_lock para evitar
# race entre o scheduler (run_port_scan) e a thread de host discovery
# (prepend_to_port_scan_queue) ou /api/scan/trigger.
# ---------------------------------------------------------------------------
_port_scan_queues: dict[int, deque] = {}
_port_scan_queues_lock = threading.Lock()

# Lock por device para scan on-demand — impede dois cliques simultâneos
# lançarem dois nmap contra o mesmo host.
_on_demand_locks: dict[int, bool] = {}
_on_demand_lock = threading.Lock()

# Contador de falhas consecutivas do quick host-down check.
# device_id -> int. Reset a 0 quando o host responde; alerta CRITICAL com
# is_priority=True é gerado quando atinge 2 (segunda falha confirma).
_quick_host_down_failures: dict[int, int] = {}
_quick_host_down_lock = threading.Lock()

# Devices que devemos re-enfileirar com scan type alternativo após "bug
# de portas sumidas". device_id -> índice na sequência de scan alternativo.
# Protegido por _port_scan_retry_lock (mutado a partir de threads do
# ThreadPoolExecutor em run_port_scan e da thread de scan on-demand).
_port_scan_retry_args: dict[int, int] = {}
_port_scan_retry_lock = threading.Lock()


def _utcnow():
    # Naive UTC — ver app.models._utcnow. APScheduler aceita aware ou naive;
    # mantemos naive para casar com os timestamps armazenados pelos modelos.
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _has_root() -> bool:
    """True quando o processo roda como root (necessário para -sS/-sU/-O)."""
    import os
    try:
        return os.geteuid() == 0
    except AttributeError:  # plataformas sem geteuid
        return False


def _remove_job_quiet(job_id: str) -> None:
    """Remove um job do scheduler ignorando inexistência (job desabilitado)."""
    from app.extensions import scheduler
    try:
        scheduler.remove_job(job_id)
    except Exception:
        pass


def register_jobs_for_all_profiles(app: Flask):
    """Registra os jobs de scan para todos os perfis ativos.

    Chamado durante a inicialização da aplicação.
    """
    from app.extensions import scheduler
    from app.models import Profile

    profiles = Profile.query.filter_by(is_active=True).all()

    for profile in profiles:
        _register_profile_jobs(app, profile)

    logger.info("Jobs registrados para %d perfis ativos.", len(profiles))


def _register_profile_jobs(app: Flask, profile):
    """Registra os jobs de um perfil específico no scheduler.

    Quando o job já existe (ex.: edição de perfil via sync_profile_jobs), preserva
    o next_run_time agendado para não disparar um scan desnecessário imediatamente.
    Na primeira vez (job inexistente), agenda o primeiro run logo após o boot.
    """
    from app.extensions import scheduler

    host_down_interval = _get_quick_host_down_interval(app)

    # --- Descobre next_run_time de jobs já existentes ---
    def _preserve_or_default(job_id: str, default_offset_s: int):
        existing = scheduler.get_job(job_id)
        if existing and existing.next_run_time is not None:
            return existing.next_run_time  # já agendado → mantém
        return _utcnow() + timedelta(seconds=default_offset_s)

    # Job de host discovery — primeiro run em 90s no boot; preserva agendamento em edições.
    # 90s dá tempo para a Wi-Fi associar/DHCP/rotas estabilizarem quando a app sobe
    # junto com a sessão; antes disso o nmap retorna 0 hosts silenciosamente.
    discovery_job_id = f"discovery_profile_{profile.id}"
    scheduler.add_job(
        func=_run_with_context,
        args=[app, run_host_discovery, profile.id],
        trigger="interval",
        minutes=profile.host_discovery_interval_minutes,
        id=discovery_job_id,
        name=f"Host Discovery - {profile.name}",
        replace_existing=True,
        max_instances=1,
        next_run_time=_preserve_or_default(discovery_job_id, 90),
    )

    # Job de port scan — primeiro run após a primeira discovery ter tempo de concluir
    portscan_job_id = f"portscan_profile_{profile.id}"
    scheduler.add_job(
        func=_run_with_context,
        args=[app, run_port_scan, profile.id],
        trigger="interval",
        minutes=profile.port_scan_interval_minutes,
        id=portscan_job_id,
        name=f"Port Scan - {profile.name}",
        replace_existing=True,
        max_instances=1,
        next_run_time=_preserve_or_default(portscan_job_id, 60),
    )

    # Job de verificação rápida HOST_DOWN (ping leve a cada N min)
    host_down_job_id = f"host_down_profile_{profile.id}"
    scheduler.add_job(
        func=_run_with_context,
        args=[app, quick_host_down_check, profile.id],
        trigger="interval",
        minutes=host_down_interval,
        id=host_down_job_id,
        name=f"Quick Host Down Check - {profile.name}",
        replace_existing=True,
        max_instances=1,
        next_run_time=_preserve_or_default(host_down_job_id, 120),
    )

    # Check rápido de portas críticas — só CRITICAL_PORTS nos devices online.
    # Detecta exposição grave (Telnet/SMB/RDP...) em horas em vez de até 24h.
    critical_job_id = f"critical_ports_profile_{profile.id}"
    critical_interval = int(app.config.get("CRITICAL_PORTS_CHECK_INTERVAL_MINUTES", 120))
    if critical_interval > 0:
        scheduler.add_job(
            func=_run_with_context,
            args=[app, critical_ports_check, profile.id],
            trigger="interval",
            minutes=critical_interval,
            id=critical_job_id,
            name=f"Critical Ports Check - {profile.name}",
            replace_existing=True,
            max_instances=1,
            next_run_time=_preserve_or_default(critical_job_id, 300),
        )
    else:
        _remove_job_quiet(critical_job_id)

    # Scan UDP periódico (requer root — -sU usa raw sockets).
    udp_job_id = f"udp_scan_profile_{profile.id}"
    udp_hours = int(app.config.get("UDP_SCAN_INTERVAL_HOURS", 168))
    if udp_hours > 0 and _has_root():
        scheduler.add_job(
            func=_run_with_context,
            args=[app, run_udp_scan, profile.id],
            trigger="interval",
            hours=udp_hours,
            id=udp_job_id,
            name=f"UDP Scan - {profile.name}",
            replace_existing=True,
            max_instances=1,
            next_run_time=_preserve_or_default(udp_job_id, 600),
        )
    else:
        _remove_job_quiet(udp_job_id)

    logger.info(
        "Jobs registrados para profile '%s': discovery=%dmin, portscan=%dmin, quick_host_down=%dmin",
        profile.name, profile.host_discovery_interval_minutes,
        profile.port_scan_interval_minutes, host_down_interval,
    )


def _get_quick_host_down_interval(app: Flask) -> int:
    """Retorna o intervalo do quick check.

    Prioridade: AppSetting('host_down_quick_check_interval') > config default.
    AppSetting permite ao admin editar sem reiniciar.
    """
    default = int(app.config.get("HOST_DOWN_QUICK_CHECK_INTERVAL_MINUTES", 5))
    try:
        from app.models import AppSetting
        return AppSetting.get_int("host_down_quick_check_interval", default)
    except Exception:
        return default


def sync_quick_host_down_jobs(app: Flask) -> None:
    """Re-agenda os jobs de quick host-down quando o intervalo é alterado no painel admin."""
    from app.extensions import scheduler
    from app.models import Profile

    if not scheduler.running:
        return

    interval = _get_quick_host_down_interval(app)
    for profile in Profile.query.filter_by(is_active=True).all():
        job_id = f"host_down_profile_{profile.id}"
        try:
            scheduler.reschedule_job(job_id, trigger="interval", minutes=interval)
            logger.info("Job '%s' re-agendado para %d min.", job_id, interval)
        except Exception:
            # Job não existe — _register_profile_jobs vai criá-lo no próximo sync
            pass


def sync_profile_jobs(app: Flask, profile) -> None:
    """Registra ou atualiza os jobs de scan de um perfil no scheduler em execução.

    Chame sempre que um perfil for criado ou editado para que o scheduler
    reflita os intervalos e configurações atuais sem precisar reiniciar a app.
    Jobs inexistentes são criados; jobs existentes são atualizados (replace_existing=True).
    Perfis inativos têm seus jobs removidos.
    """
    from app.extensions import scheduler

    if not scheduler.running:
        logger.warning("Scheduler não está rodando — jobs não atualizados para profile %d.", profile.id)
        return

    if not profile.is_active:
        remove_profile_jobs(profile.id)
        return

    _register_profile_jobs(app, profile)
    logger.info("Jobs sincronizados para profile '%s' (id=%d).", profile.name, profile.id)


def remove_profile_jobs(profile_id: int) -> None:
    """Remove os jobs do scheduler para um perfil (ex.: ao deletar ou desativar)."""
    from app.extensions import scheduler
    from apscheduler.jobstores.base import JobLookupError

    job_ids = [
        f"discovery_profile_{profile_id}",
        f"portscan_profile_{profile_id}",
        f"host_down_profile_{profile_id}",
        f"critical_ports_profile_{profile_id}",
        f"udp_scan_profile_{profile_id}",
    ]
    for job_id in job_ids:
        try:
            scheduler.remove_job(job_id)
            logger.info("Job '%s' removido do scheduler.", job_id)
        except JobLookupError:
            pass
        except Exception:
            logger.exception("Erro ao remover job '%s'.", job_id)


def register_global_jobs(app: Flask):
    """Registra jobs globais (não associados a profile).

    - Limpeza diária de dados antigos conforme *_RETENTION_DAYS.
    """
    from app.extensions import scheduler

    scheduler.add_job(
        func=_run_with_context,
        args=[app, cleanup_old_data],
        trigger="interval",
        hours=24,
        id="global_cleanup_old_data",
        name="Cleanup Old Data",
        replace_existing=True,
        max_instances=1,
        next_run_time=_utcnow() + timedelta(minutes=5),
    )
    logger.info("Job global de retenção registrado (diário).")

    # Backup automático do banco (se habilitado e SQLite).
    backup_hours = int(app.config.get("BACKUP_INTERVAL_HOURS", 24))
    db_uri = app.config.get("SQLALCHEMY_DATABASE_URI", "")
    if backup_hours > 0 and db_uri.startswith("sqlite:///"):
        scheduler.add_job(
            func=_run_with_context,
            args=[app, backup_database_job],
            trigger="interval",
            hours=backup_hours,
            id="global_backup_database",
            name="Database Backup",
            replace_existing=True,
            max_instances=1,
            next_run_time=_utcnow() + timedelta(minutes=10),
        )
        logger.info("Job global de backup registrado (a cada %dh).", backup_hours)
    else:
        # Remove um job remanescente caso o backup tenha sido desabilitado.
        try:
            scheduler.remove_job("global_backup_database")
        except Exception:
            pass
        logger.info("Backup automático desabilitado (BACKUP_INTERVAL_HOURS=0 ou DB não-SQLite).")

    # Verificação de certificados TLS em portas HTTPS abertas.
    tls_hours = int(app.config.get("TLS_CHECK_INTERVAL_HOURS", 24))
    if tls_hours > 0:
        scheduler.add_job(
            func=_run_with_context,
            args=[app, check_tls_certificates],
            trigger="interval",
            hours=tls_hours,
            id="global_tls_check",
            name="TLS Certificate Check",
            replace_existing=True,
            max_instances=1,
            next_run_time=_utcnow() + timedelta(minutes=15),
        )
        logger.info("Job global de verificação TLS registrado (a cada %dh).", tls_hours)
    else:
        _remove_job_quiet("global_tls_check")

    # Correlação CVE (NVD) — sem tráfego na rede local, só HTTPS externo.
    cve_hours = int(app.config.get("CVE_LOOKUP_INTERVAL_HOURS", 24))
    if app.config.get("CVE_LOOKUP_ENABLED", True) and cve_hours > 0:
        from app.scanner.cve import correlate_cves
        scheduler.add_job(
            func=_run_with_context,
            args=[app, correlate_cves],
            trigger="interval",
            hours=cve_hours,
            id="global_cve_correlation",
            name="CVE Correlation",
            replace_existing=True,
            max_instances=1,
            next_run_time=_utcnow() + timedelta(minutes=20),
        )
        logger.info("Job global de correlação CVE registrado (a cada %dh).", cve_hours)
    else:
        _remove_job_quiet("global_cve_correlation")
        logger.info("Correlação CVE desabilitada.")


def _run_with_context(app: Flask, func, *args, **kwargs):
    """Wrapper que executa uma função dentro do app context do Flask."""
    with app.app_context():
        func(*args, **kwargs)


# ---------------------------------------------------------------------------
# Job: Host Discovery
# ---------------------------------------------------------------------------

def run_host_discovery(profile_id: int):
    """Executa a descoberta de hosts para um perfil.

    Para cada IpRange habilitado do perfil:
    1. Executa ARP scan.
    2. Para cada host encontrado, cria/atualiza Device e DeviceIp.
    3. Gera alertas para novos devices ou mudanças de IP.
    """
    from app.extensions import db
    from app.models import (
        Profile, IpRange, Device, DeviceIp, Scan, Alert,
        ScanType, ScanStatus, AlertType, Severity, DeviceOnlineSnapshot,
    )
    from app.scanner.hosts import scan_ip_range, normalize_mac, get_vendor_from_mac, is_valid_mac

    profile = db.session.get(Profile, profile_id)
    if not profile or not profile.is_active:
        logger.warning("Profile %d não encontrado ou inativo.", profile_id)
        return

    # Registra o scan no banco
    scan = Scan(profile_id=profile.id, scan_type=ScanType.HOST_DISCOVERY)
    db.session.add(scan)
    db.session.commit()

    total_hosts = 0
    errors = []

    try:
        ranges = IpRange.query.filter_by(profile_id=profile.id, enabled=True).all()
        if not ranges:
            logger.warning("Nenhum range habilitado para profile '%s'.", profile.name)
            scan.status = ScanStatus.SUCCESS
            scan.finished_at = _utcnow()
            scan.error_message = "Nenhum range habilitado."
            db.session.commit()
            return

        logger.info("Host discovery para '%s': %d ranges habilitados.", profile.name, len(ranges))

        for ip_range in ranges:
            try:
                hosts = scan_ip_range(ip_range.cidr)
            except Exception as e:
                msg = f"Erro no scan de {ip_range.cidr}: {e}"
                logger.error(msg)
                errors.append(msg)
                continue
            total_hosts += len(hosts)

            for host in hosts:
                mac = normalize_mac(host.mac)
                now = _utcnow()
                is_real_mac = is_valid_mac(mac) and not mac.startswith("02:00:")

                # Busca device existente pelo MAC neste profile
                device = Device.query.filter_by(profile_id=profile.id, mac=mac).first()

                # Caso 1: MAC real encontrado, mas device tem placeholder
                # → Atualiza o placeholder para o MAC real
                if device is None and is_real_mac:
                    dip = DeviceIp.query.filter_by(ip=host.ip, is_current=True).first()
                    if dip:
                        placeholder_dev = db.session.get(Device, dip.device_id)
                        if placeholder_dev and placeholder_dev.profile_id == profile.id \
                                and placeholder_dev.mac.startswith("02:00:"):
                            logger.info(
                                "Atualizando MAC placeholder %s -> %s para %s",
                                placeholder_dev.mac, mac, host.ip,
                            )
                            placeholder_dev.mac = mac
                            if not placeholder_dev.vendor:
                                placeholder_dev.vendor = get_vendor_from_mac(mac)
                            device = placeholder_dev

                # Caso 2: MAC placeholder, mas já existe device com MAC real para este IP
                # → Usa o device existente (não cria duplicata)
                if device is None and not is_real_mac:
                    dip = DeviceIp.query.filter_by(ip=host.ip, is_current=True).first()
                    if dip:
                        existing_dev = db.session.get(Device, dip.device_id)
                        if existing_dev and existing_dev.profile_id == profile.id:
                            logger.debug(
                                "IP %s já pertence ao device %s (%s), ignorando placeholder %s",
                                host.ip, existing_dev.id, existing_dev.mac, mac,
                            )
                            device = existing_dev

                if device is None:
                    # Novo dispositivo
                    vendor = get_vendor_from_mac(mac)
                    device = Device(
                        profile_id=profile.id,
                        mac=mac,
                        hostname=host.hostname,
                        vendor=vendor,
                        first_seen_at=now,
                        last_seen_at=now,
                    )
                    device.record_online_today(now.date())
                    db.session.add(device)
                    db.session.flush()  # Para obter device.id

                    # Alerta: novo dispositivo
                    alert = Alert(
                        profile_id=profile.id,
                        device_id=device.id,
                        alert_type=AlertType.NEW_DEVICE,
                        severity=Severity.INFO,
                        message=f"Novo dispositivo descoberto: {mac} ({host.ip}) - {host.hostname or 'sem hostname'}",
                    )
                    db.session.add(alert)
                    _maybe_notify(alert, profile, device)
                    logger.info("Novo device: %s (%s)", mac, host.ip)

                    # Insere no início da fila de port scan para ser escaneado logo
                    prepend_to_port_scan_queue(profile.id, device.id, device.display_name, host.ip)
                else:
                    # Device existente — atualiza
                    device.last_seen_at = now
                    device.record_online_today(now.date())
                    if host.hostname and host.hostname != device.hostname:
                        device.hostname = host.hostname

                    # Device voltou a ser visto → fecha alertas HOST_DOWN abertos.
                    _ack_open_host_down_alerts(device.id, now)

                    # Alerta para dispositivo marcado como "Não Autorizado".
                    # Só emite se não houver alerta aberto do mesmo tipo para este device.
                    if device.situation == "Não Autorizado":
                        already_open = Alert.query.filter_by(
                            device_id=device.id,
                            alert_type=AlertType.UNAUTHORIZED_DEVICE,
                        ).filter(Alert.acknowledged_at.is_(None)).first()
                        if not already_open:
                            unauth_alert = Alert(
                                profile_id=profile.id,
                                device_id=device.id,
                                alert_type=AlertType.UNAUTHORIZED_DEVICE,
                                severity=Severity.WARNING,
                                message=(
                                    f"Dispositivo não autorizado detectado na rede: "
                                    f"{device.display_name} ({mac}) em {host.ip}"
                                ),
                            )
                            db.session.add(unauth_alert)
                            _maybe_notify(unauth_alert, profile, device)
                            logger.warning(
                                "Device não autorizado visto: %s (%s)", mac, host.ip
                            )

                # Detecção de conflito de IP: outro device do mesmo perfil já usa
                # este IP como current → dois MACs distintos reivindicando o mesmo IP.
                conflict_dip = (
                    DeviceIp.query
                    .join(Device, DeviceIp.device_id == Device.id)
                    .filter(
                        DeviceIp.ip == host.ip,
                        DeviceIp.is_current.is_(True),
                        Device.profile_id == profile.id,
                        Device.id != device.id,
                    )
                    .first()
                )
                if conflict_dip:
                    conflict_dev = db.session.get(Device, conflict_dip.device_id)
                    conflict_mac = conflict_dev.mac if conflict_dev else "?"

                    # Suspeita de ARP spoofing: o dono anterior do IP foi visto
                    # online há pouco — improvável reuso DHCP; provável outro
                    # host respondendo ARP por um IP que não é dele.
                    from flask import current_app
                    online_minutes = current_app.config.get("HOST_ONLINE_THRESHOLD_MINUTES", 70)
                    spoof_suspect = bool(
                        conflict_dev
                        and conflict_dev.last_seen_at
                        and conflict_dev.last_seen_at >= now - timedelta(minutes=online_minutes)
                    )
                    conflict_type = AlertType.ARP_SPOOFING if spoof_suspect else AlertType.IP_CONFLICT

                    already_open = Alert.query.filter_by(
                        profile_id=profile.id,
                        alert_type=conflict_type,
                    ).filter(
                        Alert.message.contains(host.ip),
                        Alert.acknowledged_at.is_(None),
                    ).first()
                    if not already_open:
                        if spoof_suspect:
                            ip_alert = Alert(
                                profile_id=profile.id,
                                device_id=device.id,
                                alert_type=AlertType.ARP_SPOOFING,
                                severity=Severity.CRITICAL,
                                is_priority=True,
                                message=(
                                    f"Possível ARP spoofing: {host.ip} respondido por {mac} "
                                    f"enquanto o dono recente {conflict_mac} "
                                    f"({conflict_dev.display_name}) ainda estava online"
                                ),
                            )
                        else:
                            ip_alert = Alert(
                                profile_id=profile.id,
                                device_id=device.id,
                                alert_type=AlertType.IP_CONFLICT,
                                severity=Severity.WARNING,
                                message=(
                                    f"Conflito de IP: {host.ip} reivindicado por "
                                    f"{mac} e {conflict_mac} simultaneamente"
                                ),
                            )
                        db.session.add(ip_alert)
                        _maybe_notify(ip_alert, profile, device)
                        logger.warning(
                            "Conflito de IP %s entre %s e %s (spoofing=%s)",
                            host.ip, mac, conflict_mac, spoof_suspect,
                        )

                # Gerencia DeviceIp
                current_ip = DeviceIp.query.filter_by(
                    device_id=device.id, is_current=True
                ).first()

                if current_ip is None:
                    # Primeiro IP registrado
                    new_dip = DeviceIp(
                        device_id=device.id, ip=host.ip,
                        first_seen_at=now, last_seen_at=now, is_current=True,
                    )
                    db.session.add(new_dip)
                elif current_ip.ip != host.ip:
                    # IP mudou
                    current_ip.is_current = False
                    current_ip.last_seen_at = now

                    new_dip = DeviceIp(
                        device_id=device.id, ip=host.ip,
                        first_seen_at=now, last_seen_at=now, is_current=True,
                    )
                    db.session.add(new_dip)

                    alert = Alert(
                        profile_id=profile.id,
                        device_id=device.id,
                        alert_type=AlertType.NEW_IP_FOR_MAC,
                        severity=Severity.WARNING,
                        message=f"Device {device.display_name} ({mac}) mudou de IP: {current_ip.ip} -> {host.ip}",
                    )
                    db.session.add(alert)
                    _maybe_notify(alert, profile, device)
                    logger.info("IP mudou para device %s: %s -> %s", mac, current_ip.ip, host.ip)
                else:
                    # Mesmo IP, atualiza last_seen
                    current_ip.last_seen_at = now

            db.session.commit()

        # Marca resultado no banco
        scan.finished_at = _utcnow()
        scan.hosts_found = total_hosts
        if errors and total_hosts == 0:
            scan.status = ScanStatus.ERROR
            scan.error_message = "; ".join(errors)
            logger.error("Host discovery falhou para '%s': %s", profile.name, scan.error_message)
        elif errors:
            scan.status = ScanStatus.SUCCESS
            scan.error_message = "Parcial: " + "; ".join(errors)
            logger.warning("Host discovery parcial para '%s': %d hosts, erros: %s", profile.name, total_hosts, scan.error_message)
        else:
            scan.status = ScanStatus.SUCCESS
            logger.info("Host discovery concluído para '%s': %d hosts.", profile.name, total_hosts)

        # Registra snapshot de dispositivos online para histórico do gráfico
        snapshot = DeviceOnlineSnapshot(
            profile_id=profile.id,
            recorded_at=_utcnow(),
            online_count=total_hosts,
        )
        db.session.add(snapshot)
        db.session.commit()

        # Dispositivos "fantasma": MACs na tabela ARP do sistema com IP fora
        # de todos os ranges configurados (custo zero — só leitura do kernel).
        try:
            _check_ghost_devices(profile)
        except Exception:
            logger.exception("Erro na detecção de devices fantasma (profile %d)", profile_id)

    except Exception as e:
        scan.status = ScanStatus.ERROR
        scan.finished_at = _utcnow()
        scan.error_message = str(e)
        db.session.commit()
        logger.exception("Erro no host discovery para profile %d", profile_id)


# ---------------------------------------------------------------------------
# Dispositivos "fantasma" — ARP cache fora dos ranges configurados
# ---------------------------------------------------------------------------

def _read_system_arp_table() -> list[tuple[str, str]]:
    """Lê /proc/net/arp e retorna [(ip, mac)] com MACs válidos.

    Retorna lista vazia quando indisponível (ex.: não-Linux).
    """
    entries: list[tuple[str, str]] = []
    try:
        with open("/proc/net/arp", encoding="utf-8") as f:
            next(f, None)  # cabeçalho
            for line in f:
                parts = line.split()
                if len(parts) >= 4:
                    ip, mac = parts[0], parts[3].upper()
                    if mac and mac != "00:00:00:00:00:00":
                        entries.append((ip, mac))
    except OSError:
        pass
    return entries


def _find_ghost_entries(
    arp_entries: list[tuple[str, str]], cidrs: list[str],
) -> list[tuple[str, str]]:
    """Filtra entradas ARP cujo IP não pertence a nenhum CIDR configurado.

    Ignora loopback, multicast e link-local (169.254.x — ruído de autoconfig).
    """
    nets = []
    for c in cidrs:
        try:
            nets.append(ipaddress.ip_network(c, strict=False))
        except ValueError:
            continue

    ghosts: list[tuple[str, str]] = []
    for ip, mac in arp_entries:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if addr.is_loopback or addr.is_multicast or addr.is_link_local:
            continue
        if not any(addr in n for n in nets):
            ghosts.append((ip, mac))
    return ghosts


def _check_ghost_devices(profile) -> int:
    """Alerta GHOST_DEVICE para MACs no ARP do sistema fora de QUALQUER range.

    Compara contra os ranges habilitados de todos os perfis (não só o atual)
    para não acusar devices de outro perfil como fantasmas. Dedupe por alerta
    aberto contendo o mesmo MAC.

    Returns: número de alertas emitidos.
    """
    from app.models import Alert, AlertType, IpRange, Severity

    from app.extensions import db

    all_cidrs = [r.cidr for r in IpRange.query.filter_by(enabled=True).all()]
    if not all_cidrs:
        return 0

    ghosts = _find_ghost_entries(_read_system_arp_table(), all_cidrs)
    emitted = 0
    for ip, mac in ghosts:
        already_open = Alert.query.filter_by(
            profile_id=profile.id,
            alert_type=AlertType.GHOST_DEVICE,
        ).filter(
            Alert.message.contains(mac),
            Alert.acknowledged_at.is_(None),
        ).first()
        if already_open:
            continue
        ghost_alert = Alert(
            profile_id=profile.id,
            alert_type=AlertType.GHOST_DEVICE,
            severity=Severity.WARNING,
            message=(
                f"Dispositivo fantasma: {mac} visto na tabela ARP com IP {ip}, "
                f"fora de todos os ranges configurados"
            ),
        )
        db.session.add(ghost_alert)
        _maybe_notify(ghost_alert, profile, None)
        emitted += 1
        logger.warning("Device fantasma no ARP: %s (%s)", mac, ip)

    if emitted:
        db.session.commit()
    return emitted


# ---------------------------------------------------------------------------
# Job: Port Scan
# ---------------------------------------------------------------------------

_PORT_SCAN_COOLDOWN_HOURS = 24


def _build_scan_tasks_for_profile(profile_id: int) -> list[dict]:
    """Carrega devices ATIVOS do profile e monta a lista de tasks para port scan.

    Regras de elegibilidade:
    - Visto recentemente (últimas 3× o intervalo de discovery).
    - Não escaneado nas últimas 24h (last_port_scanned_at NULL ou antigo).

    Ordena por last_port_scanned_at crescente (NULL primeiro): devices nunca
    escaneados ou escaneados há mais tempo são priorizados.
    """
    from app.extensions import db
    from app.models import Device, DeviceIp, IpRange, Profile

    profile = db.session.get(Profile, profile_id)
    profile_default_ports = (profile.default_ports or "") if profile else ""

    # Cutoff de recência: exclui devices não vistos em 3× o intervalo de discovery
    cutoff_minutes = (profile.host_discovery_interval_minutes * 3) if profile else 135
    seen_cutoff = _utcnow() - timedelta(minutes=cutoff_minutes)

    # Cooldown: não re-escaneia o mesmo device dentro de 24h
    scan_cooldown = _utcnow() - timedelta(hours=_PORT_SCAN_COOLDOWN_HOURS)

    devices_with_ip = (
        db.session.query(Device, DeviceIp)
        .join(DeviceIp, Device.id == DeviceIp.device_id)
        .filter(
            Device.profile_id == profile_id,
            DeviceIp.is_current.is_(True),
            Device.last_seen_at >= seen_cutoff,
            # Inclui apenas devices não escaneados nas últimas 24h
            db.or_(
                Device.last_port_scanned_at.is_(None),
                Device.last_port_scanned_at < scan_cooldown,
            ),
        )
        .order_by(Device.last_port_scanned_at.asc().nullsfirst())
        .all()
    )

    if not devices_with_ip:
        logger.info(
            "Port scan '%d': nenhum device elegível (todos escaneados nas últimas %dh).",
            profile_id, _PORT_SCAN_COOLDOWN_HOURS,
        )
    else:
        logger.info(
            "Port scan '%d': %d device(s) elegíveis para scan hoje.",
            profile_id, len(devices_with_ip),
        )

    enabled_ranges = IpRange.query.filter_by(profile_id=profile_id, enabled=True).all()

    return [
        {
            "device_id": device.id,
            "device_display": device.display_name,
            "ip": device_ip.ip,
            "ports": _get_ports_for_ip(device_ip.ip, enabled_ranges, profile_default_ports),
        }
        for device, device_ip in devices_with_ip
    ]


def _next_alternate_nmap_args(device_id: int) -> str:
    """Sequência de tipos de scan a tentar para um device suspeito.

    Cada chamada avança para o próximo tipo na sequência. Quando esgota,
    reseta e o ciclo recomeça.

    Mantemos --host-timeout para não travar o scheduler.
    """
    import os
    sequence = [
        # Connect scan + Pn — útil quando o roteador filtra SYN.
        "-Pn -sT -sV -T4 --version-intensity 2 --host-timeout 300s",
        # SYN + tentativa mais lenta com retries — root only; sem root cai p/ sT.
        ("-Pn -sS -sV -T3 --version-intensity 2 --max-retries 3 --host-timeout 300s"
         if os.geteuid() == 0
         else "-Pn -sT -sV -T3 --version-intensity 2 --max-retries 3 --host-timeout 300s"),
        # ACK scan para detectar firewall stateful (open|filtered).
        "-Pn -sA -T4 --host-timeout 300s",
    ]
    with _port_scan_retry_lock:
        idx = _port_scan_retry_args.get(device_id, -1)
        idx = (idx + 1) % len(sequence)
        _port_scan_retry_args[device_id] = idx
    return sequence[idx]


def _requeue_with_alternate_scan(
    profile_id: int, device_id: int, device_display: str, ip: str, ports: str,
) -> None:
    """Re-insere o device no início da fila com um scan_type alternativo.

    Usado quando detectamos "bug de portas sumidas" (host respondeu mas
    nenhuma das portas anteriores apareceu). Alterna SYN/connect/ACK para
    contornar firewalls que bloqueiam o tipo de probe original.
    """
    entry = {
        "device_id": device_id,
        "device_display": device_display,
        "ip": ip,
        "ports": ports,
        "nmap_arguments": _next_alternate_nmap_args(device_id),
    }
    with _port_scan_queues_lock:
        queue = _port_scan_queues.setdefault(profile_id, deque())
        without_device = [t for t in queue if t["device_id"] != device_id]
        queue.clear()
        queue.extend(without_device)
        queue.appendleft(entry)


def prepend_to_port_scan_queue(profile_id: int, device_id: int, device_display: str, ip: str):
    """Insere um device no início da fila de port scan do profile.

    Chamado pelo host discovery quando um novo device é encontrado, garantindo
    que seja escaneado na próxima invocação antes que fique offline.
    Remove duplicatas caso o device já esteja na fila.
    """
    # Consulta os ranges fora do lock (operação potencialmente demorada).
    try:
        from app.models import IpRange, Profile
        from app.extensions import db as _db
        _profile = _db.session.get(Profile, profile_id)
        _profile_default_ports = (_profile.default_ports or "") if _profile else ""
        enabled_ranges = IpRange.query.filter_by(profile_id=profile_id, enabled=True).all()
        ports = _get_ports_for_ip(ip, enabled_ranges, _profile_default_ports)
    except Exception:
        from app.scanner.ports import DEFAULT_PORTS
        ports = DEFAULT_PORTS

    entry = {
        "device_id": device_id,
        "device_display": device_display,
        "ip": ip,
        "ports": ports,
    }

    with _port_scan_queues_lock:
        queue = _port_scan_queues.setdefault(profile_id, deque())

        # Remove entrada existente (se houver) e insere no início.
        without_device = [t for t in queue if t["device_id"] != device_id]
        queue.clear()
        queue.extend(without_device)
        queue.appendleft(entry)
        queue_len = len(queue)

    logger.info(
        "Novo device '%s' (%s) inserido no início da fila de port scan "
        "(profile %d, fila: %d items)",
        device_display, ip, profile_id, queue_len,
    )


def _get_ports_for_ip(ip_str: str, ranges, profile_default_ports: str = "") -> str:
    """Determina quais portas escanear baseado na config do IpRange que contém o IP.

    Prioridade:
    1. IpRange mais específico com custom_ports / scan_all_ports.
    2. profile_default_ports (configurado pelo admin no perfil).
    3. DEFAULT_PORTS (constante hardcoded em ports.py).
    """
    from app.scanner.ports import DEFAULT_PORTS

    fallback = profile_default_ports.strip() or DEFAULT_PORTS

    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return fallback

    best_match = None
    best_prefix = -1

    for r in ranges:
        try:
            net = ipaddress.ip_network(r.cidr, strict=False)
        except ValueError:
            continue
        if addr in net and net.prefixlen > best_prefix:
            best_match = r
            best_prefix = net.prefixlen

    if best_match is None:
        return fallback

    if best_match.scan_all_ports:
        return "1-65535"
    if best_match.custom_ports:
        return best_match.custom_ports

    return fallback


def run_port_scan(profile_id: int):
    """Escaneia o próximo lote de hosts da fila de port scan do perfil.

    Cada invocação consome até max_concurrent_scans devices da frente da fila.
    Quando a fila esgota é reconstruída apenas com devices elegíveis: ativos e
    não escaneados nas últimas 24h (cooldown por device_id via last_port_scanned_at).
    Se todos os devices já foram escaneados hoje, a função retorna sem trabalho.
    Novos devices descobertos pelo host discovery são inseridos no início via
    prepend_to_port_scan_queue(), sendo escaneados prioritariamente.
    """
    from app.extensions import db
    from app.models import (
        Device, Profile, Port, Scan, Alert,
        ScanType, ScanStatus, AlertType, Severity,
    )
    from app.scanner.ports import scan_ports_for_host, get_actionable_ports

    profile = db.session.get(Profile, profile_id)
    if not profile or not profile.is_active:
        return

    try:
        # Reconstrução + extração do lote sob lock único, evitando race com
        # prepend_to_port_scan_queue executando em outra thread.
        with _port_scan_queues_lock:
            queue = _port_scan_queues.get(profile_id)
            if not queue:
                # Fora do lock? Não — _build_scan_tasks_for_profile consulta o
                # DB mas o session do SQLAlchemy é thread-local e as filas in-memory
                # são pequenas; manter simples e thread-safe.
                tasks = _build_scan_tasks_for_profile(profile_id)
                if not tasks:
                    return
                queue = deque(tasks)
                _port_scan_queues[profile_id] = queue
                logger.info(
                    "Fila de port scan para '%s' reconstruída: %d devices.",
                    profile.name, len(tasks),
                )

            batch: list[dict] = []
            while queue and len(batch) < profile.max_concurrent_scans:
                batch.append(queue.popleft())
            remaining = len(queue)

        if not batch:
            return

        logger.info(
            "Port scan '%s': lote=%d host(s), fila restante=%d",
            profile.name, len(batch), remaining,
        )

        scan_start = _utcnow()

        def _scan_single(task):
            """Executa o nmap — só usa strings, sem acesso ao Flask/DB."""
            # Se este device foi marcado para retry com scan alternativo, usa.
            override = task.get("nmap_arguments")
            port_list, host_found = scan_ports_for_host(
                task["ip"], ports=task["ports"], arguments=override,
            )
            return task, port_list, host_found

        with ThreadPoolExecutor(max_workers=len(batch)) as executor:
            futures = []
            for task in batch:
                futures.append(executor.submit(_scan_single, task))
                time.sleep(0.3)

            for future in futures:
                try:
                    task, port_results, host_found = future.result(timeout=600)
                except Exception:
                    logger.exception("Erro no port scan de um device")
                    continue

                device_id = task["device_id"]
                device_display = task["device_display"]
                ip_str = task["ip"]

                # Considera portas open + filtered (todas menos closed)
                found_ports = get_actionable_ports(port_results)
                now = _utcnow()

                # Mapa para lookup rápido
                found_map = {(p.protocol, p.port): p for p in found_ports}
                found_set = set(found_map.keys())

                # Conjunto atual de portas no banco (não fechadas)
                existing_ports = Port.query.filter_by(device_id=device_id).filter(
                    Port.last_seen_closed_at.is_(None)
                ).all()
                old_set = {(p.protocol, p.port) for p in existing_ports}

                # --- Novas portas encontradas ---
                for key in (found_set - old_set):
                    proto, port_num = key
                    pi = found_map[key]

                    existing = Port.query.filter_by(
                        device_id=device_id, protocol=proto, port=port_num
                    ).first()

                    # Baseline: porta autorizada que reaparece não alerta.
                    port_authorized = bool(existing and existing.is_authorized)

                    if existing:
                        existing.last_seen_open_at = now
                        existing.last_seen_closed_at = None
                        existing.state = pi.state
                        existing.service_name = pi.service_name
                        existing.service_version = pi.service_version
                    else:
                        db.session.add(Port(
                            device_id=device_id,
                            protocol=proto,
                            port=port_num,
                            state=pi.state,
                            service_name=pi.service_name,
                            service_version=pi.service_version,
                            first_open_at=now,
                            last_seen_open_at=now,
                        ))

                    # Só emite alerta para portas OPEN — portas filtered são
                    # gravadas mas não geram ruído (firewall as bloqueia, sem risco).
                    # Suprime se a porta está no baseline (autorizada) ou se já
                    # houve alerta recente para esta porta (janela de dedupe).
                    if (
                        pi.state == "open"
                        and not port_authorized
                        and not _recent_port_alert_exists(device_id, proto, port_num)
                    ):
                        new_port_alert = Alert(
                            profile_id=profile.id,
                            device_id=device_id,
                            alert_type=AlertType.NEW_PORT,
                            severity=_severity_for_port(port_num),
                            message=f"Nova porta em {device_display} ({ip_str}): {proto}/{port_num} ({pi.service_name}) [{pi.state}]",
                        )
                        db.session.add(new_port_alert)
                        _maybe_notify(new_port_alert, profile, None)

                # --- Detecção de "bug de portas sumidas" ---
                # Se o device tinha >=2 portas mapeadas e o scan retornou 0,
                # tratamos como falha (provável bloqueio de firewall transitório
                # ou perda de pacotes), NÃO fechamos as portas e re-enfileiramos
                # com scan type alternativo. Só faz sentido se o MAC continua o
                # mesmo (DHCP swap muda o MAC junto, tratado em run_host_discovery).
                ports_vanished_bug = (
                    host_found and len(old_set) >= 2 and len(found_set) == 0
                )

                if ports_vanished_bug:
                    logger.warning(
                        "Port scan %s (%s): %d portas anteriores e 0 encontradas — "
                        "tratando como bug. Re-enfileirando com scan alternativo.",
                        device_display, ip_str, len(old_set),
                    )
                    _requeue_with_alternate_scan(
                        profile.id, device_id, device_display, ip_str, task["ports"]
                    )
                elif host_found:
                    # Cenário normal: marca portas que desapareceram como fechadas.
                    for key in (old_set - found_set):
                        proto, port_num = key
                        p = Port.query.filter_by(
                            device_id=device_id, protocol=proto, port=port_num
                        ).first()
                        if p:
                            p.last_seen_closed_at = now

                # --- Portas que continuam visíveis ---
                for key in (old_set & found_set):
                    proto, port_num = key
                    p = Port.query.filter_by(
                        device_id=device_id, protocol=proto, port=port_num
                    ).first()
                    pi = found_map[key]
                    if p:
                        p.last_seen_open_at = now
                        # Mudança de estado (ex.: filtered → open) indica que
                        # um firewall caiu ou uma nova regra foi aplicada.
                        # Vale um alerta mesmo sem "nova porta".
                        prev_state = p.state
                        if (
                            prev_state and pi.state and prev_state != pi.state
                            and not p.is_authorized
                            and not _recent_port_alert_exists(device_id, proto, port_num)
                        ):
                            state_alert = Alert(
                                profile_id=profile.id,
                                device_id=device_id,
                                alert_type=AlertType.NEW_PORT,
                                severity=_severity_for_port(port_num),
                                message=(
                                    f"Mudança de estado em {device_display} ({ip_str}): "
                                    f"{proto}/{port_num} ({pi.service_name or '-'}) "
                                    f"[{prev_state} → {pi.state}]"
                                ),
                            )
                            db.session.add(state_alert)
                            _maybe_notify(state_alert, profile, None)
                        p.state = pi.state
                        if pi.service_version:
                            p.service_version = pi.service_version
                        if pi.service_name:
                            p.service_name = pi.service_name

                # Marca timestamp do port scan no device (guarda cooldown de 24h).
                # Pula no caso ports_vanished_bug — queremos re-escanear logo.
                if host_found and not ports_vanished_bug:
                    _device = db.session.get(Device, device_id)
                    if _device:
                        _device.last_port_scanned_at = now

                # Resumo legível: mostra o que foi encontrado (ou o motivo de 0 portas)
                open_ports = [p for p in found_ports if p.state == "open"]
                filtered_ports = [p for p in found_ports if "filtered" in p.state]
                if not host_found:
                    scan_summary = "Host não respondeu ao scan"
                elif ports_vanished_bug:
                    scan_summary = (
                        f"Bug detectado: {len(old_set)} portas anteriores e 0 encontradas — "
                        "re-enfileirado com scan alternativo."
                    )
                elif not found_ports:
                    scan_summary = "0 portas abertas/filtradas (todas fechadas)"
                else:
                    scan_summary = (
                        f"{len(open_ports)} porta(s) abertas"
                        + (f", {len(filtered_ports)} filtradas" if filtered_ports else "")
                    )

                logger.info(
                    "Port scan %s (%s): host_found=%s, %s",
                    device_display, ip_str, host_found, scan_summary,
                )

                db.session.add(Scan(
                    profile_id=profile.id,
                    scan_type=ScanType.PORT_SCAN,
                    target_ip=ip_str,
                    started_at=scan_start,
                    finished_at=now,
                    hosts_found=len(found_ports),
                    status=ScanStatus.SUCCESS,
                    result_summary=scan_summary,
                ))
                db.session.commit()

        with _port_scan_queues_lock:
            remaining_after = len(_port_scan_queues.get(profile_id, []))
        logger.info(
            "Port scan lote concluído para '%s' (fila restante: %d).",
            profile.name, remaining_after,
        )

    except Exception:
        db.session.rollback()
        logger.exception("Erro no port scan para profile %d", profile_id)


# ---------------------------------------------------------------------------
# Helpers de severidade para alertas de porta
# ---------------------------------------------------------------------------

# Portas de alto risco — definidas em ports.py para reuso
from app.scanner.ports import CRITICAL_PORTS as _CRITICAL_PORTS


def _severity_for_port(port_num: int) -> "Severity":
    """Retorna Severity.CRITICAL para portas de alto risco, WARNING para as demais."""
    from app.models import Severity
    return Severity.CRITICAL if port_num in _CRITICAL_PORTS else Severity.WARNING


def _recent_port_alert_exists(device_id: int, proto: str, port_num: int) -> bool:
    """Dedupe de alertas de porta: já existe alerta NEW_PORT para este
    device+porta dentro da janela PORT_ALERT_DEDUP_HOURS?

    Evita spam quando o estado oscila (flapping filtered<->open) entre scans.
    As mensagens de alerta sempre contêm "{proto}/{porta} (", usado como chave.
    """
    from flask import current_app

    from app.extensions import db
    from app.models import Alert, AlertType

    try:
        hours = int(current_app.config.get("PORT_ALERT_DEDUP_HOURS", 6))
    except RuntimeError:
        hours = 6
    if hours <= 0:
        return False

    cutoff = _utcnow() - timedelta(hours=hours)
    return db.session.query(Alert.id).filter(
        Alert.device_id == device_id,
        Alert.alert_type == AlertType.NEW_PORT,
        Alert.created_at >= cutoff,
        Alert.message.contains(f"{proto}/{port_num} ("),
    ).first() is not None


def _record_detected_open_port(
    profile, device_id: int, device_display: str, ip_str: str, pi, now, source: str,
) -> bool:
    """Upsert leve de uma porta encontrada por checks auxiliares (críticas/UDP).

    Diferente de run_port_scan, nunca fecha portas — apenas registra/reabre a
    porta detectada e emite alerta quando é um achado novo em estado 'open',
    respeitando baseline (is_authorized) e a janela de dedupe.

    Returns: True se um alerta foi emitido.
    """
    from app.extensions import db
    from app.models import Alert, AlertType, Port

    port_row = Port.query.filter_by(
        device_id=device_id, protocol=pi.protocol, port=pi.port
    ).first()

    if port_row is None:
        port_row = Port(
            device_id=device_id,
            protocol=pi.protocol,
            port=pi.port,
            state=pi.state,
            service_name=pi.service_name,
            service_version=pi.service_version,
            first_open_at=now,
            last_seen_open_at=now,
        )
        db.session.add(port_row)
        is_new_finding = pi.state == "open"
        authorized = False
    else:
        # Achado novo = estava fechada, ou transicionou para open agora.
        is_new_finding = pi.state == "open" and (
            port_row.last_seen_closed_at is not None or port_row.state != "open"
        )
        authorized = port_row.is_authorized
        port_row.last_seen_open_at = now
        port_row.last_seen_closed_at = None
        port_row.state = pi.state
        if pi.service_name:
            port_row.service_name = pi.service_name
        if pi.service_version:
            port_row.service_version = pi.service_version

    if not is_new_finding or authorized:
        return False
    if _recent_port_alert_exists(device_id, pi.protocol, pi.port):
        return False

    alert = Alert(
        profile_id=profile.id,
        device_id=device_id,
        alert_type=AlertType.NEW_PORT,
        severity=_severity_for_port(pi.port),
        message=(
            f"Nova porta em {device_display} ({ip_str}): "
            f"{pi.protocol}/{pi.port} ({pi.service_name}) [{pi.state}] — via {source}"
        ),
    )
    db.session.add(alert)
    _maybe_notify(alert, profile, None)
    return True


def _online_devices_with_ip(profile_id: int):
    """[(Device, DeviceIp)] dos devices online (last_seen dentro do threshold)."""
    from flask import current_app

    from app.extensions import db
    from app.models import Device, DeviceIp

    online_minutes = current_app.config.get("HOST_ONLINE_THRESHOLD_MINUTES", 70)
    cutoff = _utcnow() - timedelta(minutes=online_minutes)
    return (
        db.session.query(Device, DeviceIp)
        .join(DeviceIp, Device.id == DeviceIp.device_id)
        .filter(
            Device.profile_id == profile_id,
            DeviceIp.is_current.is_(True),
            Device.last_seen_at >= cutoff,
        )
        .all()
    )


# ---------------------------------------------------------------------------
# Job: Check rápido de portas críticas
# ---------------------------------------------------------------------------

def critical_ports_check(profile_id: int):
    """Escaneia APENAS as CRITICAL_PORTS nos devices online do perfil.

    Probe leve (~11 portas, sem -sV) para detectar exposição grave
    (Telnet/SMB/RDP/VNC...) em horas em vez de esperar o ciclo de 24h do
    port scan completo. Nunca fecha portas — só registra novas aberturas.
    """
    from app.extensions import db
    from app.models import Profile, Scan, ScanStatus, ScanType
    from app.scanner.ports import CRITICAL_PORTS, scan_ports_for_host

    profile = db.session.get(Profile, profile_id)
    if not profile or not profile.is_active:
        return

    rows = _online_devices_with_ip(profile_id)
    if not rows:
        logger.info("Check de portas críticas '%s': nenhum device online.", profile.name)
        return

    ports_csv = ",".join(str(p) for p in sorted(CRITICAL_PORTS))
    timeout_args = "--host-timeout 60s"
    if _has_root():
        nmap_args = f"-Pn -sS -T4 {timeout_args}"
    else:
        nmap_args = f"-Pn -sT -T4 {timeout_args}"

    # Extrai dados antes das threads (sem acesso a DB dentro delas).
    tasks = [
        {"device_id": d.id, "device_display": d.display_name, "ip": dip.ip}
        for d, dip in rows
    ]

    scan_start = _utcnow()
    alerts_emitted = 0
    max_workers = max(1, profile.max_concurrent_scans)

    def _scan_one(task):
        port_list, host_found = scan_ports_for_host(
            task["ip"], ports=ports_csv, arguments=nmap_args,
        )
        return task, port_list, host_found

    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []
            for task in tasks:
                futures.append(executor.submit(_scan_one, task))
                time.sleep(0.2)

            for future in futures:
                try:
                    task, port_results, host_found = future.result(timeout=300)
                except Exception:
                    logger.exception("Erro no check de porta crítica de um device")
                    continue
                if not host_found:
                    continue
                now = _utcnow()
                for pi in port_results:
                    if pi.state != "open":
                        continue  # check rápido: só portas abertas interessam
                    if _record_detected_open_port(
                        profile, task["device_id"], task["device_display"],
                        task["ip"], pi, now, source="check de portas críticas",
                    ):
                        alerts_emitted += 1
                db.session.commit()

        db.session.add(Scan(
            profile_id=profile.id,
            scan_type=ScanType.PORT_SCAN,
            target_ip=None,
            started_at=scan_start,
            finished_at=_utcnow(),
            hosts_found=alerts_emitted,
            status=ScanStatus.SUCCESS,
            result_summary=(
                f"Check de portas críticas: {len(tasks)} device(s) online, "
                f"{alerts_emitted} alerta(s) de porta crítica aberta."
            ),
        ))
        db.session.commit()
        logger.info(
            "Check de portas críticas '%s': %d devices, %d alertas.",
            profile.name, len(tasks), alerts_emitted,
        )
    except Exception:
        db.session.rollback()
        logger.exception("Erro no check de portas críticas (profile %d)", profile_id)


# ---------------------------------------------------------------------------
# Job: Scan UDP periódico
# ---------------------------------------------------------------------------

def run_udp_scan(profile_id: int):
    """Scan UDP de um conjunto pequeno de portas nos devices online.

    Requer root (-sU usa raw sockets) — o registro do job já filtra isso.
    Alerta apenas para portas em estado 'open' (open|filtered é ruído inerente
    ao UDP e seria falso-positivo em massa).
    """
    from app.extensions import db
    from app.models import Profile, Scan, ScanStatus, ScanType
    from app.scanner.ports import UDP_SCAN_PORTS, scan_ports_for_host

    if not _has_root():
        logger.warning("Scan UDP exige root — ignorando (profile %d).", profile_id)
        return

    profile = db.session.get(Profile, profile_id)
    if not profile or not profile.is_active:
        return

    rows = _online_devices_with_ip(profile_id)
    if not rows:
        logger.info("Scan UDP '%s': nenhum device online.", profile.name)
        return

    nmap_args = "-Pn -sU -sV --version-intensity 0 -T4 --host-timeout 120s"
    tasks = [
        {"device_id": d.id, "device_display": d.display_name, "ip": dip.ip}
        for d, dip in rows
    ]

    scan_start = _utcnow()
    alerts_emitted = 0
    open_found = 0
    max_workers = max(1, profile.max_concurrent_scans)

    def _scan_one(task):
        port_list, host_found = scan_ports_for_host(
            task["ip"], ports=UDP_SCAN_PORTS, arguments=nmap_args,
        )
        return task, port_list, host_found

    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []
            for task in tasks:
                futures.append(executor.submit(_scan_one, task))
                time.sleep(0.3)

            for future in futures:
                try:
                    task, port_results, host_found = future.result(timeout=600)
                except Exception:
                    logger.exception("Erro no scan UDP de um device")
                    continue
                if not host_found:
                    continue
                now = _utcnow()
                for pi in port_results:
                    if pi.state != "open":
                        continue  # UDP: open|filtered é indeterminado, não alertar
                    open_found += 1
                    if _record_detected_open_port(
                        profile, task["device_id"], task["device_display"],
                        task["ip"], pi, now, source="scan UDP",
                    ):
                        alerts_emitted += 1
                db.session.commit()

        db.session.add(Scan(
            profile_id=profile.id,
            scan_type=ScanType.PORT_SCAN,
            target_ip=None,
            started_at=scan_start,
            finished_at=_utcnow(),
            hosts_found=open_found,
            status=ScanStatus.SUCCESS,
            result_summary=(
                f"Scan UDP: {len(tasks)} device(s), {open_found} porta(s) UDP abertas, "
                f"{alerts_emitted} alerta(s)."
            ),
        ))
        db.session.commit()
        logger.info(
            "Scan UDP '%s': %d devices, %d portas abertas, %d alertas.",
            profile.name, len(tasks), open_found, alerts_emitted,
        )
    except Exception:
        db.session.rollback()
        logger.exception("Erro no scan UDP (profile %d)", profile_id)


# ---------------------------------------------------------------------------
# Job: Verificação de certificados TLS
# ---------------------------------------------------------------------------

def _fetch_cert_not_after(ip: str, port: int, timeout: int = 8):
    """Conecta na porta TLS e retorna (not_after_utc_naive, subject_str).

    Lança exceção em falha de conexão/handshake — o chamador decide ignorar.
    Não valida a cadeia (queremos ler o cert mesmo se self-signed).
    """
    import socket
    import ssl

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with socket.create_connection((ip, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock) as ssock:
            der = ssock.getpeercert(binary_form=True)

    from cryptography import x509

    cert = x509.load_der_x509_certificate(der)
    # cryptography >= 42 expõe not_valid_after_utc (aware); versões antigas
    # só not_valid_after (naive UTC).
    not_after = getattr(cert, "not_valid_after_utc", None)
    if not_after is not None:
        not_after = not_after.replace(tzinfo=None)
    else:
        not_after = cert.not_valid_after
    try:
        subject = cert.subject.rfc4514_string()
    except Exception:
        subject = ""
    return not_after, subject


def check_tls_certificates():
    """Job global: verifica expiração de certificados TLS em portas HTTPS abertas.

    Uma conexão TCP por porta — custo de rede desprezível. Alerta WARNING
    quando o certificado expira em <= TLS_CERT_WARN_DAYS dias e CRITICAL
    quando já expirou. Dedupe: um alerta por device+porta por janela de 7 dias.
    """
    from flask import current_app

    from app.extensions import db
    from app.models import Alert, AlertType, Device, Port, Profile, Severity
    from app.scanner.ports import TLS_PORTS

    warn_days = int(current_app.config.get("TLS_CERT_WARN_DAYS", 15))
    online_minutes = current_app.config.get("HOST_ONLINE_THRESHOLD_MINUTES", 70)
    seen_cutoff = _utcnow() - timedelta(minutes=online_minutes)

    rows = (
        db.session.query(Port, Device)
        .join(Device, Port.device_id == Device.id)
        .filter(
            Port.last_seen_closed_at.is_(None),
            Port.state == "open",
            Port.port.in_(list(TLS_PORTS)),
            Device.last_seen_at >= seen_cutoff,
        )
        .all()
    )

    checked = alerts = 0
    for port_row, device in rows:
        ip = device.current_ip
        if not ip:
            continue
        try:
            not_after, subject = _fetch_cert_not_after(ip, port_row.port)
        except Exception as exc:
            logger.debug("TLS check falhou para %s:%d: %s", ip, port_row.port, exc)
            continue
        checked += 1

        days_left = (not_after - _utcnow()).days
        if days_left > warn_days:
            continue

        # Dedupe: alerta recente (7 dias) ou aberto para o mesmo device+porta.
        dedup_cutoff = _utcnow() - timedelta(days=7)
        existing = Alert.query.filter(
            Alert.device_id == device.id,
            Alert.alert_type == AlertType.TLS_CERT_EXPIRING,
            Alert.message.contains(f"{ip}:{port_row.port}"),
            db.or_(
                Alert.acknowledged_at.is_(None),
                Alert.created_at >= dedup_cutoff,
            ),
        ).first()
        if existing:
            continue

        if days_left < 0:
            severity = Severity.CRITICAL
            status_txt = f"EXPIRADO há {-days_left} dia(s)"
        else:
            severity = Severity.WARNING
            status_txt = f"expira em {days_left} dia(s)"

        profile = db.session.get(Profile, device.profile_id)
        alert = Alert(
            profile_id=device.profile_id,
            device_id=device.id,
            alert_type=AlertType.TLS_CERT_EXPIRING,
            severity=severity,
            message=(
                f"Certificado TLS em {device.display_name} ({ip}:{port_row.port}) "
                f"{status_txt} (validade até {not_after:%d/%m/%Y})"
                + (f" — {subject}" if subject else "")
            ),
        )
        db.session.add(alert)
        if profile:
            _maybe_notify(alert, profile, device)
        alerts += 1

    db.session.commit()
    logger.info("Verificação TLS: %d certificado(s) lidos, %d alerta(s).", checked, alerts)


# ---------------------------------------------------------------------------
# Scan manual (sob demanda) de um ativo específico
# ---------------------------------------------------------------------------

def _build_mobile_result_message(mobile_res: dict) -> str:
    """Gera uma string descritiva do resultado do Mobile ID para exibição no histórico.

    Exemplos:
        "iOS — iPhone de João"
        "Android — Samsung Galaxy A32"
        "Identificado (desconhecido)"
        "Host não respondeu ao Mobile ID"
    """
    if not mobile_res.get("is_mobile"):
        return mobile_res.get("note", "Host não respondeu ao Mobile ID")

    _os_labels = {"ios": "iOS", "android": "Android", "windows_mobile": "Windows Mobile"}
    likely_os = mobile_res.get("likely_os") or ""
    os_label = _os_labels.get(likely_os, likely_os.capitalize()) if likely_os else ""

    friendly = mobile_res.get("friendly_name", "").strip()
    manufacturer = mobile_res.get("manufacturer", "").strip()
    model = mobile_res.get("model", "").strip()

    # Monta identificação: preferencia para nome amigável > fabricante+modelo
    if friendly:
        device_id_str = friendly
    elif manufacturer or model:
        device_id_str = f"{manufacturer} {model}".strip()
    else:
        device_id_str = ""

    if os_label and device_id_str:
        return f"{os_label} — {device_id_str}"
    if os_label:
        return f"{os_label} (sem nome/modelo)"
    if device_id_str:
        return f"Identificado — {device_id_str}"
    return "Identificado (sem detalhes)"


def run_on_demand_scan(device_id: int, scan_types: list[str]) -> dict:
    """Executa scans sob demanda em um dispositivo específico.

    Args:
        device_id: ID do dispositivo a escanear.
        scan_types: Lista de tipos de scan:
            "ping", "ports", "os_detect", "vuln", "snmp", "mobile".

    Returns:
        Dicionário com resultados de cada tipo de scan solicitado.
    """
    # Evita dois scans simultâneos no mesmo device (dois cliques rápidos).
    with _on_demand_lock:
        if _on_demand_locks.get(device_id):
            return {"error": "Scan já em andamento para este dispositivo."}
        _on_demand_locks[device_id] = True

    try:
        return _run_on_demand_scan_inner(device_id, scan_types)
    finally:
        with _on_demand_lock:
            _on_demand_locks[device_id] = False


def _run_on_demand_scan_inner(device_id: int, scan_types: list[str]) -> dict:
    from app.extensions import db
    from app.models import Device, DeviceIp, Port, Alert, AlertType, Severity, Scan, ScanType, ScanStatus
    from app.scanner.ports import scan_ports_for_host, get_actionable_ports
    from app.scanner.snmp import get_system_info

    device = db.session.get(Device, device_id)
    if not device:
        return {"error": "Dispositivo não encontrado."}

    current_dip = DeviceIp.query.filter_by(device_id=device.id, is_current=True).first()
    if not current_dip:
        return {"error": "Dispositivo sem IP atual registrado."}

    ip = current_dip.ip
    results = {"device_id": device_id, "ip": ip}
    now = _utcnow()

    # Determina tipo de scan principal para o registro
    if "ports" in scan_types:
        scan_type_log = ScanType.PORT_SCAN
    elif "mobile" in scan_types:
        scan_type_log = ScanType.MOBILE_SCAN
    else:
        scan_type_log = ScanType.HOST_DISCOVERY

    scan_record = Scan(
        profile_id=device.profile_id,
        scan_type=scan_type_log,
        target_ip=ip,
    )
    db.session.add(scan_record)
    db.session.commit()

    # --- Ping (multi-método: ICMP → ARP → TCP) ---
    if "ping" in scan_types:
        from app.scanner.hosts import is_host_reachable
        is_up, method = is_host_reachable(ip)
        results["ping"] = {"is_up": is_up, "method": method}
        if is_up:
            device.last_seen_at = now
            current_dip.last_seen_at = now
            device.record_online_today(now.date())

    # --- Port Scan ---
    if "ports" in scan_types:
        from app.models import IpRange, Profile
        _profile = db.session.get(Profile, device.profile_id)
        _profile_default_ports = (_profile.default_ports or "") if _profile else ""
        enabled_ranges = IpRange.query.filter_by(
            profile_id=device.profile_id, enabled=True
        ).all()
        ports_str = _get_ports_for_ip(ip, enabled_ranges, _profile_default_ports)
        port_results, host_found = scan_ports_for_host(ip, ports=ports_str)
        found_ports = get_actionable_ports(port_results)

        results["ports"] = [
            {
                "port": p.port, "protocol": p.protocol, "state": p.state,
                "service": p.service_name, "version": p.service_version,
            }
            for p in found_ports
        ]

        # Atualiza banco de dados com os resultados
        found_map = {(p.protocol, p.port): p for p in found_ports}
        found_set = set(found_map.keys())

        existing_open = Port.query.filter_by(device_id=device.id).filter(
            Port.last_seen_closed_at.is_(None)
        ).all()
        old_set = {(p.protocol, p.port) for p in existing_open}

        for key in (found_set - old_set):
            proto, port_num = key
            pi = found_map[key]
            existing = Port.query.filter_by(device_id=device.id, protocol=proto, port=port_num).first()
            if existing:
                existing.last_seen_open_at = now
                existing.last_seen_closed_at = None
                existing.state = pi.state
                existing.service_name = pi.service_name
                existing.service_version = pi.service_version
            else:
                db.session.add(Port(
                    device_id=device.id, protocol=proto, port=port_num,
                    state=pi.state,
                    service_name=pi.service_name, service_version=pi.service_version,
                    first_open_at=now, last_seen_open_at=now,
                ))
            # Só alerta para portas OPEN (filtered não oferece risco).
            if pi.state == "open":
                db.session.add(Alert(
                    profile_id=device.profile_id, device_id=device.id,
                    alert_type=AlertType.NEW_PORT, severity=_severity_for_port(port_num),
                    message=f"Nova porta em {device.display_name}: {proto}/{port_num} ({pi.service_name}) [{pi.state}]",
                ))

        if host_found:
            for key in (old_set - found_set):
                proto, port_num = key
                p = Port.query.filter_by(device_id=device.id, protocol=proto, port=port_num).first()
                if p:
                    p.last_seen_closed_at = now

        for key in (old_set & found_set):
            proto, port_num = key
            p = Port.query.filter_by(device_id=device.id, protocol=proto, port=port_num).first()
            pi = found_map[key]
            if p:
                p.last_seen_open_at = now
                # Gera alerta quando o estado muda (ex.: filtered → open).
                prev_state = p.state
                if prev_state and pi.state and prev_state != pi.state:
                    db.session.add(Alert(
                        profile_id=device.profile_id, device_id=device.id,
                        alert_type=AlertType.NEW_PORT, severity=_severity_for_port(port_num),
                        message=(
                            f"Mudança de estado em {device.display_name}: "
                            f"{proto}/{port_num} ({pi.service_name or '-'}) "
                            f"[{prev_state} → {pi.state}]"
                        ),
                    ))
                p.state = pi.state
                if pi.service_name:
                    p.service_name = pi.service_name
                if pi.service_version:
                    p.service_version = pi.service_version

        # Atualiza cooldown de port scan (scan manual também conta como "escaneado hoje")
        if host_found:
            device.last_port_scanned_at = now

        db.session.commit()

    # --- OS Detection (nmap -O) ---
    if "os_detect" in scan_types:
        results["os_detect"] = _detect_os(ip)
        if results["os_detect"].get("os_guess"):
            device.os_guess = results["os_detect"]["os_guess"]

    # --- Vulnerability scan básico (nmap --script=vuln) ---
    if "vuln" in scan_types:
        from app.models import Profile, Vulnerability
        vuln_result = _scan_vulnerabilities(ip)
        results["vuln"] = vuln_result

        vuln_profile = db.session.get(Profile, device.profile_id)

        # Salva vulnerabilidades no banco
        for v in vuln_result.get("vulns", []):
            is_vulnerable = v.get("is_vulnerable", False)
            existing = Vulnerability.query.filter_by(
                device_id=device.id,
                script_name=v["script"],
                port=v["port"],
                protocol=v.get("protocol", ""),
            ).first()
            if existing:
                # Alerta só na transição não-vulnerável → vulnerável (sem spam
                # em re-scans de algo já conhecido).
                newly_vulnerable = is_vulnerable and (
                    not existing.is_vulnerable or existing.resolved_at is not None
                )
                existing.last_seen_at = now
                existing.output = v["output"]
                existing.is_vulnerable = is_vulnerable
                existing.resolved_at = None
            else:
                newly_vulnerable = is_vulnerable
                db.session.add(Vulnerability(
                    device_id=device.id,
                    port=v["port"],
                    protocol=v.get("protocol", ""),
                    service=v.get("service", ""),
                    script_name=v["script"],
                    output=v["output"],
                    is_vulnerable=is_vulnerable,
                    found_at=now,
                    last_seen_at=now,
                ))

            # Vulnerabilidade confirmada precisa aparecer na lista de alertas —
            # o card "Vulnerabilidades Abertas" do dashboard conta estas linhas
            # e cada uma deve ter alerta correspondente.
            if newly_vulnerable:
                port_txt = (
                    f" na porta {v.get('protocol', 'tcp') or 'tcp'}/{v['port']}"
                    if v.get("port") else ""
                )
                vuln_alert = Alert(
                    profile_id=device.profile_id,
                    device_id=device.id,
                    alert_type=AlertType.VULNERABILITY,
                    severity=Severity.CRITICAL,
                    message=(
                        f"Vulnerabilidade confirmada em {device.display_name} ({ip})"
                        f"{port_txt}: {v['script']}"
                    ),
                )
                db.session.add(vuln_alert)
                if vuln_profile:
                    _maybe_notify(vuln_alert, vuln_profile, device)

    # --- SNMP ---
    if "snmp" in scan_types:
        from app.models import Profile
        profile = db.session.get(Profile, device.profile_id)
        community = profile.snmp_community if profile else "public"
        snmp_info = get_system_info(ip, community=community)
        results["snmp"] = snmp_info

    # --- Identificação de dispositivo móvel ---
    if "mobile" in scan_types:
        from app.scanner.mobile import scan_mobile_device
        from app.models import DeviceType
        mobile_result = scan_mobile_device(ip)
        results["mobile"] = mobile_result

        # Atualiza device_type se identificado como móvel
        if mobile_result.get("is_mobile"):
            if device.device_type not in (DeviceType.SMARTPHONE, DeviceType.LAPTOP):
                device.device_type = DeviceType.SMARTPHONE

        # Atualiza os_guess com OS provável + modelo
        likely_os = mobile_result.get("likely_os")
        model = mobile_result.get("model", "")
        if likely_os:
            os_label = {"ios": "iOS", "android": "Android",
                        "windows_mobile": "Windows Mobile"}.get(likely_os, likely_os.capitalize())
            device.os_guess = f"{os_label} — {model}".rstrip(" —") if model else os_label

        # Atualiza friendly_name se ainda não tem e foi encontrado um
        friendly = mobile_result.get("friendly_name", "")
        if friendly and not device.friendly_name:
            device.friendly_name = friendly

        # Adiciona detalhes UPnP/fabricante/modelo às notas
        upnp = mobile_result.get("upnp", {})
        info_parts = []
        if upnp.get("manufacturer"):
            info_parts.append(f"Fabricante: {upnp['manufacturer']}")
        if upnp.get("model_name"):
            info_parts.append(f"Modelo: {upnp['model_name']}")
        if upnp.get("model_number"):
            info_parts.append(f"Nº modelo: {upnp['model_number']}")
        if upnp.get("serial_number"):
            info_parts.append(f"Serial: {upnp['serial_number']}")
        if mobile_result.get("mdns_hostname"):
            info_parts.append(f"Hostname mDNS: {mobile_result['mdns_hostname']}")
        if info_parts:
            note_block = "[Mobile Scan] " + " | ".join(info_parts)
            device.notes = (device.notes + "\n" + note_block).strip() if device.notes else note_block

        db.session.commit()

    # Finaliza o scan_record com resultado apropriado por tipo
    if "mobile" in scan_types and "ports" not in scan_types:
        mobile_res = results.get("mobile", {})
        scan_record.hosts_found = 1 if mobile_res.get("is_mobile") else 0
        scan_record.result_summary = _build_mobile_result_message(mobile_res)
    else:
        scan_record.hosts_found = len(results.get("ports", [])) if "ports" in results else 0

    scan_record.status = ScanStatus.SUCCESS
    scan_record.finished_at = _utcnow()
    db.session.commit()
    return results


def _detect_os(ip: str) -> dict:
    """Detecção de sistema operacional via nmap -O.

    Requer root. Sem root, tenta -sV para inferir o OS pelo banner.
    """
    import os
    import nmap

    result = {"os_guess": "", "os_matches": []}
    try:
        nm = nmap.PortScanner()
        if os.geteuid() == 0:
            nm.scan(hosts=ip, arguments="-Pn -O -T4")
            for host in nm.all_hosts():
                os_matches = nm[host].get("osmatch", [])
                if os_matches:
                    result["os_guess"] = os_matches[0].get("name", "")
                    result["os_matches"] = [
                        {"name": m.get("name", ""), "accuracy": m.get("accuracy", "")}
                        for m in os_matches[:5]
                    ]
        else:
            # Sem root: -sV aggressive para inferir OS por banner/service
            nm.scan(hosts=ip, arguments="-Pn -sT -sV --version-intensity 5 -T4")

            # Serviços/produtos que NÃO indicam o OS (servidores de aplicação)
            _NOT_OS = {
                "nginx", "apache", "httpd", "lighttpd", "caddy", "iis",
                "openssh", "ssh", "mysql", "mariadb", "postgresql", "postgres",
                "redis", "memcached", "mongodb", "cups", "postfix", "sendmail",
                "dovecot", "samba", "proftpd", "vsftpd", "squid", "haproxy",
                "tomcat", "jetty", "node.js", "php", "python", "perl",
                "java", "gunicorn", "uvicorn", "dnsmasq",
            }

            os_hints = []       # Pistas reais de OS (extrainfo com nome de OS)
            service_hints = []  # Nomes de produto (fallback inferior)

            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    for port_num in nm[host][proto]:
                        port_data = nm[host][proto][port_num]
                        extra = port_data.get("extrainfo", "")
                        product = port_data.get("product", "")
                        version = port_data.get("version", "")
                        ostype = port_data.get("ostype", "")

                        # ostype é o mais confiável (ex: "Linux", "Windows")
                        if ostype:
                            os_hints.append(ostype)

                        # extrainfo geralmente contém info de OS (ex: "Ubuntu", "Debian")
                        if extra:
                            low = extra.lower()
                            if any(kw in low for kw in ("linux", "ubuntu", "debian", "centos",
                                    "fedora", "windows", "freebsd", "macos", "darwin")):
                                os_hints.append(extra)

                        # product como fallback apenas se NÃO for servidor de app
                        if product:
                            low = product.lower()
                            if not any(app in low for app in _NOT_OS):
                                service_hints.append(f"{product} {version}".strip())

            # Prioriza hints reais de OS sobre nomes de produto
            all_hints = os_hints or service_hints
            if all_hints:
                # Remove duplicatas preservando ordem
                unique = list(dict.fromkeys(all_hints))
                result["os_guess"] = unique[0]
                result["os_matches"] = [
                    {"name": h, "accuracy": "service-based"}
                    for h in unique
                ]
            result["note"] = "Sem root: estimativa por banner de serviço (execute com sudo para -O)."
    except Exception as e:
        logger.exception("Erro na detecção de OS para %s", ip)
        result["error"] = str(e)
    return result


def _scan_vulnerabilities(ip: str) -> dict:
    """Scan básico de vulnerabilidades via nmap scripts."""
    import nmap

    result = {"vulns": []}
    try:
        nm = nmap.PortScanner()
        # -Pn para não pular host, -sV para detectar versões, --script=vuln
        nm.scan(hosts=ip, arguments="-Pn -sV --script=vuln -T4")

        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port_num in nm[host][proto]:
                    port_data = nm[host][proto][port_num]
                    script = port_data.get("script", {})
                    service = port_data.get("name", "")
                    for script_name, output in script.items():
                        result["vulns"].append({
                            "port": port_num,
                            "protocol": proto,
                            "service": service,
                            "script": script_name,
                            "output": output[:1000],
                            "is_vulnerable": "VULNERABLE" in output.upper(),
                        })

            # Scripts a nível de host (não associados a porta)
            host_scripts = nm[host].get("hostscript", [])
            for script in host_scripts:
                result["vulns"].append({
                    "port": 0,
                    "protocol": "",
                    "service": "host",
                    "script": script.get("id", ""),
                    "output": script.get("output", "")[:1000],
                    "is_vulnerable": "VULNERABLE" in script.get("output", "").upper(),
                })

    except Exception as e:
        logger.exception("Erro no vulnerability scan de %s", ip)
        result["error"] = str(e)
    return result


# ---------------------------------------------------------------------------
# Notificações de alertas CRITICAL / WARNING
# ---------------------------------------------------------------------------

def _maybe_notify(alert, profile, device) -> None:
    """Dispara notificação externa para alertas relevantes.

    Notifica quando a severidade do alerta é >= ao nível mínimo configurado no
    perfil (``Profile.notify_min_severity``, default CRITICAL). Assim um perfil
    pode optar por receber também WARNING (NEW_DEVICE/UNAUTHORIZED/IP_CONFLICT)
    sem afetar os demais.
    Falha silenciosa: notificação nunca bloqueia o fluxo de scan.
    """
    from app.models import severity_rank

    min_severity = (getattr(profile, "notify_min_severity", None) or "CRITICAL")
    if severity_rank(alert.severity) < severity_rank(min_severity):
        return
    try:
        from app.extensions import db
        from app.notifications import notify_alert
        # Flush para aplicar os defaults da coluna (id, created_at) antes de
        # montar o payload — _maybe_notify normalmente roda antes do commit,
        # então sem isto o webhook/e-mail sairia com id=None e created_at vazio.
        if alert.id is None or alert.created_at is None:
            db.session.flush()
        notify_alert(alert, profile=profile, device=device)
    except Exception:
        logger.exception("Falha ao enfileirar notificação para alert")


# ---------------------------------------------------------------------------
# Job: HOST_DOWN (detecta devices sumidos)
# ---------------------------------------------------------------------------

def _ack_open_host_down_alerts(device_id: int, now) -> None:
    """Marca alertas HOST_DOWN abertos do device como reconhecidos (device voltou)."""
    from app.extensions import db
    from app.models import Alert, AlertType

    open_alerts = Alert.query.filter_by(
        device_id=device_id,
        alert_type=AlertType.HOST_DOWN,
        acknowledged_at=None,
    ).all()
    for a in open_alerts:
        a.acknowledged_at = now


def quick_host_down_check(profile_id: int):
    """Verifica rapidamente (ping ICMP/ARP/TCP) os devices com alert_on_down=True.

    Diferenças vs. o antigo ``check_host_down``:
    - Não depende de ``last_seen_at`` (que se atualiza só no host discovery, a cada
      45 min) — pinga o IP atual diretamente, evitando falsos positivos.
    - Confirma com duas falhas consecutivas antes de alertar (segunda chance reduz
      ruído por perdas pontuais de pacote).
    - Alerta criado é CRITICAL com ``is_priority=True`` para subir ao topo da UI
      e ser renderizado em alert-danger.

    Quando o host responde, ``last_seen_at`` é atualizado e o contador de falhas
    zera; alertas HOST_DOWN abertos do device são reconhecidos.
    """
    from app.extensions import db
    from app.models import Profile, Device, DeviceIp, Alert, AlertType, Severity
    from app.scanner.hosts import is_host_reachable

    profile = db.session.get(Profile, profile_id)
    if not profile or not profile.is_active:
        return

    try:
        devices = (
            db.session.query(Device, DeviceIp)
            .join(DeviceIp, (DeviceIp.device_id == Device.id) & DeviceIp.is_current.is_(True))
            .filter(
                Device.profile_id == profile_id,
                Device.alert_on_down.is_(True),
            ).all()
        )

        if not devices:
            return

        created = 0
        for device, dip in devices:
            ip = dip.ip
            is_up, _method = is_host_reachable(ip)
            now = _utcnow()

            if is_up:
                # Host respondeu — limpa contador e fecha alertas abertos
                with _quick_host_down_lock:
                    _quick_host_down_failures.pop(device.id, None)
                device.last_seen_at = now
                dip.last_seen_at = now
                device.record_online_today(now.date())
                _ack_open_host_down_alerts(device.id, now)
                continue

            # Falhou — incrementa o contador
            with _quick_host_down_lock:
                failures = _quick_host_down_failures.get(device.id, 0) + 1
                _quick_host_down_failures[device.id] = failures

            if failures < 2:
                # Primeira falha: aguarda próxima execução para confirmar
                logger.info(
                    "Quick check: %s (%s) não respondeu (1ª falha — aguarda confirmação)",
                    device.display_name, ip,
                )
                continue

            # Segunda falha — confirma host down. Só cria alerta se não houver aberto.
            open_alert = Alert.query.filter_by(
                device_id=device.id,
                alert_type=AlertType.HOST_DOWN,
                acknowledged_at=None,
            ).first()
            if open_alert:
                continue

            alert = Alert(
                profile_id=profile_id,
                device_id=device.id,
                alert_type=AlertType.HOST_DOWN,
                severity=Severity.CRITICAL,
                is_priority=True,
                message=(
                    f"Host OFFLINE confirmado: {device.display_name} ({device.mac}) "
                    f"em {ip} — duas verificações consecutivas sem resposta."
                ),
            )
            db.session.add(alert)
            _maybe_notify(alert, profile, device)
            created += 1
            logger.warning(
                "Quick check: %s (%s) HOST_DOWN confirmado após 2 falhas.",
                device.display_name, ip,
            )

        db.session.commit()
        if created:
            logger.info(
                "Quick HOST_DOWN '%s': %d alerta(s) confirmado(s).",
                profile.name, created,
            )
    except Exception:
        db.session.rollback()
        logger.exception("Erro em quick_host_down_check para profile %d", profile_id)


# ---------------------------------------------------------------------------
# Manutenção: re-resolve MACs placeholder de devices online
# ---------------------------------------------------------------------------

def refresh_placeholder_macs(profile_id: int | None = None, prefix: str = "02:00:") -> dict:
    """Tenta substituir MACs placeholder por MACs reais para devices online.

    Para cada device cujo MAC começa com ``prefix`` (placeholder gerado
    quando o ARP não respondeu na descoberta original):
    1. Resolve o IP atual do device.
    2. Verifica se o host responde (ICMP/ARP/TCP) — `is_host_reachable` também
       popula a tabela ARP do kernel como efeito colateral.
    3. Lê a tabela ARP procurando o MAC real do host.
    4. Se encontrar e o MAC não estiver em uso por outro device do mesmo
       perfil, atualiza o device. Se já estiver em uso (duplicata), pula
       e registra no log — o operador deve resolver manualmente.

    Args:
        profile_id: Limita a operação a um perfil específico, ou None para todos.
        prefix: Prefixo de MAC considerado placeholder (default "02:00:").

    Returns:
        Dicionário com estatísticas: checked, updated, online_not_resolved,
        offline, conflicts.
    """
    from app.extensions import db
    from app.models import Device, DeviceIp
    from app.scanner.hosts import (
        is_host_reachable, _read_mac_from_arp_table,
        is_valid_mac, get_vendor_from_mac,
    )

    stats = {
        "checked": 0, "updated": 0, "online_not_resolved": 0,
        "offline": 0, "conflicts": 0, "details": [],
    }

    query = Device.query.filter(Device.mac.like(f"{prefix}%"))
    if profile_id is not None:
        query = query.filter_by(profile_id=profile_id)

    for device in query.all():
        stats["checked"] += 1
        current_dip = DeviceIp.query.filter_by(
            device_id=device.id, is_current=True
        ).first()
        if not current_dip:
            stats["offline"] += 1
            continue

        ip = current_dip.ip
        is_up, _method = is_host_reachable(ip)
        if not is_up:
            stats["offline"] += 1
            stats["details"].append(
                {"device_id": device.id, "ip": ip, "old_mac": device.mac, "result": "offline"}
            )
            continue

        new_mac = _read_mac_from_arp_table(ip)
        if not (is_valid_mac(new_mac) and not new_mac.startswith(prefix)):
            stats["online_not_resolved"] += 1
            stats["details"].append(
                {"device_id": device.id, "ip": ip, "old_mac": device.mac,
                 "result": "online_sem_arp"}
            )
            continue

        conflict = Device.query.filter_by(
            profile_id=device.profile_id, mac=new_mac
        ).filter(Device.id != device.id).first()
        if conflict:
            stats["conflicts"] += 1
            stats["details"].append(
                {"device_id": device.id, "ip": ip, "old_mac": device.mac,
                 "new_mac": new_mac, "result": "conflito",
                 "conflict_device_id": conflict.id}
            )
            logger.warning(
                "MAC real %s para %s já pertence ao device %s; mantendo placeholder %s",
                new_mac, ip, conflict.id, device.mac,
            )
            continue

        old_mac = device.mac
        device.mac = new_mac
        if not device.vendor:
            device.vendor = get_vendor_from_mac(new_mac)
        stats["updated"] += 1
        stats["details"].append(
            {"device_id": device.id, "ip": ip, "old_mac": old_mac,
             "new_mac": new_mac, "result": "atualizado"}
        )
        logger.info("MAC placeholder %s -> %s para device %s (%s)", old_mac, new_mac, device.id, ip)

    db.session.commit()
    logger.info("refresh_placeholder_macs: %s", {k: v for k, v in stats.items() if k != "details"})
    return stats


# ---------------------------------------------------------------------------
# Job: Retenção — limpa dados antigos
# ---------------------------------------------------------------------------

def cleanup_old_data():
    """Remove registros antigos conforme *_RETENTION_DAYS.

    Retention = 0 desativa a limpeza daquela entidade.
    - Scans concluídos antes do cutoff → delete.
    - Alertas acknowledged antes do cutoff → delete.
    - DeviceOnlineSnapshots antes do cutoff → delete.
    - AuditLogs antes do cutoff → delete.
    Devices, Ports e Vulnerabilities NÃO são removidos automaticamente
    (apagar um device cascateia suas portas — perda de estado).
    """
    from flask import current_app
    from app.extensions import db
    from app.models import Scan, Alert, DeviceOnlineSnapshot, AuditLog

    cfg = current_app.config

    def _delete_older(model, column, days: int) -> int:
        if days <= 0:
            return 0
        cutoff = _utcnow() - timedelta(days=days)
        q = db.session.query(model).filter(column < cutoff)
        count = q.count()
        if count:
            q.delete(synchronize_session=False)
        return count

    try:
        removed_scans = _delete_older(
            Scan, Scan.started_at, int(cfg.get("SCAN_RETENTION_DAYS", 30))
        )
        # Apaga apenas alertas já reconhecidos; os abertos permanecem.
        alert_days = int(cfg.get("ALERT_RETENTION_DAYS", 90))
        removed_alerts = 0
        if alert_days > 0:
            cutoff = _utcnow() - timedelta(days=alert_days)
            q = db.session.query(Alert).filter(
                Alert.created_at < cutoff,
                Alert.acknowledged_at.isnot(None),
            )
            removed_alerts = q.count()
            if removed_alerts:
                q.delete(synchronize_session=False)

        removed_snaps = _delete_older(
            DeviceOnlineSnapshot,
            DeviceOnlineSnapshot.recorded_at,
            int(cfg.get("SNAPSHOT_RETENTION_DAYS", 180)),
        )
        removed_audit = _delete_older(
            AuditLog,
            AuditLog.created_at,
            int(cfg.get("AUDIT_LOG_RETENTION_DAYS", 365)),
        )

        db.session.commit()
        logger.info(
            "Retenção: scans=%d, alerts=%d, snapshots=%d, audit=%d removidos.",
            removed_scans, removed_alerts, removed_snaps, removed_audit,
        )
    except Exception:
        db.session.rollback()
        logger.exception("Erro em cleanup_old_data")


# ---------------------------------------------------------------------------
# Backup do banco SQLite (reutilizado pela CLI e pelo job agendado)
# ---------------------------------------------------------------------------

def perform_backup(dest: str | None = None, compress: bool = True) -> str:
    """Gera um backup consistente do banco SQLite e devolve o caminho do arquivo.

    Usa ``sqlite3.connect().backup()`` para garantir consistência transacional
    mesmo com a aplicação em execução. Compatível apenas com SQLite — para
    Postgres use ``pg_dump`` externamente.

    Aplica retenção: remove backups ``netmonitor_*.db[.gz]`` mais antigos que
    ``BACKUP_RETENTION_DAYS`` (0 = mantém todos).

    Levanta ``RuntimeError`` em caso de erro (CLI/itinerário tratam).
    """
    import gzip
    import os
    import shutil
    import sqlite3
    from datetime import datetime
    from flask import current_app

    db_url = current_app.config["SQLALCHEMY_DATABASE_URI"]
    if not db_url.startswith("sqlite:///"):
        raise RuntimeError("backup suporta apenas SQLite. Para PostgreSQL use pg_dump.")

    src_path = db_url.replace("sqlite:///", "")
    if not os.path.isabs(src_path):
        src_path = os.path.abspath(src_path)
    if not os.path.exists(src_path):
        raise RuntimeError(f"Banco não encontrado em: {src_path}")

    backup_dir = os.path.abspath(dest or current_app.config.get("BACKUP_DIR", "backups"))
    os.makedirs(backup_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    dest_path = os.path.join(backup_dir, f"netmonitor_{timestamp}.db")

    src_conn = sqlite3.connect(src_path)
    dst_conn = sqlite3.connect(dest_path)
    try:
        src_conn.backup(dst_conn)
    finally:
        dst_conn.close()
        src_conn.close()

    if compress:
        gz_path = dest_path + ".gz"
        with open(dest_path, "rb") as f_in, gzip.open(gz_path, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)
        os.remove(dest_path)
        dest_path = gz_path

    _prune_old_backups(backup_dir)
    logger.info("Backup do banco gravado em %s (%d KB).", dest_path, os.path.getsize(dest_path) // 1024)
    return dest_path


def _prune_old_backups(backup_dir: str) -> int:
    """Remove backups mais antigos que BACKUP_RETENTION_DAYS. Retorna nº removido."""
    import glob
    import os
    from flask import current_app

    days = int(current_app.config.get("BACKUP_RETENTION_DAYS", 30))
    if days <= 0:
        return 0

    cutoff = time.time() - days * 86400
    removed = 0
    for path in glob.glob(os.path.join(backup_dir, "netmonitor_*.db*")):
        try:
            if os.path.getmtime(path) < cutoff:
                os.remove(path)
                removed += 1
        except OSError:
            continue
    if removed:
        logger.info("Retenção de backups: %d arquivo(s) antigo(s) removido(s).", removed)
    return removed


def backup_database_job():
    """Job agendado: gera backup do banco. Falha silenciosa (apenas loga)."""
    try:
        perform_backup()
    except Exception:
        logger.exception("Erro no backup agendado do banco")
