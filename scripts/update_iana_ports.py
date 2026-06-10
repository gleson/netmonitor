#!/usr/bin/env python3
"""Atualiza um índice de nomes de serviço de portas a partir do registro IANA.

Demonstra que a base "técnica" de portas pode ser atualizada **sem LLM**: o
registro oficial IANA (Service Name and Transport Protocol Port Number
Registry) é um CSV público. Este script o baixa e gera
``app/data/iana_ports.json`` com o mapeamento porta/protocolo → nome + descrição
curta de serviço.

IMPORTANTE — o que isto NÃO substitui:
    O catálogo rico de ``app/views/ports_info.py`` (riscos, análise, comandos
    nmap/tcpdump, quando alertar) é conteúdo editorial em pt-BR que a IANA não
    fornece. Este índice serve para (a) detectar portas ainda sem ficha no
    catálogo e (b) preencher o nome do serviço como fallback. Veja
    ``docs/atualizacao-bases.md``.

Uso:
    python scripts/update_iana_ports.py            # baixa e grava o JSON
    python scripts/update_iana_ports.py --check    # só reporta diferenças

Pode ser agendado em cron — não depende da aplicação Flask nem de chave de API.
"""

import argparse
import csv
import io
import json
import os
import sys
from urllib.request import Request, urlopen

IANA_CSV_URL = (
    "https://www.iana.org/assignments/service-names-port-numbers/"
    "service-names-port-numbers.csv"
)

OUTPUT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "app", "data", "iana_ports.json",
)


def fetch_iana_csv(timeout: int = 60) -> str:
    req = Request(IANA_CSV_URL, headers={"User-Agent": "NetMonitor IANA updater"})
    with urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


def parse_ports(csv_text: str) -> dict:
    """Converte o CSV da IANA em {"<port>/<proto>": {service, description}}."""
    index: dict[str, dict] = {}
    reader = csv.DictReader(io.StringIO(csv_text))
    for row in reader:
        port = (row.get("Port Number") or "").strip()
        proto = (row.get("Transport Protocol") or "").strip().lower()
        service = (row.get("Service Name") or "").strip()
        desc = (row.get("Description") or "").strip()
        if not port or not proto or not service:
            continue
        if not port.isdigit():
            continue  # ignora faixas "1024-65535"
        key = f"{port}/{proto}"
        # Mantém a primeira ocorrência (entradas oficiais vêm primeiro).
        index.setdefault(key, {"service": service, "description": desc[:200]})
    return index


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="Só reporta diferenças, sem gravar.")
    args = parser.parse_args()

    try:
        csv_text = fetch_iana_csv()
    except Exception as exc:  # noqa: BLE001 - script de linha de comando
        print(f"ERRO ao baixar o CSV da IANA: {exc}", file=sys.stderr)
        return 1

    index = parse_ports(csv_text)
    print(f"IANA: {len(index)} portas/protocolos com nome de serviço.")

    if args.check:
        if os.path.exists(OUTPUT_PATH):
            with open(OUTPUT_PATH, encoding="utf-8") as fh:
                old = json.load(fh)
            added = set(index) - set(old)
            removed = set(old) - set(index)
            print(f"Novas: {len(added)} | removidas: {len(removed)}")
            for k in sorted(added)[:20]:
                print(f"  + {k}: {index[k]['service']}")
        else:
            print("Sem JSON anterior para comparar.")
        return 0

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as fh:
        json.dump(index, fh, ensure_ascii=False, indent=2, sort_keys=True)
    print(f"Gravado: {OUTPUT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
