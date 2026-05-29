"""Scan de portas e serviços via python-nmap."""

import logging
from dataclasses import dataclass

import nmap

logger = logging.getLogger(__name__)

# Portas de alto risco de segurança — geram alerta CRITICAL e ícone na lista
CRITICAL_PORTS: frozenset[int] = frozenset({
    23,    # Telnet
    135,   # Windows RPC
    139,   # NetBIOS
    445,   # SMB (EternalBlue, WannaCry)
    1433,  # MSSQL
    1434,  # MSSQL Browser
    3389,  # RDP (BlueKeep)
    4444,  # Metasploit/backdoors
    5900,  # VNC
    5985,  # WinRM HTTP
    5986,  # WinRM HTTPS
})

# Portas padrão ampliadas — cobre os serviços mais comuns
DEFAULT_PORTS = (
    "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,"
    "1110,1433,1723,2869,3306,3389,5060,5357,5432,5900,"
    "8080,8443,8888,9090,19780"
)


@dataclass
class PortInfo:
    """Resultado de uma porta encontrada em um host."""
    port: int
    protocol: str  # "tcp" ou "udp"
    state: str      # "open", "closed", "filtered", "open|filtered"
    service_name: str = ""
    service_version: str = ""


def scan_ports_for_host(
    ip: str,
    ports: str = DEFAULT_PORTS,
    arguments: str | None = None,
) -> tuple[list[PortInfo], bool]:
    """Escaneia portas de um host usando nmap.

    Seleciona automaticamente o melhor tipo de scan:
    - Com root: -sS (SYN scan) — mais rápido e detecta filtered.
    - Sem root: -sT (TCP connect) — não precisa de privilégios.

    Sempre usa:
    - -Pn: Assume host up (já foi descoberto, não precisa pingar de novo).
    - -sV --version-intensity 2: Detecção leve de versão de serviço.
    - -T4: Timing agressivo mas não abusivo.

    Args:
        ip: Endereço IP do host alvo.
        ports: String com portas separadas por vírgula, ou range ("1-1024").
        arguments: Argumentos do nmap (se None, auto-detecta baseado em permissões).

    Returns:
        Tupla (ports, host_scanned):
        - ports: lista de PortInfo com portas open/filtered encontradas.
        - host_scanned: True se o nmap encontrou e escaneou o host com sucesso.
          False indica falha no scan (exceção, host invisível à rede) — neste
          caso o chamador NÃO deve atualizar o status das portas no banco.

    Motivação para host_scanned:
        Sem este flag, se o scan retorna vazio (host offline com RST do roteador,
        ou exceção do nmap), todas as portas anteriormente abertas seriam
        erroneamente marcadas como fechadas, gerando re-alertas na próxima
        vez que o host ficasse online.
    """
    import os

    if arguments is None:
        # --host-timeout limita o tempo total por host, evitando que nmap
        # trave o scheduler em hosts inacessíveis (especialmente com scan_all_ports).
        # 300s para scan padrão; scans de todas as portas podem precisar mais,
        # mas o ThreadPoolExecutor já limita a 600s por thread.
        host_timeout = "--host-timeout 300s"
        if os.geteuid() == 0:
            # Root: SYN scan (detecta filtered)
            arguments = f"-Pn -sS -sV -T4 --version-intensity 2 {host_timeout}"
        else:
            # Sem root: TCP connect scan
            arguments = f"-Pn -sT -sV -T4 --version-intensity 2 {host_timeout}"

    logger.info("Iniciando port scan em %s (portas: %s, args: %s)", ip, ports, arguments)
    results: list[PortInfo] = []
    host_scanned = False

    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=ip, ports=ports, arguments=arguments)

        for host in nm.all_hosts():
            host_scanned = True  # nmap alcançou e reportou o host
            for proto in nm[host].all_protocols():
                port_list = sorted(nm[host][proto].keys())
                for port_num in port_list:
                    port_data = nm[host][proto][port_num]
                    state = port_data.get("state", "unknown")
                    # Ignora portas explicitamente fechadas — não são interessantes
                    if state == "closed":
                        continue
                    results.append(PortInfo(
                        port=port_num,
                        protocol=proto,
                        state=state,
                        service_name=port_data.get("name", ""),
                        service_version=port_data.get("version", ""),
                    ))

        open_count = sum(1 for p in results if p.state == "open")
        filtered_count = sum(1 for p in results if "filtered" in p.state)
        logger.info(
            "Port scan concluído em %s: host_scanned=%s, %d portas (open=%d, filtered=%d)",
            ip, host_scanned, len(results), open_count, filtered_count,
        )
    except nmap.PortScannerError:
        logger.exception("Erro do nmap ao escanear %s", ip)
    except Exception:
        logger.exception("Erro inesperado no port scan de %s", ip)

    return results, host_scanned


def get_open_ports(port_infos: list[PortInfo]) -> list[PortInfo]:
    """Filtra portas com estado 'open' ou 'open|filtered'."""
    return [p for p in port_infos if p.state in ("open", "open|filtered")]


def get_filtered_ports(port_infos: list[PortInfo]) -> list[PortInfo]:
    """Filtra portas com estado 'filtered'."""
    return [p for p in port_infos if p.state == "filtered"]


def get_actionable_ports(port_infos: list[PortInfo]) -> list[PortInfo]:
    """Filtra portas relevantes: open, open|filtered e filtered."""
    return [p for p in port_infos if p.state != "closed"]


def diff_ports(
    old_ports: set[tuple[str, int]],
    new_ports: set[tuple[str, int]],
) -> tuple[set[tuple[str, int]], set[tuple[str, int]]]:
    """Compara conjuntos de portas antigas e novas.

    Cada porta é representada como tupla (protocol, port_number).

    Args:
        old_ports: Conjunto de portas no snapshot anterior.
        new_ports: Conjunto de portas encontradas agora.

    Returns:
        Tupla (opened, closed):
            - opened: portas que são novas (não existiam antes).
            - closed: portas que existiam antes e agora não foram encontradas.
    """
    opened = new_ports - old_ports
    closed = old_ports - new_ports
    return opened, closed
