"""Descoberta de hosts na rede.

Estratégia com fallback automático:
1. Tenta ARP scan via Scapy (precisa de root, mais confiável, retorna MAC).
2. Se falhar por permissão, usa nmap host discovery (funciona sem root).
3. Suplementa com ping sweep + tabela ARP do kernel (detecta smartphones/IoT
   que bloqueiam TCP mas respondem ARP na mesma sub-rede).
4. ICMP ping individual como utilitário auxiliar.
"""

import logging
import os
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from ipaddress import ip_address, ip_network

import nmap

logger = logging.getLogger(__name__)

# Regex para MAC válido (6 grupos de 2 hex separados por :)
_MAC_RE = re.compile(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$")


@dataclass
class HostInfo:
    """Resultado de um host descoberto."""
    ip: str
    mac: str
    hostname: str = ""


class ScanPermissionError(Exception):
    """Indica que o scan falhou por falta de permissão (root necessário)."""


def normalize_mac(mac: str) -> str:
    """Normaliza endereço MAC para formato AA:BB:CC:DD:EE:FF (maiúsculas).

    Returns:
        MAC normalizado, ou string vazia se o input não for um MAC válido.
    """
    if not mac:
        return ""
    mac = mac.strip().upper()
    for sep in ["-", "."]:
        mac = mac.replace(sep, ":")
    clean = mac.replace(":", "")
    # Deve ter exatamente 12 hex chars para ser um MAC válido
    if len(clean) != 12 or not all(c in "0123456789ABCDEF" for c in clean):
        return ""
    formatted = ":".join(clean[i:i+2] for i in range(0, 12, 2))
    # Rejeita MACs nulos
    if formatted == "00:00:00:00:00:00":
        return ""
    return formatted


def is_valid_mac(mac: str) -> bool:
    """Verifica se um MAC normalizado é válido e não é placeholder/nulo."""
    if not mac:
        return False
    return bool(_MAC_RE.match(mac)) and mac != "00:00:00:00:00:00"


def resolve_hostname(ip: str) -> str:
    """Tenta resolver o hostname via DNS reverso."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return ""


def get_vendor_from_mac(mac: str) -> str:
    """Retorna o fabricante baseado no OUI (primeiros 3 octetos do MAC).

    Implementação simplificada — em produção, use um banco OUI completo
    (ex.: arquivo oui.txt do IEEE ou pacote 'mac-vendor-lookup').
    """
    oui_db = {
        "00:50:56": "VMware",
        "00:0C:29": "VMware",
        "08:00:27": "VirtualBox",
        "B8:27:EB": "Raspberry Pi",
        "DC:A6:32": "Raspberry Pi",
        "AA:BB:CC": "Test Vendor",
        "00:1A:2B": "Ayecom Technology",
        "F4:F5:D8": "Google",
        "3C:22:FB": "Apple",
        "A4:83:E7": "Apple",
        "AC:DE:48": "Apple",
        "00:17:88": "Philips Hue",
    }
    normalized = normalize_mac(mac)
    if not normalized:
        return ""
    prefix = normalized[:8]
    return oui_db.get(prefix, "")


# ---------------------------------------------------------------------------
# Detecção de MAC da máquina local
# ---------------------------------------------------------------------------

def _get_local_ips_and_macs() -> dict[str, str]:
    """Retorna mapa {ip: mac} das interfaces de rede locais.

    Lê de /sys/class/net/ e /proc/net/if_inet6, funciona sem root no Linux.
    """
    local_map: dict[str, str] = {}

    try:
        # Lista interfaces de rede
        net_dir = "/sys/class/net"
        if not os.path.isdir(net_dir):
            return local_map

        for iface in os.listdir(net_dir):
            # Ignora loopback e interfaces virtuais docker/veth
            if iface == "lo" or iface.startswith("veth"):
                continue

            # Lê o MAC da interface
            mac_path = os.path.join(net_dir, iface, "address")
            try:
                with open(mac_path) as f:
                    mac = normalize_mac(f.read().strip())
            except (FileNotFoundError, PermissionError):
                continue

            if not is_valid_mac(mac):
                continue

            # Obtém IPs associados a esta interface via 'ip addr show'
            try:
                result = subprocess.run(
                    ["ip", "-4", "addr", "show", iface],
                    capture_output=True, text=True, timeout=5,
                )
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if line.startswith("inet "):
                        # "inet 192.168.100.111/24 brd ..."
                        ip_cidr = line.split()[1]
                        ip_str = ip_cidr.split("/")[0]
                        local_map[ip_str] = mac
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue

    except Exception:
        logger.exception("Erro ao detectar IPs/MACs locais")

    logger.debug("IPs/MACs locais detectados: %s", local_map)
    return local_map


def _read_mac_from_arp_table(ip: str) -> str:
    """Tenta ler o MAC da tabela ARP do sistema para um IP conhecido.

    Funciona sem root — apenas lê /proc/net/arp.
    """
    try:
        with open("/proc/net/arp", "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 4 and parts[0] == ip:
                    mac = normalize_mac(parts[3])
                    if is_valid_mac(mac):
                        return mac
    except (FileNotFoundError, PermissionError):
        pass

    return ""


def _ping_to_populate_arp(ip: str):
    """Envia um ping ao host para forçar a entrada na tabela ARP.

    Sem root, o nmap não retorna MAC. Pingar o host antes de ler
    /proc/net/arp garante que o MAC estará no cache ARP.
    """
    try:
        subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip],
            capture_output=True, timeout=3,
        )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Estratégia principal: tenta ARP, se falhar usa nmap
# ---------------------------------------------------------------------------

def scan_ip_range(cidr: str, timeout: int = 5) -> list[HostInfo]:
    """Descobre hosts em uma faixa CIDR usando a melhor estratégia disponível.

    Tenta ARP scan (Scapy) primeiro. Se falhar por falta de permissão,
    faz fallback automático para nmap host discovery.

    Args:
        cidr: Faixa de rede em notação CIDR, ex.: "192.168.1.0/24"
        timeout: Tempo máximo de espera por respostas (segundos).

    Returns:
        Lista de HostInfo com IP, MAC e hostname.
    """
    if os.geteuid() == 0:
        logger.info("Executando como root — usando ARP scan para %s", cidr)
        return _scan_with_arp(cidr, timeout)

    logger.info("Sem root — usando nmap host discovery para %s", cidr)
    return _scan_with_nmap(cidr)


def _scan_with_arp(cidr: str, timeout: int = 3) -> list[HostInfo]:
    """ARP scan via Scapy. Requer root."""
    from scapy.all import ARP, Ether, srp

    logger.info("Iniciando ARP scan na faixa %s (timeout=%ds)", cidr, timeout)
    hosts: list[HostInfo] = []

    try:
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)
        answered, _ = srp(arp_request, timeout=timeout, verbose=False)

        for sent, received in answered:
            ip = received.psrc
            mac = normalize_mac(received.hwsrc)
            if not is_valid_mac(mac):
                logger.warning("ARP retornou MAC inválido para %s: %s — ignorando", ip, received.hwsrc)
                continue
            hostname = resolve_hostname(ip)
            hosts.append(HostInfo(ip=ip, mac=mac, hostname=hostname))

        logger.info("ARP scan concluído: %d hosts em %s", len(hosts), cidr)
    except PermissionError:
        logger.warning("Sem permissão para ARP scan em %s, tentando nmap...", cidr)
        return _scan_with_nmap(cidr)
    except Exception:
        logger.exception("Erro no ARP scan de %s, tentando nmap...", cidr)
        return _scan_with_nmap(cidr)

    return hosts


def _scan_with_nmap(cidr: str) -> list[HostInfo]:
    """Host discovery via nmap + suplemento ARP.

    Sem root, nmap usa apenas TCP connect() nas portas 80 e 443.
    Smartphones, IoT e outros dispositivos que não têm essas portas abertas
    ficam invisíveis. Para compensar, após o nmap fazemos:
    1. Ping sweep paralelo para popular a tabela ARP do kernel.
    2. Leitura da tabela ARP (ip neigh) para encontrar hosts adicionais.

    O ARP funciona em camada 2 — mesmo que o host bloqueie ICMP e TCP,
    ele DEVE responder ARP para manter sua conexão na rede local.

    Levanta exceção se nmap falhar E o suplemento ARP também não encontrar
    nada — assim o caller registra status=ERROR em vez de SUCCESS com 0 hosts.
    """
    logger.info("Iniciando nmap host discovery em %s", cidr)
    hosts: list[HostInfo] = []
    nmap_error: Exception | None = None

    # Mapa de IPs locais para resolver o MAC da própria máquina
    local_ips = _get_local_ips_and_macs()

    try:
        nm = nmap.PortScanner()
        # -PS faz TCP SYN probe nas portas listadas — detecta hosts que bloqueiam
        # ICMP mas têm alguma porta aberta (servidores com firewall restrito).
        # Sem root o nmap usa TCP connect() em vez de SYN raw, o que funciona
        # igualmente para detectar se o host responde.
        discovery_ports = "21,22,23,25,53,80,110,135,139,143,443,445,993,995,3306,3389,5432,5900,8080,8443"
        nm.scan(hosts=cidr, arguments=f"-sn -PS{discovery_ports} -T4 --host-timeout 10s")

        for host_ip in nm.all_hosts():
            host_data = nm[host_ip]

            if host_data.state() != "up":
                continue

            # Resolve MAC: nmap > interface local > ARP (com ping) > placeholder
            mac = ""

            # 1) MAC direto do nmap (disponível quando rodando como root)
            if "mac" in host_data.get("addresses", {}):
                mac = normalize_mac(host_data["addresses"]["mac"])

            # 2) Se é a própria máquina, pega do sistema de arquivos
            if not is_valid_mac(mac) and host_ip in local_ips:
                mac = local_ips[host_ip]
                logger.debug("MAC da máquina local para %s: %s", host_ip, mac)

            # 3) Ping + tabela ARP (ping força entrada no cache ARP)
            if not is_valid_mac(mac):
                _ping_to_populate_arp(host_ip)
                mac = _read_mac_from_arp_table(host_ip)

            # 4) Último recurso: placeholder determinístico baseado no IP
            if not is_valid_mac(mac):
                mac = _generate_placeholder_mac(host_ip)
                logger.info("MAC não disponível para %s, usando placeholder: %s", host_ip, mac)

            hostname = ""
            if "hostnames" in host_data:
                for hn in host_data["hostnames"]:
                    name = hn.get("name", "")
                    if name:
                        hostname = name
                        break
            if not hostname:
                hostname = resolve_hostname(host_ip)

            hosts.append(HostInfo(ip=host_ip, mac=mac, hostname=hostname))

        logger.info("nmap discovery concluído: %d hosts em %s", len(hosts), cidr)

    except nmap.PortScannerError as e:
        logger.error("Erro do nmap ao descobrir hosts em %s: %s", cidr, e)
        nmap_error = e
    except Exception as e:
        logger.exception("Erro inesperado no nmap discovery de %s", cidr)
        nmap_error = e

    # --- Suplemento ARP: descobre hosts que nmap não viu ---
    nmap_ips = {h.ip for h in hosts}
    arp_extra = _supplement_from_arp(cidr, nmap_ips, local_ips)
    if arp_extra:
        logger.info(
            "ARP supplement encontrou %d hosts adicionais em %s: %s",
            len(arp_extra), cidr, [h.ip for h in arp_extra],
        )
    hosts.extend(arp_extra)

    # nmap falhou e nem o ARP supplement conseguiu pegar nada → propaga o erro
    # para o caller marcar o scan como ERROR. Sem isso, falha de rede vira
    # SUCCESS silencioso com 0 hosts (ex.: scan disparado antes da Wi-Fi subir).
    if nmap_error is not None and not hosts:
        raise nmap_error

    return hosts


# ---------------------------------------------------------------------------
# Suplemento ARP: detecta hosts invisíveis ao nmap (smartphones, IoT)
# ---------------------------------------------------------------------------

def _supplement_from_arp(
    cidr: str, found_ips: set[str], local_ips: dict[str, str],
) -> list[HostInfo]:
    """Descobre hosts adicionais via ping sweep + tabela ARP do kernel.

    Sem root, nmap só usa TCP 80/443 para descoberta. Dispositivos que não
    respondem nessas portas (smartphones, IoT, câmeras) são invisíveis.
    A tabela ARP do kernel contém entradas de qualquer host que comunicou
    na mesma sub-rede recentemente. Combinando um ping sweep (que força
    requisições ARP em L2) com a leitura da tabela, encontramos esses hosts.
    """
    network = ip_network(cidr, strict=False)

    # Limita a ranges <= /22 (1024 hosts) para evitar sweep em redes enormes
    if network.num_addresses > 1024:
        logger.debug("Range %s muito grande para ARP supplement, pulando", cidr)
        return []

    exclude = found_ips | set(local_ips.keys())

    # Fase 1: Ping sweep paralelo — popula cache ARP para hosts na sub-rede
    _ping_sweep_parallel(network, exclude)

    # Fase 2: Lê tabela de vizinhos ARP do kernel
    neighbors = _read_all_arp_neighbors()

    hosts: list[HostInfo] = []
    for ip_str, mac in neighbors.items():
        if ip_str in exclude:
            continue
        try:
            if ip_address(ip_str) not in network:
                continue
        except ValueError:
            continue

        hostname = resolve_hostname(ip_str)
        hosts.append(HostInfo(ip=ip_str, mac=mac, hostname=hostname))

    return hosts


def _ping_sweep_parallel(network, exclude_ips: set[str]):
    """Ping sweep paralelo para popular a tabela ARP do kernel.

    Mesmo que o host não responda ao ICMP (firewall), o kernel envia
    uma requisição ARP antes do ping. Se o host responder ao ARP
    (obrigatório para comunicação em L2), a entrada fica no cache.
    """
    targets = [str(ip) for ip in network.hosts() if str(ip) not in exclude_ips]
    if not targets:
        return

    logger.debug("Ping sweep: %d IPs em %s", len(targets), network)

    def _ping_one(ip):
        try:
            subprocess.run(
                ["ping", "-c", "1", "-W", "1", ip],
                capture_output=True, timeout=3,
            )
        except Exception:
            pass

    # 20 workers: gera no máximo 20 ARP requests simultâneos na rede,
    # evitando inundar switches com requisições ARP em rajada.
    with ThreadPoolExecutor(max_workers=20) as executor:
        list(executor.map(_ping_one, targets))


def _read_all_arp_neighbors() -> dict[str, str]:
    """Lê a tabela ARP do kernel. Retorna {ip: mac} para entradas válidas.

    Usa 'ip neigh show' (mais confiável, mostra estado REACHABLE/STALE).
    Inclui apenas entradas com MAC válido (REACHABLE, STALE, DELAY, PROBE).
    Entradas FAILED (sem MAC confirmado) são ignoradas.
    """
    result: dict[str, str] = {}

    try:
        proc = subprocess.run(
            ["ip", "-4", "neigh", "show", "nud", "reachable",
             "nud", "stale", "nud", "delay", "nud", "probe"],
            capture_output=True, text=True, timeout=5,
        )
        for line in proc.stdout.splitlines():
            # "192.168.100.27 dev wlp2s0 lladdr fa:3f:9a:8f:50:32 STALE"
            parts = line.split()
            if "lladdr" not in parts:
                continue
            ip_str = parts[0]
            lladdr_idx = parts.index("lladdr")
            if lladdr_idx + 1 >= len(parts):
                continue
            mac = normalize_mac(parts[lladdr_idx + 1])
            if is_valid_mac(mac):
                result[ip_str] = mac
    except Exception:
        logger.debug("'ip neigh show' falhou, usando /proc/net/arp como fallback")
        # Fallback: /proc/net/arp (filtra por flag 0x2 = ATF_COM = completa)
        try:
            with open("/proc/net/arp", "r") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) < 4 or parts[0] == "IP":
                        continue
                    try:
                        flag = int(parts[2], 16)
                    except ValueError:
                        continue
                    if not (flag & 0x2):
                        continue
                    mac = normalize_mac(parts[3])
                    if is_valid_mac(mac):
                        result[parts[0]] = mac
        except (FileNotFoundError, PermissionError):
            pass

    return result


def _generate_placeholder_mac(ip: str) -> str:
    """Gera um MAC placeholder determinístico baseado no IP.

    Formato: 02:00:XX:XX:XX:XX (bit locally administered setado).
    """
    parts = ip.split(".")
    if len(parts) != 4:
        return "02:00:00:00:00:01"
    return "02:00:{:02X}:{:02X}:{:02X}:{:02X}".format(
        int(parts[0]) & 0xFF,
        int(parts[1]) & 0xFF,
        int(parts[2]) & 0xFF,
        int(parts[3]) & 0xFF,
    )


def scan_host_with_icmp(ip: str, timeout: int = 2) -> bool:
    """Verifica se um host está up via ICMP echo (ping).

    Usa o comando 'ping' do sistema para não precisar de root.
    """
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout), ip],
            capture_output=True, timeout=timeout + 2,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False
    except Exception:
        logger.exception("Erro ao pingar %s", ip)
        return False


def _tcp_probe(ip: str, timeout: float = 1.5) -> int | None:
    """Tenta conexão TCP em portas comuns em paralelo.

    Retorna o número da primeira porta que responder (aberta OU com
    'connection refused', que confirma que o host está ativo), ou None
    se todas esgotarem o tempo.
    """
    import errno as _errno
    import socket as _socket

    common_ports = [80, 443, 22, 8080, 8443, 53, 8888, 5900, 445, 7]

    def try_port(port: int) -> int | None:
        try:
            with _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                err = sock.connect_ex((ip, port))
                # 0 = conectado (porta aberta)
                # ECONNREFUSED = porta fechada mas HOST ONLINE (TCP stack respondeu RST)
                if err == 0 or err == _errno.ECONNREFUSED:
                    return port
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=len(common_ports)) as executor:
        for result in executor.map(try_port, common_ports):
            if result is not None:
                return result
    return None


def is_host_reachable(ip: str, timeout: int = 2) -> tuple[bool, str]:
    """Verifica se um host está alcançável usando múltiplos métodos.

    Ordem de tentativa:
    1. ICMP ping — mais rápido; também aciona ARP no kernel para popular o cache.
    2. Tabela ARP — dispositivos móveis/IoT bloqueiam ICMP mas devem responder
       ARP (protocolo L2 obrigatório). Lido após o ping para pegar entradas novas.
    3. TCP connect — funciona com ICMP bloqueado se o host tiver alguma porta acessível.

    Returns:
        (is_up, method): is_up indica se o host foi alcançado;
                         method descreve como ("icmp", "arp", "tcp/80", etc.).
    """
    # 1. ICMP ping (também popula tabela ARP do kernel como efeito colateral)
    if scan_host_with_icmp(ip, timeout=1):
        return True, "icmp"

    # 2. Tabela ARP — após o ping, o kernel enviou ARP antes de tentar ICMP.
    #    Se o host respondeu ARP (obrigatório em L2), a entrada está no cache.
    arp_mac = _read_mac_from_arp_table(ip)
    if is_valid_mac(arp_mac) and not arp_mac.startswith("02:00:"):
        return True, "arp"

    # 3. TCP probe — detecta hosts com ICMP bloqueado mas alguma porta ativa
    tcp_port = _tcp_probe(ip, timeout=float(timeout))
    if tcp_port is not None:
        return True, f"tcp/{tcp_port}"

    return False, ""


# Mantém compatibilidade com código antigo
scan_ip_range_with_arp = scan_ip_range
