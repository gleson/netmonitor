"""Identificação de dispositivos móveis (smartphones/tablets).

Combina quatro técnicas complementares:

1. Scan nmap de portas características
   - 62078/tcp  iOS lockdownd  (iPhone/iPad conectado ao computador)
   - 7000/tcp   AirPlay        (iOS com espelhamento ativo)
   - 7100/tcp   AirPlay alt    (iOS mais recente)
   - 8008/tcp   Google Cast    (Android, Chromecast)
   - 8009/tcp   Google Cast TLS
   - 5000/tcp   UPnP / varios  (Smart TV, Android)
   - 1900/udp   SSDP           (qualquer dispositivo UPnP)

2. Probe UPnP/SSDP unicast (socket Python)
   Muitos dispositivos Android, Smart TVs e roteadores respondem ao M-SEARCH
   e fornecem um XML com modelo, fabricante e nome amigável.

3. Resolução mDNS via avahi-resolve-address
   iPhone/iPad anunciam hostname "<NomeDoUsuário-iPhone>.local" via Bonjour.
   Funciona enquanto o dispositivo estiver na rede com a tela ligada.

4. Script upnp-info do nmap como fallback adicional.

Limitações conhecidas:
- Smartphones em sleep/modo economia de bateria geralmente não respondem.
- Porta 62078 só abre quando o iPhone está pareado com o iTunes/Finder.
- AirPlay/Cast só anunciam quando o serviço está ativo.
- Melhor resultado com o dispositivo desbloqueado e conectado ao Wi-Fi.
"""

import logging
import os
import socket
import struct
import subprocess
import urllib.request
from xml.etree import ElementTree

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Mapa de portas → significado
# ---------------------------------------------------------------------------
_PORT_HINTS: dict[int, str] = {
    62078: "iOS lockdownd (iPhone/iPad)",
    7000:  "AirPlay (Apple iOS/macOS)",
    7100:  "AirPlay alternativo (Apple)",
    8008:  "Google Cast (Android/Chromecast)",
    8009:  "Google Cast TLS (Android/Chromecast)",
    5000:  "UPnP / AirPlay / Samsung SmartTV",
    1900:  "SSDP/UPnP",
}

# Portas que indicam fortemente iOS
_IOS_PORTS = {62078, 7000, 7100}

# Portas que indicam fortemente Android/Cast
_ANDROID_PORTS = {8008, 8009}


# ---------------------------------------------------------------------------
# Função principal
# ---------------------------------------------------------------------------

def scan_mobile_device(ip: str) -> dict:
    """Identifica se o dispositivo é um smartphone/tablet e coleta informações.

    Args:
        ip: Endereço IPv4 do alvo.

    Returns:
        dict com as chaves:
        - is_mobile (bool)
        - likely_os (str): "ios" | "android" | "unknown" | None
        - friendly_name (str): nome do dispositivo se encontrado
        - manufacturer (str)
        - model (str)
        - open_mobile_ports (dict): porta -> {state, service, hint}
        - upnp (dict): campos do XML UPnP se disponível
        - mdns_hostname (str): hostname .local se resolvido
        - techniques_used (list[str])
        - note (str): observações / limitações
    """
    result: dict = {
        "is_mobile": False,
        "likely_os": None,
        "friendly_name": "",
        "manufacturer": "",
        "model": "",
        "open_mobile_ports": {},
        "upnp": {},
        "mdns_hostname": "",
        "techniques_used": [],
        "note": "",
    }

    # 1. Scan de portas características
    mobile_ports = _scan_mobile_ports(ip)
    result["open_mobile_ports"] = mobile_ports
    if mobile_ports:
        result["techniques_used"].append("port_scan")

    # 2. Probe SSDP/UPnP unicast
    upnp = _ssdp_probe(ip)
    if upnp:
        result["upnp"] = upnp
        result["techniques_used"].append("upnp_ssdp")
        if upnp.get("friendly_name") and not result["friendly_name"]:
            result["friendly_name"] = upnp["friendly_name"]
        if upnp.get("manufacturer") and not result["manufacturer"]:
            result["manufacturer"] = upnp["manufacturer"]
        if upnp.get("model_name") and not result["model"]:
            result["model"] = upnp["model_name"]

    # 3. Resolução mDNS via avahi-resolve-address
    mdns_hostname = _avahi_resolve(ip)
    if mdns_hostname:
        result["mdns_hostname"] = mdns_hostname
        result["techniques_used"].append("mdns_avahi")
        if not result["friendly_name"]:
            result["friendly_name"] = mdns_hostname

    # --- Determina se é móvel e qual OS provável ---
    open_ports = set(mobile_ports.keys())

    if _IOS_PORTS & open_ports:
        result["is_mobile"] = True
        result["likely_os"] = "ios"
    elif _ANDROID_PORTS & open_ports:
        result["is_mobile"] = True
        result["likely_os"] = "android"
    elif upnp:
        # UPnP respondeu — dispositivo "smart" (pode ser Android, Smart TV, etc.)
        result["is_mobile"] = True
        result["likely_os"] = _guess_os_from_upnp(upnp)
    elif mdns_hostname:
        # mDNS respondeu — provável Apple
        result["is_mobile"] = True
        result["likely_os"] = _guess_os_from_hostname(mdns_hostname)

    if not result["is_mobile"]:
        result["note"] = (
            "Nenhum indicador de dispositivo móvel encontrado. "
            "Smartphones em modo sleep ou com Wi-Fi inativo geralmente não respondem. "
            "Tente enquanto o dispositivo estiver desbloqueado e com a tela ligada."
        )
    elif not result["techniques_used"]:
        result["note"] = "Dispositivo identificado pelo vendor do MAC."

    return result


# ---------------------------------------------------------------------------
# Técnica 1 — nmap nas portas características
# ---------------------------------------------------------------------------

def _scan_mobile_ports(ip: str) -> dict[int, dict]:
    """Verifica portas características de dispositivos móveis via nmap."""
    try:
        import nmap as nmap_mod
    except ImportError:
        logger.warning("python-nmap não disponível para scan de portas móveis.")
        return {}

    ports_str = ",".join(str(p) for p in _PORT_HINTS)
    nm = nmap_mod.PortScanner()
    found: dict[int, dict] = {}

    try:
        args = "-Pn -sS -T4" if os.geteuid() == 0 else "-Pn -sT -T4"
        nm.scan(hosts=ip, ports=ports_str, arguments=args)

        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port_num in nm[host][proto]:
                    state = nm[host][proto][port_num].get("state", "")
                    if state in ("open", "open|filtered"):
                        found[port_num] = {
                            "state": state,
                            "service": nm[host][proto][port_num].get("name", ""),
                            "hint": _PORT_HINTS.get(port_num, ""),
                        }
    except Exception:
        logger.exception("Erro no scan de portas móveis para %s", ip)

    return found


# ---------------------------------------------------------------------------
# Técnica 2 — Probe SSDP/UPnP unicast
# ---------------------------------------------------------------------------

def _ssdp_probe(ip: str, timeout: float = 2.5) -> dict:
    """Envia M-SEARCH unicast à porta 1900 e parseia resposta UPnP."""
    msearch = (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {ip}:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 1\r\n"
        "ST: ssdp:all\r\n"
        "\r\n"
    ).encode()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(msearch, (ip, 1900))

        try:
            data, _ = sock.recvfrom(4096)
        except socket.timeout:
            return {}
        finally:
            sock.close()

        # Parseia headers HTTP da resposta SSDP
        headers: dict[str, str] = {}
        for line in data.decode("utf-8", errors="replace").split("\r\n")[1:]:
            if ":" in line:
                key, _, val = line.partition(":")
                headers[key.strip().lower()] = val.strip()

        result: dict = {
            "server": headers.get("server", ""),
            "usn": headers.get("usn", ""),
        }

        location = headers.get("location", "")
        if location:
            result["location"] = location
            xml_info = _fetch_upnp_xml(location)
            result.update(xml_info)

        return result

    except Exception:
        logger.debug("SSDP probe para %s falhou", ip)
        return {}


def _fetch_upnp_xml(url: str, timeout: float = 3.0) -> dict:
    """Busca e parseia o XML de descrição do dispositivo UPnP."""
    result: dict = {}
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "NetMonitor/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(65536)

        root = ElementTree.fromstring(raw)

        def find_text(tag: str) -> str:
            for elem in root.iter():
                local = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
                if local == tag and elem.text:
                    return elem.text.strip()
            return ""

        result["friendly_name"]      = find_text("friendlyName")
        result["manufacturer"]       = find_text("manufacturer")
        result["manufacturer_url"]   = find_text("manufacturerURL")
        result["model_name"]         = find_text("modelName")
        result["model_number"]       = find_text("modelNumber")
        result["model_description"]  = find_text("modelDescription")
        result["serial_number"]      = find_text("serialNumber")
        result["device_type"]        = find_text("deviceType")

    except Exception:
        logger.debug("Fetch UPnP XML de %s falhou", url)

    return result


# ---------------------------------------------------------------------------
# Técnica 3 — mDNS via avahi-resolve-address
# ---------------------------------------------------------------------------

def _avahi_resolve(ip: str) -> str:
    """Resolve o IP para hostname .local via avahi-resolve-address.

    Retorna o hostname sem '.local', ou '' se não disponível/falhou.
    """
    try:
        proc = subprocess.run(
            ["avahi-resolve-address", "-4", ip],
            capture_output=True,
            text=True,
            timeout=4.0,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            # Formato: "192.168.1.10\tiPhone-de-Joao.local"
            parts = proc.stdout.strip().split("\t")
            if len(parts) >= 2:
                return parts[1].strip().removesuffix(".local")
    except FileNotFoundError:
        logger.debug("avahi-resolve-address não encontrado no sistema.")
    except subprocess.TimeoutExpired:
        logger.debug("avahi-resolve-address timeout para %s", ip)
    except Exception:
        logger.debug("Erro ao resolver mDNS para %s", ip)
    return ""


# ---------------------------------------------------------------------------
# Helpers de classificação
# ---------------------------------------------------------------------------

def _guess_os_from_upnp(upnp: dict) -> str:
    """Infere o OS a partir dos campos UPnP."""
    text = " ".join([
        upnp.get("friendly_name", ""),
        upnp.get("manufacturer", ""),
        upnp.get("model_name", ""),
        upnp.get("server", ""),
        upnp.get("device_type", ""),
    ]).lower()

    if any(k in text for k in ("apple", "iphone", "ipad", "ios")):
        return "ios"
    if any(k in text for k in ("android", "google", "samsung", "xiaomi",
                                "motorola", "huawei", "oppo", "oneplus")):
        return "android"
    if "windows" in text:
        return "windows_mobile"
    return "unknown"


def _guess_os_from_hostname(hostname: str) -> str:
    """Infere o OS a partir do hostname mDNS."""
    h = hostname.lower()
    if any(k in h for k in ("iphone", "ipad", "ipod", "macbook", "imac", "apple")):
        return "ios"
    if any(k in h for k in ("android", "pixel", "samsung", "galaxy")):
        return "android"
    return "unknown"
