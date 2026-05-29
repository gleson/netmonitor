"""Funções utilitárias de coleta SNMP via PySNMP 6.x (async).

Módulo opcional e modular — pode ser desabilitado por profile.
"""

import asyncio
import logging

logger = logging.getLogger(__name__)

# OIDs comuns
OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"
OID_SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
OID_SYS_CONTACT = "1.3.6.1.2.1.1.4.0"
OID_SYS_LOCATION = "1.3.6.1.2.1.1.6.0"
OID_IF_NUMBER = "1.3.6.1.2.1.2.1.0"


def snmp_get(ip: str, oid: str, community: str = "public", port: int = 161, timeout: int = 5) -> str | None:
    """Faz um SNMP GET para um OID específico (wrapper síncrono).

    Args:
        ip: Endereço IP do agente SNMP.
        oid: OID a consultar.
        community: Community string SNMPv2c.
        port: Porta SNMP (padrão 161).
        timeout: Timeout em segundos.

    Returns:
        Valor retornado como string, ou None se falhar.
    """
    try:
        from pysnmp.hlapi.asyncio import (
            getCmd, SnmpEngine, CommunityData, UdpTransportTarget,
            ContextData, ObjectType, ObjectIdentity,
        )
    except ImportError:
        logger.warning("pysnmp não instalado. Ignorando consulta SNMP.")
        return None

    async def _do_get():
        error_indication, error_status, error_index, var_binds = await getCmd(
            SnmpEngine(),
            CommunityData(community),
            UdpTransportTarget((ip, port), timeout=timeout, retries=1),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
        )

        if error_indication:
            logger.warning("SNMP error indication para %s: %s", ip, error_indication)
            return None
        if error_status:
            logger.warning(
                "SNMP error status para %s: %s at %s",
                ip, error_status.prettyPrint(),
                error_index and var_binds[int(error_index) - 1][0] or "?",
            )
            return None

        for name, val in var_binds:
            return str(val)
        return None

    try:
        # Reutiliza loop existente se estiver num contexto async,
        # senão cria um novo com asyncio.run()
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                return pool.submit(asyncio.run, _do_get()).result(timeout=timeout + 2)
        else:
            return asyncio.run(_do_get())
    except Exception:
        logger.exception("Erro SNMP ao consultar %s (OID=%s)", ip, oid)
        return None


def get_system_info(ip: str, community: str = "public") -> dict:
    """Coleta informações básicas do sistema via SNMP.

    Returns:
        Dicionário com chaves: sys_descr, sys_name, sys_uptime, sys_contact, sys_location.
        Se nenhum dado for retornado, inclui chave 'error'.
    """
    info = {}
    oid_map = {
        "sys_descr": OID_SYS_DESCR,
        "sys_name": OID_SYS_NAME,
        "sys_uptime": OID_SYS_UPTIME,
        "sys_contact": OID_SYS_CONTACT,
        "sys_location": OID_SYS_LOCATION,
    }
    for key, oid in oid_map.items():
        value = snmp_get(ip, oid, community=community)
        if value is not None:
            info[key] = value

    if not info:
        info["error"] = f"Nenhuma resposta SNMP de {ip} (timeout ou agente SNMP desabilitado)."

    return info
