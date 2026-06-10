"""Cálculo compartilhado das estatísticas do dashboard.

Usado tanto pela view HTML (app/views/main.py) quanto pela API de atualização
ao vivo (/api/metrics/dashboard-stats) para que os números nunca divirjam.
"""

from datetime import timedelta

from flask import current_app

from app.extensions import db
from app.models import Alert, AlertType, Device, Port, Vulnerability, _utcnow


def compute_dashboard_stats(profile_id: int) -> dict:
    """Retorna os contadores dos cartões do dashboard para um perfil."""
    from app.scanner.ports import CRITICAL_PORTS

    now = _utcnow()
    online_minutes = current_app.config.get("HOST_ONLINE_THRESHOLD_MINUTES", 70)
    threshold = now - timedelta(minutes=online_minutes)
    yesterday = now - timedelta(hours=24)

    total_devices = Device.query.filter_by(profile_id=profile_id).count()
    online_devices = Device.query.filter_by(profile_id=profile_id).filter(
        Device.last_seen_at >= threshold
    ).count()
    new_devices_24h = Device.query.filter_by(profile_id=profile_id).filter(
        Device.first_seen_at >= yesterday
    ).count()
    open_alerts = Alert.query.filter_by(profile_id=profile_id).filter(
        Alert.acknowledged_at.is_(None)
    ).count()

    # --- Cartões de segurança ---
    # Devices com pelo menos uma porta crítica aberta (estado open).
    critical_port_devices = (
        db.session.query(Port.device_id)
        .join(Device, Port.device_id == Device.id)
        .filter(
            Device.profile_id == profile_id,
            Port.last_seen_closed_at.is_(None),
            Port.state == "open",
            Port.port.in_(list(CRITICAL_PORTS)),
        )
        .distinct()
        .count()
    )

    # Vulnerabilidades confirmadas e não resolvidas.
    open_vulnerabilities = (
        Vulnerability.query
        .join(Device, Vulnerability.device_id == Device.id)
        .filter(
            Device.profile_id == profile_id,
            Vulnerability.is_vulnerable.is_(True),
            Vulnerability.resolved_at.is_(None),
        )
        .count()
    )

    # Devices marcados "Não Autorizado" vistos online agora.
    unauthorized_online = Device.query.filter_by(profile_id=profile_id).filter(
        Device.situation == "Não Autorizado",
        Device.last_seen_at >= threshold,
    ).count()

    return {
        "total_devices": total_devices,
        "online_devices": online_devices,
        "new_devices_24h": new_devices_24h,
        "open_alerts": open_alerts,
        "critical_port_devices": critical_port_devices,
        "open_vulnerabilities": open_vulnerabilities,
        "unauthorized_online": unauthorized_online,
    }
