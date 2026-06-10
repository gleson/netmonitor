"""Endpoints JSON para dispositivos."""

from flask import jsonify, request
from flask_login import login_required

from app.api import api_bp, to_iso
from app.extensions import db
from app.models import Device, DeviceIp, Port, Profile


@api_bp.route("/devices")
@login_required
def api_device_list():
    """Retorna lista de dispositivos em JSON.

    Query params: profile_id, q (busca), page, per_page.
    """
    profile_id = request.args.get("profile_id", type=int)
    search = request.args.get("q", "").strip()
    page = request.args.get("page", 1, type=int)
    # Cap duro em 200 para evitar cliente puxando 100k linhas numa request.
    per_page = min(max(request.args.get("per_page", 50, type=int), 1), 200)

    query = Device.query

    if profile_id:
        query = query.filter_by(profile_id=profile_id)

    if search:
        like = f"%{search}%"
        query = query.filter(
            db.or_(
                Device.friendly_name.ilike(like),
                Device.hostname.ilike(like),
                Device.mac.ilike(like),
            )
        )

    query = query.order_by(Device.last_seen_at.desc())
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)

    devices = []
    for d in pagination.items:
        devices.append(_device_to_dict(d))

    return jsonify({
        "devices": devices,
        "total": pagination.total,
        "page": pagination.page,
        "pages": pagination.pages,
    })


@api_bp.route("/devices/<int:device_id>")
@login_required
def api_device_detail(device_id):
    """Retorna detalhe de um dispositivo em JSON."""
    device = db.session.get(Device, device_id)
    if not device:
        return jsonify({"error": "Dispositivo não encontrado."}), 404

    data = _device_to_dict(device)

    # Histórico de IPs
    ips = DeviceIp.query.filter_by(device_id=device.id).order_by(DeviceIp.last_seen_at.desc()).all()
    data["ip_history"] = [
        {
            "ip": dip.ip,
            "is_current": dip.is_current,
            "first_seen_at": to_iso(dip.first_seen_at),
            "last_seen_at": to_iso(dip.last_seen_at),
        }
        for dip in ips
    ]

    # Portas abertas
    open_ports = Port.query.filter_by(device_id=device.id).filter(
        Port.last_seen_closed_at.is_(None)
    ).order_by(Port.port).all()
    data["open_ports"] = [
        {
            "protocol": p.protocol,
            "port": p.port,
            "service_name": p.service_name,
            "service_version": p.service_version,
            "first_open_at": to_iso(p.first_open_at),
            "last_seen_open_at": to_iso(p.last_seen_open_at),
        }
        for p in open_ports
    ]

    return jsonify(data)


def _device_to_dict(device: Device) -> dict:
    return {
        "id": device.id,
        "profile_id": device.profile_id,
        "mac": device.mac,
        "hostname": device.hostname,
        "friendly_name": device.friendly_name,
        "display_name": device.display_name,
        "vendor": device.vendor,
        "device_type": device.device_type.value if device.device_type else "OTHER",
        "os_guess": device.os_guess,
        "current_ip": device.current_ip,
        "open_ports_count": device.open_ports_count,
        "truly_open_ports_count": device.truly_open_ports_count,
        "first_seen_at": to_iso(device.first_seen_at),
        "last_seen_at": to_iso(device.last_seen_at),
    }
