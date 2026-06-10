"""Blueprint de dispositivos — inventário, detalhe e scan manual."""

import ipaddress

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required

from app.auth_utils import audit, require_role
from app.extensions import db
from app.models import (
    Device, DeviceIp, Port, Profile, DeviceType, Vulnerability,
    ROLE_ADMIN, ROLE_OPERATOR, _utcnow,
)

devices_bp = Blueprint("devices", __name__, template_folder="../templates/devices")


def _ip_in_profile_ranges(ip_str: str, profile_id: int) -> bool:
    """True se `ip_str` cai em algum IpRange habilitado do profile.

    Garante que scans manuais e criação por IP só alcancem alvos dentro
    do escopo autorizado do perfil — evita usar o servidor como pivot de
    recon contra IPs arbitrários.
    """
    from app.models import IpRange

    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    ranges = IpRange.query.filter_by(profile_id=profile_id, enabled=True).all()
    if not ranges:
        # Sem ranges configurados = sem restrição de escopo
        return True
    for r in ranges:
        try:
            if addr in ipaddress.ip_network(r.cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


@devices_bp.route("/")
@login_required
def device_list():
    """Lista de dispositivos com filtros e ordenação."""
    from datetime import timedelta
    from flask import current_app

    from app.profile_utils import get_active_profile_id
    profile_id = get_active_profile_id()
    search = request.args.get("q", "").strip()
    device_type = request.args.get("type", "")
    status_filter = request.args.get("status", "")
    sort = request.args.get("sort", "last_seen_at")
    order = request.args.get("order", "desc")
    page = request.args.get("page", 1, type=int)

    # Naive UTC para bater com o que está armazenado nas colunas `db.DateTime`.
    threshold_min = current_app.config.get("HOST_ONLINE_THRESHOLD_MINUTES", 70)
    now = _utcnow()
    online_cutoff = now - timedelta(minutes=threshold_min)
    new_cutoff = now - timedelta(hours=24)

    query = Device.query

    if profile_id:
        query = query.filter_by(profile_id=profile_id)

    if search:
        like = f"%{search}%"
        # IP vive em DeviceIp (relacionamento 1:N por histórico) — checa via EXISTS
        # para qualquer IP (atual ou antigo) do device casar a busca.
        ip_match = (
            db.select(DeviceIp.id)
            .where(DeviceIp.device_id == Device.id, DeviceIp.ip.ilike(like))
            .exists()
        )
        query = query.filter(
            db.or_(
                Device.friendly_name.ilike(like),
                Device.hostname.ilike(like),
                Device.mac.ilike(like),
                Device.vendor.ilike(like),
                ip_match,
            )
        )

    if device_type:
        try:
            dt = DeviceType(device_type)
            query = query.filter_by(device_type=dt)
        except ValueError:
            pass

    if status_filter == "online":
        query = query.filter(Device.last_seen_at >= online_cutoff)
    elif status_filter == "offline":
        query = query.filter(Device.last_seen_at < online_cutoff)
    elif status_filter == "new":
        query = query.filter(Device.first_seen_at >= new_cutoff)

    # Subqueries para colunas calculadas
    from sqlalchemy import func

    current_ip_sq = (
        db.select(DeviceIp.ip)
        .where(DeviceIp.device_id == Device.id, DeviceIp.is_current == True)
        .correlate(Device)
        .scalar_subquery()
    )
    open_ports_sq = (
        db.select(func.count(Port.id))
        .where(Port.device_id == Device.id, Port.last_seen_closed_at.is_(None))
        .correlate(Device)
        .scalar_subquery()
    )

    # Ordenação
    sortable = {
        "status": Device.last_seen_at,
        "name": Device.friendly_name,
        "hostname": Device.hostname,
        "ip": current_ip_sq,
        "mac": Device.mac,
        "vendor": Device.vendor,
        "type": Device.device_type,
        "situation": Device.situation,
        "tags": Device.tags,
        "first_seen_at": Device.first_seen_at,
        "last_seen_at": Device.last_seen_at,
        "ports": open_ports_sq,
    }
    sort_col = sortable.get(sort, Device.last_seen_at)
    if order == "asc":
        query = query.order_by(sort_col.asc())
    else:
        query = query.order_by(sort_col.desc())

    pagination = query.paginate(page=page, per_page=25, error_out=False)

    # IDs de devices desta página que têm porta crítica aberta
    from app.scanner.ports import CRITICAL_PORTS
    critical_device_ids: set[int] = set()
    if pagination.items:
        page_ids = [d.id for d in pagination.items]
        rows = (
            Port.query
            .with_entities(Port.device_id)
            .filter(
                Port.device_id.in_(page_ids),
                Port.last_seen_closed_at.is_(None),
                Port.port.in_(list(CRITICAL_PORTS)),
                Port.state == "open",
            )
            .distinct()
            .all()
        )
        critical_device_ids = {r.device_id for r in rows}

    return render_template(
        "devices/list.html",
        devices=pagination.items,
        pagination=pagination,
        selected_profile_id=profile_id,
        search=search,
        device_type=device_type,
        status_filter=status_filter,
        sort=sort,
        order=order,
        device_types=DeviceType,
        online_cutoff=online_cutoff,
        new_cutoff=new_cutoff,
        threshold_min=threshold_min,
        critical_device_ids=critical_device_ids,
    )


@devices_bp.route("/history")
@login_required
def device_history():
    """Histórico diário: quais devices foram vistos online em cada data.

    Agrega ``Device.online_dates`` de todos os devices do perfil ativo.
    Aceita ``?days=N`` para janela personalizada (default 30, máx 365).
    """
    from datetime import date as _date, timedelta as _td

    from app.profile_utils import get_active_profile_id

    profile_id = get_active_profile_id()
    try:
        days = int(request.args.get("days", 30))
    except ValueError:
        days = 30
    days = max(1, min(days, 365))

    today = _utcnow().date()
    window_start = today - _td(days=days - 1)
    window_start_str = window_start.isoformat()

    query = Device.query
    if profile_id:
        query = query.filter_by(profile_id=profile_id)

    devices = query.all()

    by_date: dict[str, list[Device]] = {}
    for d in devices:
        for ds in d.get_online_dates():
            if ds >= window_start_str:
                by_date.setdefault(ds, []).append(d)

    rows = sorted(by_date.items(), key=lambda kv: kv[0], reverse=True)

    # Data em que o tracking começou (mínima registrada no perfil ativo)
    all_dates: list[str] = []
    for d in devices:
        all_dates.extend(d.get_online_dates())
    tracking_started = min(all_dates) if all_dates else None

    return render_template(
        "devices/history.html",
        rows=rows,
        days=days,
        window_start=window_start,
        tracking_started=tracking_started,
        total_devices=len(devices),
    )


@devices_bp.route("/<int:device_id>")
@login_required
def device_detail(device_id):
    """Detalhe de um dispositivo."""
    from flask import current_app
    device = db.session.get(Device, device_id) or abort(404)
    ips = DeviceIp.query.filter_by(device_id=device.id).order_by(DeviceIp.last_seen_at.desc()).all()
    open_ports = Port.query.filter_by(device_id=device.id).filter(
        Port.last_seen_closed_at.is_(None)
    ).order_by(Port.port).all()
    closed_ports = Port.query.filter_by(device_id=device.id).filter(
        Port.last_seen_closed_at.isnot(None)
    ).order_by(Port.last_seen_closed_at.desc()).limit(20).all()

    vulns = Vulnerability.query.filter_by(device_id=device.id).filter(
        Vulnerability.resolved_at.is_(None)
    ).order_by(Vulnerability.is_vulnerable.desc(), Vulnerability.last_seen_at.desc()).all()

    threshold_min = current_app.config.get("HOST_ONLINE_THRESHOLD_MINUTES", 70)
    uptime_7d = device.uptime_estimate(days=7, online_threshold_minutes=threshold_min)
    uptime_30d = device.uptime_estimate(days=30, online_threshold_minutes=threshold_min)

    return render_template(
        "devices/detail.html",
        device=device,
        ips=ips,
        open_ports=open_ports,
        closed_ports=closed_ports,
        vulns=vulns,
        device_types=DeviceType,
        uptime_7d=uptime_7d,
        uptime_30d=uptime_30d,
    )


@devices_bp.route("/<int:device_id>/ports/<int:port_id>/toggle-authorized", methods=["POST"])
@login_required
@require_role(ROLE_OPERATOR)
def port_toggle_authorized(device_id, port_id):
    """Alterna o baseline (is_authorized) de uma porta do device.

    Portas autorizadas são consideradas esperadas: não geram alerta ao
    reaparecer nem em mudanças de estado — somente desvios do baseline alertam.
    """
    device = db.session.get(Device, device_id) or abort(404)
    port = db.session.get(Port, port_id)
    if not port or port.device_id != device.id:
        abort(404)

    port.is_authorized = not port.is_authorized
    action = "port.authorize" if port.is_authorized else "port.unauthorize"
    audit(
        action,
        entity_type="Port",
        entity_id=port.id,
        details=(
            f"{device.display_name}: {port.protocol}/{port.port} "
            f"({'autorizada' if port.is_authorized else 'não autorizada'})"
        ),
    )
    db.session.commit()
    flash(
        f"Porta {port.protocol}/{port.port} marcada como "
        f"{'autorizada (baseline)' if port.is_authorized else 'não autorizada'}.",
        "success",
    )
    return redirect(url_for("devices.device_detail", device_id=device.id))


@devices_bp.route("/<int:device_id>/ports/history")
@login_required
def port_history(device_id):
    """Timeline de eventos de porta: aberturas, fechamentos e mudanças de estado."""
    from app.models import Alert, AlertType

    device = db.session.get(Device, device_id) or abort(404)

    # Todos os registros de porta (abertas + fechadas), mais recentes primeiro
    all_ports = Port.query.filter_by(device_id=device.id).order_by(
        Port.last_seen_open_at.desc()
    ).all()

    # Monta lista de eventos derivada dos registros de porta
    events = []
    for p in all_ports:
        label = f"{p.protocol}/{p.port}"
        svc = f" ({p.service_name})" if p.service_name else ""
        ver = f" {p.service_version}" if p.service_version else ""

        if p.first_open_at:
            events.append({
                "at": p.first_open_at,
                "kind": "opened",
                "label": label,
                "detail": f"Porta aberta{svc}{ver} — estado: {p.state or 'open'}",
                "port": p.port,
                "protocol": p.protocol,
            })

        if p.last_seen_closed_at:
            events.append({
                "at": p.last_seen_closed_at,
                "kind": "closed",
                "label": label,
                "detail": f"Porta fechada{svc}",
                "port": p.port,
                "protocol": p.protocol,
            })

    # Alertas NEW_PORT do device capturam mudanças de estado
    port_alerts = (
        Alert.query
        .filter_by(device_id=device.id, alert_type=AlertType.NEW_PORT)
        .order_by(Alert.created_at.desc())
        .limit(200)
        .all()
    )
    for a in port_alerts:
        # Só adicionar alertas de mudança de estado (mensagem contém "→")
        if "→" in a.message:
            events.append({
                "at": a.created_at,
                "kind": "state_change",
                "label": a.message,
                "detail": a.message,
                "port": None,
                "protocol": None,
            })

    # Ordena por data decrescente
    events.sort(key=lambda e: e["at"] or _utcnow(), reverse=True)

    return render_template(
        "devices/port_history.html",
        device=device,
        events=events,
        all_ports=all_ports,
    )


@devices_bp.route("/<int:device_id>/edit", methods=["POST"])
@login_required
@require_role(ROLE_OPERATOR)
def device_edit(device_id):
    """Edita campos do dispositivo (friendly name, tipo, notas)."""
    device = db.session.get(Device, device_id) or abort(404)

    device.friendly_name = request.form.get("friendly_name", "").strip() or None
    device.hostname = request.form.get("hostname", "").strip()
    device.vendor = request.form.get("vendor", "").strip()
    device.os_guess = request.form.get("os_guess", "").strip()
    device.notes = request.form.get("notes", "").strip()
    device.situation = request.form.get("situation", "NI").strip() or "NI"
    device.alert_on_down = request.form.get("alert_on_down") == "on"
    # Normaliza tags: remove espaços, minúsculas, separa por vírgula
    raw_tags = request.form.get("tags", "").strip()
    device.tags = ",".join(t.strip().lower() for t in raw_tags.split(",") if t.strip())

    # MAC editável (valida formato e unicidade)
    new_mac = request.form.get("mac", "").strip()
    if new_mac:
        from app.scanner.hosts import normalize_mac, is_valid_mac
        new_mac = normalize_mac(new_mac)
        if is_valid_mac(new_mac) and new_mac != device.mac:
            existing = Device.query.filter_by(profile_id=device.profile_id, mac=new_mac).first()
            if existing:
                flash(f"MAC {new_mac} já está em uso por outro dispositivo.", "danger")
            else:
                device.mac = new_mac

    dtype = request.form.get("device_type", "")
    if dtype:
        try:
            device.device_type = DeviceType(dtype)
        except ValueError:
            pass

    audit("device.update", "device", device.id, details=device.display_name)
    db.session.commit()
    flash("Dispositivo atualizado.", "success")
    return redirect(url_for("devices.device_detail", device_id=device.id))


@devices_bp.route("/<int:device_id>/scan", methods=["POST"])
@login_required
@require_role(ROLE_OPERATOR)
def device_scan(device_id):
    """Inicia um scan manual sob demanda em um dispositivo.

    Aceita JSON com campo scan_types (lista de strings).
    Tipos disponíveis: ping, ports, os_detect, vuln, snmp.
    """
    from app.scanner.scheduling import run_on_demand_scan

    data = request.get_json(silent=True) or {}
    scan_types = data.get("scan_types", ["ping", "ports"])

    # Valida tipos
    valid_types = {"ping", "ports", "os_detect", "vuln", "snmp", "mobile"}
    scan_types = [t for t in scan_types if t in valid_types]

    if not scan_types:
        return jsonify({"error": "Nenhum tipo de scan válido informado."}), 400

    # vuln scan é potencialmente destrutivo/intenso — exige admin
    from flask_login import current_user
    if "vuln" in scan_types and not current_user.has_role(ROLE_ADMIN):
        return jsonify({"error": "vuln scan exige role admin."}), 403

    # Autorização de alvo: só escaneia IPs dentro do escopo do perfil.
    # Evita usar o servidor como pivot de recon contra hosts arbitrários
    # (um operador poderia mudar DeviceIp.ip no DB direto — defesa em camadas).
    device = db.session.get(Device, device_id)
    if not device:
        return jsonify({"error": "Dispositivo não encontrado."}), 404

    current_dip = DeviceIp.query.filter_by(device_id=device.id, is_current=True).first()
    if current_dip and not _ip_in_profile_ranges(current_dip.ip, device.profile_id):
        return jsonify({
            "error": f"IP {current_dip.ip} fora dos ranges autorizados do perfil.",
        }), 403

    audit(
        "device.scan",
        "device",
        device_id,
        details=",".join(scan_types),
    )
    db.session.commit()

    results = run_on_demand_scan(device_id, scan_types)
    return jsonify(results)


@devices_bp.route("/<int:device_id>/delete", methods=["POST"])
@login_required
@require_role(ROLE_ADMIN)
def device_delete(device_id):
    """Exclui um dispositivo e todos os dados associados."""
    from app.models import Alert
    device = db.session.get(Device, device_id) or abort(404)
    name = device.display_name

    audit("device.delete", "device", device.id, details=name)

    # Limpa alertas (não têm cascade automático pois device_id é nullable)
    Alert.query.filter_by(device_id=device.id).delete()

    # Limpa scans com target_ip apontando para IPs do device.
    # Scans de perfil inteiro (target_ip IS NULL) são preservados.
    from app.models import Scan
    device_ips = [dip.ip for dip in device.ips.all()]
    if device_ips:
        Scan.query.filter(Scan.target_ip.in_(device_ips)).delete(synchronize_session=False)

    # O restante (DeviceIp, Port, Vulnerability) é deletado via cascade
    db.session.delete(device)
    db.session.commit()
    flash(f"Dispositivo '{name}' excluído.", "warning")
    return redirect(url_for("devices.device_list"))


@devices_bp.route("/add-by-ip", methods=["POST"])
@login_required
@require_role(ROLE_OPERATOR)
def device_add_by_ip():
    """Adiciona um dispositivo manualmente a partir de um IP.

    Pinga o host, tenta resolver MAC/hostname, cria Device + DeviceIp.
    """
    from app.scanner.hosts import (
        is_host_reachable, resolve_hostname, normalize_mac,
        is_valid_mac, get_vendor_from_mac,
        _read_mac_from_arp_table, _generate_placeholder_mac,
    )

    ip = request.form.get("ip", "").strip()
    profile_id = request.form.get("profile_id", type=int)

    if not ip:
        flash("Informe um endereço IP.", "danger")
        return redirect(url_for("devices.device_list"))

    if not profile_id:
        # Usa o primeiro perfil ativo como padrão
        profile = Profile.query.filter_by(is_active=True).first()
        if not profile:
            flash("Nenhum perfil ativo encontrado.", "danger")
            return redirect(url_for("devices.device_list"))
        profile_id = profile.id
    else:
        profile = db.session.get(Profile, profile_id)
        if not profile:
            flash("Perfil não encontrado.", "danger")
            return redirect(url_for("devices.device_list"))

    # Autorização de alvo: o IP precisa cair em algum IpRange do perfil.
    if not _ip_in_profile_ranges(ip, profile_id):
        flash(
            f"IP {ip} está fora dos ranges autorizados do perfil '{profile.name}'.",
            "danger",
        )
        return redirect(url_for("devices.device_list"))

    # Verifica se já existe dispositivo com este IP neste perfil
    existing_dip = DeviceIp.query.join(Device).filter(
        Device.profile_id == profile_id,
        DeviceIp.ip == ip,
        DeviceIp.is_current == True,
    ).first()
    if existing_dip:
        flash(f"Já existe um dispositivo com o IP {ip} neste perfil.", "warning")
        return redirect(url_for("devices.device_detail", device_id=existing_dip.device_id))

    # Verifica se o host está ativo (ICMP → ARP → TCP) e popula tabela ARP
    is_up, _method = is_host_reachable(ip)

    # Tenta resolver MAC via tabela ARP
    mac = _read_mac_from_arp_table(ip)
    if not is_valid_mac(mac):
        mac = _generate_placeholder_mac(ip)

    # Verifica se já existe dispositivo com este MAC neste perfil
    existing_device = Device.query.filter_by(profile_id=profile_id, mac=mac).first()
    if existing_device:
        # Atualiza IP do dispositivo existente
        dip = DeviceIp.query.filter_by(device_id=existing_device.id, ip=ip).first()
        now = _utcnow()
        if not dip:
            DeviceIp.query.filter_by(device_id=existing_device.id, is_current=True).update(
                {"is_current": False}
            )
            dip = DeviceIp(device_id=existing_device.id, ip=ip, is_current=True)
            db.session.add(dip)
        else:
            dip.is_current = True
            dip.last_seen_at = now
        existing_device.last_seen_at = now
        db.session.commit()
        status = "online" if is_up else "offline (sem resposta ao ping)"
        flash(f"Dispositivo já existente atualizado com IP {ip} — {status}.", "info")
        return redirect(url_for("devices.device_detail", device_id=existing_device.id))

    # Resolve hostname
    hostname = resolve_hostname(ip)
    vendor = get_vendor_from_mac(mac)

    now = _utcnow()
    device = Device(
        profile_id=profile_id,
        mac=mac,
        hostname=hostname,
        vendor=vendor,
        first_seen_at=now,
        last_seen_at=now,
    )
    db.session.add(device)
    db.session.flush()

    dip = DeviceIp(device_id=device.id, ip=ip, is_current=True)
    db.session.add(dip)
    audit("device.create", "device", device.id, details=f"{ip} ({mac})")
    db.session.commit()

    status = "online" if is_up else "offline (sem resposta ao ping)"
    flash(f"Dispositivo adicionado com IP {ip} — {status}.", "success")
    return redirect(url_for("devices.device_detail", device_id=device.id))


def abort(code):
    from flask import abort as flask_abort
    flask_abort(code)
