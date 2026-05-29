"""Blueprint de administração — CRUD de perfis, faixas de IP e usuários."""

import ipaddress

from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user

from app.auth_utils import audit, require_role
from app.extensions import db
from app.models import Profile, IpRange, User, AppSetting, ROLE_ADMIN


def _validate_cidr(cidr: str) -> tuple[str, str | None]:
    """Valida e normaliza uma string CIDR.

    Returns:
        (normalized_cidr, None) em caso de sucesso.
        ("", mensagem_de_erro) em caso de falha.
    """
    cidr = (cidr or "").strip()
    if not cidr:
        return "", "CIDR é obrigatório."
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        return "", f"CIDR inválido: {exc}"
    # Limite defensivo — redes maiores que /16 geram scans enormes.
    if network.num_addresses > 65536:
        return "", (
            f"Rede muito grande ({network.num_addresses} hosts). "
            "Use prefixo /16 ou mais específico."
        )
    return str(network), None

admin_bp = Blueprint("admin", __name__, template_folder="../templates/admin")


def _clean_min_severity(value: str | None) -> str:
    """Normaliza a severidade mínima de notificação (default CRITICAL)."""
    value = (value or "").strip().upper()
    return value if value in ("INFO", "WARNING", "CRITICAL") else "CRITICAL"


# ---------------------------------------------------------------------------
# Profiles
# ---------------------------------------------------------------------------

@admin_bp.route("/profiles")
@login_required
@require_role(ROLE_ADMIN)
def profiles():
    """Lista de perfis de rede."""
    all_profiles = Profile.query.order_by(Profile.name).all()
    return render_template("admin/profiles.html", profiles=all_profiles)


@admin_bp.route("/profiles/new", methods=["GET", "POST"])
@login_required
@require_role(ROLE_ADMIN)
def profile_new():
    """Cria novo perfil."""
    if request.method == "POST":
        profile = Profile(
            name=request.form["name"],
            description=request.form.get("description", ""),
            host_discovery_interval_minutes=int(request.form.get("host_discovery_interval", 45)),
            port_scan_interval_minutes=int(request.form.get("port_scan_interval", 4)),
            max_concurrent_scans=int(request.form.get("max_concurrent_scans", 3)),
            snmp_enabled="snmp_enabled" in request.form,
            snmp_community=request.form.get("snmp_community", "public"),
            webhook_url=request.form.get("webhook_url", "").strip(),
            notify_email=request.form.get("notify_email", "").strip(),
            notify_min_severity=_clean_min_severity(request.form.get("notify_min_severity")),
            default_ports=request.form.get("default_ports", "").strip(),
        )
        db.session.add(profile)
        db.session.flush()
        audit("profile.create", "profile", profile.id, details=profile.name)
        db.session.commit()
        from flask import current_app
        from app.scanner.scheduling import sync_profile_jobs
        sync_profile_jobs(current_app._get_current_object(), profile)
        flash(f"Perfil '{profile.name}' criado.", "success")
        return redirect(url_for("admin.profiles"))

    return render_template("admin/profile_form.html", profile=None)


@admin_bp.route("/profiles/<int:profile_id>/edit", methods=["GET", "POST"])
@login_required
@require_role(ROLE_ADMIN)
def profile_edit(profile_id):
    """Edita um perfil existente."""
    profile = db.session.get(Profile, profile_id) or _abort(404)

    if request.method == "POST":
        profile.name = request.form["name"]
        profile.description = request.form.get("description", "")
        profile.host_discovery_interval_minutes = int(request.form.get("host_discovery_interval", 45))
        profile.port_scan_interval_minutes = int(request.form.get("port_scan_interval", 4))
        profile.max_concurrent_scans = int(request.form.get("max_concurrent_scans", 3))
        profile.snmp_enabled = "snmp_enabled" in request.form
        profile.snmp_community = request.form.get("snmp_community", "public")
        profile.is_active = "is_active" in request.form
        profile.webhook_url = request.form.get("webhook_url", "").strip()
        profile.notify_email = request.form.get("notify_email", "").strip()
        profile.notify_min_severity = _clean_min_severity(request.form.get("notify_min_severity"))
        profile.default_ports = request.form.get("default_ports", "").strip()
        audit("profile.update", "profile", profile.id, details=profile.name)
        db.session.commit()
        from flask import current_app
        from app.scanner.scheduling import sync_profile_jobs
        sync_profile_jobs(current_app._get_current_object(), profile)
        flash(f"Perfil '{profile.name}' atualizado.", "success")
        return redirect(url_for("admin.profiles"))

    return render_template("admin/profile_form.html", profile=profile)


@admin_bp.route("/profiles/<int:profile_id>/delete", methods=["POST"])
@login_required
@require_role(ROLE_ADMIN)
def profile_delete(profile_id):
    """Remove um perfil e todos os dados associados."""
    profile = db.session.get(Profile, profile_id) or _abort(404)
    name = profile.name
    pid = profile.id
    audit("profile.delete", "profile", profile.id, details=name)
    db.session.delete(profile)
    db.session.commit()
    from app.scanner.scheduling import remove_profile_jobs
    remove_profile_jobs(pid)
    flash(f"Perfil '{name}' removido.", "warning")
    return redirect(url_for("admin.profiles"))


# ---------------------------------------------------------------------------
# IP Ranges
# ---------------------------------------------------------------------------

@admin_bp.route("/profiles/<int:profile_id>/ranges")
@login_required
@require_role(ROLE_ADMIN)
def ranges(profile_id):
    """Lista faixas de IP de um perfil."""
    profile = db.session.get(Profile, profile_id) or _abort(404)
    ip_ranges = IpRange.query.filter_by(profile_id=profile.id).order_by(IpRange.cidr).all()
    return render_template("admin/ranges.html", profile=profile, ip_ranges=ip_ranges)


@admin_bp.route("/profiles/<int:profile_id>/ranges/new", methods=["POST"])
@login_required
@require_role(ROLE_ADMIN)
def range_new(profile_id):
    """Adiciona nova faixa de IP."""
    profile = db.session.get(Profile, profile_id) or _abort(404)
    description = request.form.get("description", "").strip()

    cidr, err = _validate_cidr(request.form.get("cidr", ""))
    if err:
        flash(err, "danger")
        return redirect(url_for("admin.ranges", profile_id=profile.id))

    port_mode = request.form.get("port_mode", "default")
    custom_ports = request.form.get("custom_ports", "").strip()

    ip_range = IpRange(
        profile_id=profile.id,
        cidr=cidr,
        description=description,
        enabled="enabled" in request.form or not request.form.get("enabled_field"),
        scan_all_ports=(port_mode == "all"),
        custom_ports=custom_ports if port_mode == "custom" else "",
    )
    db.session.add(ip_range)
    db.session.flush()
    audit("range.create", "ip_range", ip_range.id, details=f"{profile.name}: {cidr}")
    db.session.commit()
    flash(f"Faixa {cidr} adicionada.", "success")
    return redirect(url_for("admin.ranges", profile_id=profile.id))


@admin_bp.route("/ranges/<int:range_id>/toggle", methods=["POST"])
@login_required
@require_role(ROLE_ADMIN)
def range_toggle(range_id):
    """Habilita/desabilita uma faixa de IP."""
    ip_range = db.session.get(IpRange, range_id) or _abort(404)
    ip_range.enabled = not ip_range.enabled
    audit(
        "range.toggle",
        "ip_range",
        ip_range.id,
        details=f"{ip_range.cidr} -> {'enabled' if ip_range.enabled else 'disabled'}",
    )
    db.session.commit()
    status = "habilitada" if ip_range.enabled else "desabilitada"
    flash(f"Faixa {ip_range.cidr} {status}.", "info")
    return redirect(url_for("admin.ranges", profile_id=ip_range.profile_id))


@admin_bp.route("/ranges/<int:range_id>/edit", methods=["GET", "POST"])
@login_required
@require_role(ROLE_ADMIN)
def range_edit(range_id):
    """Edita uma faixa de IP existente."""
    ip_range = db.session.get(IpRange, range_id) or _abort(404)

    if request.method == "POST":
        cidr, err = _validate_cidr(request.form.get("cidr", ip_range.cidr))
        if err:
            flash(err, "danger")
            profile = db.session.get(Profile, ip_range.profile_id)
            return render_template("admin/range_edit.html", profile=profile, ip_range=ip_range)
        ip_range.cidr = cidr
        ip_range.description = request.form.get("description", "").strip()
        ip_range.enabled = "enabled" in request.form

        port_mode = request.form.get("port_mode", "default")
        ip_range.scan_all_ports = (port_mode == "all")
        ip_range.custom_ports = (
            request.form.get("custom_ports", "").strip()
            if port_mode == "custom" else ""
        )

        audit("range.update", "ip_range", ip_range.id, details=ip_range.cidr)
        db.session.commit()
        flash(f"Faixa {ip_range.cidr} atualizada.", "success")
        return redirect(url_for("admin.ranges", profile_id=ip_range.profile_id))

    profile = db.session.get(Profile, ip_range.profile_id)
    return render_template("admin/range_edit.html", profile=profile, ip_range=ip_range)


@admin_bp.route("/ranges/<int:range_id>/delete", methods=["POST"])
@login_required
@require_role(ROLE_ADMIN)
def range_delete(range_id):
    """Remove uma faixa de IP."""
    ip_range = db.session.get(IpRange, range_id) or _abort(404)
    profile_id = ip_range.profile_id
    cidr = ip_range.cidr
    audit("range.delete", "ip_range", ip_range.id, details=cidr)
    db.session.delete(ip_range)
    db.session.commit()
    flash("Faixa removida.", "warning")
    return redirect(url_for("admin.ranges", profile_id=profile_id))


# ---------------------------------------------------------------------------
# Audit log (visualização)
# ---------------------------------------------------------------------------

@admin_bp.route("/audit")
@login_required
@require_role(ROLE_ADMIN)
def audit_log():
    """Lista paginada do audit log. Somente admin."""
    from app.models import AuditLog
    from flask import current_app

    page = max(int(request.args.get("page", 1)), 1)
    per_page = int(current_app.config.get("ITEMS_PER_PAGE", 25))
    action_filter = request.args.get("action", "").strip()
    user_filter = request.args.get("username", "").strip()

    q = AuditLog.query
    if action_filter:
        q = q.filter(AuditLog.action.like(f"%{action_filter}%"))
    if user_filter:
        q = q.filter(AuditLog.username.like(f"%{user_filter}%"))

    pagination = q.order_by(AuditLog.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    return render_template(
        "admin/audit_log.html",
        pagination=pagination,
        entries=pagination.items,
        action_filter=action_filter,
        user_filter=user_filter,
    )


# ---------------------------------------------------------------------------
# Dispositivos fantasma (fora de qualquer IpRange habilitado)
# ---------------------------------------------------------------------------

@admin_bp.route("/rogue-devices")
@login_required
@require_role(ROLE_ADMIN)
def rogue_devices():
    """Lista devices cujo IP atual não pertence a nenhum IpRange habilitado do perfil.

    Esses dispositivos foram descobertos mas estão fora do escopo configurado —
    podem ser dispositivos adicionados manualmente, ranges removidos posteriormente,
    ou hosts que obtiveram DHCP fora da faixa monitorada.
    """
    from app.models import Device, DeviceIp, IpRange
    import ipaddress as _ip

    profile_id = request.args.get("profile_id", type=int)

    # Carrega todos os profiles com seus ranges
    profiles_q = Profile.query.filter_by(is_active=True).order_by(Profile.name)
    if profile_id:
        profiles_q = profiles_q.filter_by(id=profile_id)
    profiles = profiles_q.all()

    # Pré-compila as redes por perfil
    ranges_by_profile: dict[int, list] = {}
    for p in profiles:
        nets = []
        for r in IpRange.query.filter_by(profile_id=p.id, enabled=True).all():
            try:
                nets.append(_ip.ip_network(r.cidr, strict=False))
            except ValueError:
                pass
        ranges_by_profile[p.id] = nets

    rogue = []
    for p in profiles:
        nets = ranges_by_profile[p.id]
        devices = (
            db.session.query(Device, DeviceIp)
            .join(DeviceIp, (DeviceIp.device_id == Device.id) & DeviceIp.is_current.is_(True))
            .filter(Device.profile_id == p.id)
            .all()
        )
        for device, dip in devices:
            try:
                addr = _ip.ip_address(dip.ip)
            except ValueError:
                continue
            in_range = any(addr in net for net in nets)
            if not in_range:
                rogue.append({
                    "device": device,
                    "ip": dip.ip,
                    "profile": p,
                })

    profiles_all = Profile.query.filter_by(is_active=True).order_by(Profile.name).all()
    return render_template(
        "admin/rogue_devices.html",
        rogue=rogue,
        profiles=profiles_all,
        selected_profile_id=profile_id,
    )


# ---------------------------------------------------------------------------
# Gerenciamento de usuários
# ---------------------------------------------------------------------------

@admin_bp.route("/users")
@login_required
@require_role(ROLE_ADMIN)
def user_list():
    """Lista todos os usuários do sistema."""
    users = User.query.order_by(User.username).all()
    return render_template("admin/users.html", users=users)


@admin_bp.route("/users/new", methods=["GET", "POST"])
@login_required
@require_role(ROLE_ADMIN)
def user_new():
    """Cria novo usuário."""
    roles = ["viewer", "operator", "admin"]
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "viewer")

        if not username:
            flash("Nome de usuário é obrigatório.", "danger")
            return render_template("admin/user_form.html", user=None, roles=roles)

        if role not in roles:
            role = "viewer"

        err = User.validate_password(password)
        if err:
            flash(err, "danger")
            return render_template("admin/user_form.html", user=None, roles=roles)

        if User.query.filter_by(username=username).first():
            flash(f"Usuário '{username}' já existe.", "danger")
            return render_template("admin/user_form.html", user=None, roles=roles)

        user = User(username=username, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.flush()
        audit("user.create", "user", user.id, details=f"{username} role={role}")
        db.session.commit()
        flash(f"Usuário '{username}' criado com role '{role}'.", "success")
        return redirect(url_for("admin.user_list"))

    return render_template("admin/user_form.html", user=None, roles=roles)


@admin_bp.route("/users/<int:user_id>/edit", methods=["GET", "POST"])
@login_required
@require_role(ROLE_ADMIN)
def user_edit(user_id):
    """Edita username e role de um usuário."""
    user = db.session.get(User, user_id) or _abort(404)
    roles = ["viewer", "operator", "admin"]

    if request.method == "POST":
        new_username = request.form.get("username", "").strip()
        new_role = request.form.get("role", user.role)

        if not new_username:
            flash("Nome de usuário é obrigatório.", "danger")
            return render_template("admin/user_form.html", user=user, roles=roles)

        if new_role not in roles:
            new_role = user.role

        # Verifica conflito de username (exceto o próprio usuário)
        conflict = User.query.filter(User.username == new_username, User.id != user.id).first()
        if conflict:
            flash(f"Nome '{new_username}' já está em uso.", "danger")
            return render_template("admin/user_form.html", user=user, roles=roles)

        old_info = f"{user.username} role={user.role}"
        user.username = new_username
        user.role = new_role
        audit("user.update", "user", user.id, details=f"{old_info} → {new_username} role={new_role}")
        db.session.commit()
        flash(f"Usuário '{new_username}' atualizado.", "success")
        return redirect(url_for("admin.user_list"))

    return render_template("admin/user_form.html", user=user, roles=roles)


@admin_bp.route("/users/<int:user_id>/set-password", methods=["GET", "POST"])
@login_required
@require_role(ROLE_ADMIN)
def user_set_password(user_id):
    """Define nova senha para um usuário."""
    user = db.session.get(User, user_id) or _abort(404)

    if request.method == "POST":
        new_password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if new_password != confirm:
            flash("As senhas não coincidem.", "danger")
            return render_template("admin/user_password.html", user=user)

        err = User.validate_password(new_password)
        if err:
            flash(err, "danger")
            return render_template("admin/user_password.html", user=user)

        user.set_password(new_password)
        audit("user.set_password", "user", user.id, details=user.username)
        db.session.commit()
        flash(f"Senha de '{user.username}' alterada.", "success")
        return redirect(url_for("admin.user_list"))

    return render_template("admin/user_password.html", user=user)


@admin_bp.route("/users/<int:user_id>/toggle-active", methods=["POST"])
@login_required
@require_role(ROLE_ADMIN)
def user_toggle_active(user_id):
    """Bloqueia ou desbloqueia uma conta de usuário."""
    user = db.session.get(User, user_id) or _abort(404)

    # Impede o admin de bloquear a própria conta
    if user.id == current_user.id:
        flash("Você não pode bloquear sua própria conta.", "danger")
        return redirect(url_for("admin.user_list"))

    user.is_active = not user.is_active
    action = "user.unblock" if user.is_active else "user.block"
    audit(action, "user", user.id, details=user.username)
    db.session.commit()
    status = "desbloqueada" if user.is_active else "bloqueada"
    flash(f"Conta '{user.username}' {status}.", "info")
    return redirect(url_for("admin.user_list"))


@admin_bp.route("/users/<int:user_id>/delete", methods=["POST"])
@login_required
@require_role(ROLE_ADMIN)
def user_delete(user_id):
    """Remove um usuário do sistema."""
    user = db.session.get(User, user_id) or _abort(404)

    if user.id == current_user.id:
        flash("Você não pode excluir sua própria conta.", "danger")
        return redirect(url_for("admin.user_list"))

    username = user.username
    audit("user.delete", "user", user.id, details=username)
    db.session.delete(user)
    db.session.commit()
    flash(f"Usuário '{username}' excluído.", "warning")
    return redirect(url_for("admin.user_list"))


# ---------------------------------------------------------------------------
# Configurações de scan (AppSetting)
# ---------------------------------------------------------------------------

QUICK_CHECK_KEY = "host_down_quick_check_interval"


@admin_bp.route("/scan-settings", methods=["GET", "POST"])
@login_required
@require_role(ROLE_ADMIN)
def scan_settings():
    """Painel de ajustes globais de scan editáveis em runtime.

    Hoje expõe somente o intervalo do quick check de HOST_DOWN; novas chaves
    podem ser adicionadas aqui sem migration.
    """
    from flask import current_app

    default_quick = int(current_app.config.get("HOST_DOWN_QUICK_CHECK_INTERVAL_MINUTES", 5))

    if request.method == "POST":
        try:
            new_interval = int(request.form.get("quick_check_interval", default_quick))
        except ValueError:
            flash("Intervalo inválido.", "danger")
            return redirect(url_for("admin.scan_settings"))

        if new_interval < 1 or new_interval > 60:
            flash("Intervalo deve estar entre 1 e 60 minutos.", "danger")
            return redirect(url_for("admin.scan_settings"))

        AppSetting.set_value(QUICK_CHECK_KEY, new_interval)
        audit("scan_settings.update", "app_setting", None,
              details=f"{QUICK_CHECK_KEY}={new_interval}")
        db.session.commit()

        # Reagenda os jobs de host-down nos perfis ativos
        from app.scanner.scheduling import sync_quick_host_down_jobs
        sync_quick_host_down_jobs(current_app._get_current_object())

        flash(f"Intervalo do quick check atualizado para {new_interval} min.", "success")
        return redirect(url_for("admin.scan_settings"))

    quick_check_interval = AppSetting.get_int(QUICK_CHECK_KEY, default_quick)
    return render_template(
        "admin/scan_settings.html",
        quick_check_interval=quick_check_interval,
        default_quick=default_quick,
    )


def _abort(code):
    from flask import abort
    abort(code)
