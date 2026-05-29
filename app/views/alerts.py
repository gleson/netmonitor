"""Blueprint de alertas."""

from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required

from app.auth_utils import audit, require_role
from app.extensions import db
from app.models import (
    Alert, AlertType, Severity, Device, DeviceIp, Profile, ROLE_OPERATOR,
    _utcnow,
)

alerts_bp = Blueprint("alerts", __name__, template_folder="../templates/alerts")


@alerts_bp.route("/")
@login_required
def alert_list():
    """Lista paginada de alertas com filtros."""
    from app.profile_utils import get_active_profile_id
    profile_id = get_active_profile_id()
    alert_type = request.args.get("type", "")
    severity = request.args.get("severity", "")
    status = request.args.get("status", "")  # "open" ou "acknowledged"
    device_search = request.args.get("device", "").strip()
    page = request.args.get("page", 1, type=int)

    # Banner alert-danger no topo lista todos os HOST_DOWN prioritários abertos
    # (não respeita os filtros — esses casos precisam visibilidade incondicional).
    priority_q = Alert.query.filter(
        Alert.is_priority.is_(True),
        Alert.acknowledged_at.is_(None),
    )
    if profile_id:
        priority_q = priority_q.filter_by(profile_id=profile_id)
    priority_alerts = priority_q.order_by(Alert.created_at.desc()).all()

    query = Alert.query

    if profile_id:
        query = query.filter_by(profile_id=profile_id)
    if alert_type:
        try:
            query = query.filter_by(alert_type=AlertType(alert_type))
        except ValueError:
            pass
    if severity:
        try:
            query = query.filter_by(severity=Severity(severity))
        except ValueError:
            pass
    if status == "open":
        query = query.filter(Alert.acknowledged_at.is_(None))
    elif status == "acknowledged":
        query = query.filter(Alert.acknowledged_at.isnot(None))

    if device_search:
        like = f"%{device_search}%"
        # Subquery: device_ids cujo IP atual bate com a busca
        ip_sq = (
            db.select(DeviceIp.device_id)
            .where(DeviceIp.ip.ilike(like))
            .scalar_subquery()
        )
        query = (
            query.join(Device, Alert.device_id == Device.id)
            .filter(
                db.or_(
                    Device.friendly_name.ilike(like),
                    Device.hostname.ilike(like),
                    Device.mac.ilike(like),
                    Device.id.in_(ip_sq),
                )
            )
        )

    # Prioritários (HOST_DOWN confirmado) primeiro; depois mais recentes.
    query = query.order_by(Alert.is_priority.desc(), Alert.created_at.desc())
    pagination = query.paginate(page=page, per_page=25, error_out=False)

    return render_template(
        "alerts/list.html",
        alerts=pagination.items,
        pagination=pagination,
        selected_profile_id=profile_id,
        selected_type=alert_type,
        selected_severity=severity,
        selected_status=status,
        device_search=device_search,
        alert_types=AlertType,
        severities=Severity,
        priority_alerts=priority_alerts,
    )


@alerts_bp.route("/<int:alert_id>/acknowledge", methods=["POST"])
@login_required
@require_role(ROLE_OPERATOR)
def acknowledge(alert_id):
    """Marca um alerta como reconhecido."""
    alert = db.session.get(Alert, alert_id)
    if alert and not alert.acknowledged_at:
        alert.acknowledged_at = _utcnow()
        audit("alert.acknowledge", "alert", alert.id)
        db.session.commit()
        flash("Alerta reconhecido.", "success")
    return redirect(request.referrer or url_for("alerts.alert_list"))


@alerts_bp.route("/acknowledge-selected", methods=["POST"])
@login_required
@require_role(ROLE_OPERATOR)
def acknowledge_selected():
    """Reconhece apenas os alertas marcados pelo usuário."""
    from app.profile_utils import get_active_profile_id

    alert_ids = request.form.getlist("alert_ids", type=int)
    if not alert_ids:
        flash("Nenhum alerta selecionado.", "warning")
        return redirect(request.referrer or url_for("alerts.alert_list"))

    profile_id = get_active_profile_id()
    now = _utcnow()

    query = Alert.query.filter(
        Alert.id.in_(alert_ids),
        Alert.acknowledged_at.is_(None),
    )
    if profile_id:
        query = query.filter_by(profile_id=profile_id)

    updated = query.update({"acknowledged_at": now}, synchronize_session=False)
    audit(
        "alert.acknowledge_selected",
        "alert",
        None,
        details=f"{updated} alerta(s) ids={alert_ids}",
    )
    db.session.commit()
    flash(f"{updated} alerta(s) reconhecido(s).", "success")
    return redirect(request.referrer or url_for("alerts.alert_list"))


@alerts_bp.route("/acknowledge-all", methods=["POST"])
@login_required
@require_role(ROLE_OPERATOR)
def acknowledge_all():
    """Marca todos os alertas abertos de um perfil específico como reconhecidos.

    profile_id é obrigatório para evitar reconhecimento em massa acidental
    entre perfis distintos.
    """
    profile_id = request.form.get("profile_id", type=int)

    if not profile_id:
        flash(
            "Selecione um perfil antes de reconhecer todos os alertas.",
            "danger",
        )
        return redirect(request.referrer or url_for("alerts.alert_list"))

    profile = db.session.get(Profile, profile_id)
    if not profile:
        flash("Perfil não encontrado.", "danger")
        return redirect(request.referrer or url_for("alerts.alert_list"))

    now = _utcnow()
    updated = (
        Alert.query
        .filter(Alert.acknowledged_at.is_(None))
        .filter_by(profile_id=profile_id)
        .update({"acknowledged_at": now})
    )
    audit(
        "alert.acknowledge_all",
        "profile",
        profile_id,
        details=f"{updated} alerta(s)",
    )
    db.session.commit()
    flash(
        f"{updated} alerta(s) do perfil '{profile.name}' reconhecidos.",
        "success",
    )
    return redirect(request.referrer or url_for("alerts.alert_list"))
