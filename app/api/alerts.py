"""Endpoints JSON para alertas."""

from flask import jsonify, request
from flask_login import login_required

from app.api import api_bp, to_iso
from app.auth_utils import audit, require_role
from app.extensions import db
from app.models import Alert, AlertType, Severity, ROLE_OPERATOR, _utcnow


@api_bp.route("/alerts")
@login_required
def api_alert_list():
    """Retorna lista de alertas em JSON.

    Query params: profile_id, type, severity, status (open/acknowledged), page, per_page.
    """
    profile_id = request.args.get("profile_id", type=int)
    alert_type = request.args.get("type", "")
    severity = request.args.get("severity", "")
    status = request.args.get("status", "")
    page = request.args.get("page", 1, type=int)
    # Cap duro em 200 para evitar dump massivo via API pública autenticada.
    per_page = min(max(request.args.get("per_page", 50, type=int), 1), 200)

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

    query = query.order_by(Alert.created_at.desc())
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)

    alerts = []
    for a in pagination.items:
        alerts.append({
            "id": a.id,
            "profile_id": a.profile_id,
            "device_id": a.device_id,
            "alert_type": a.alert_type.value,
            "severity": a.severity.value,
            "message": a.message,
            "created_at": to_iso(a.created_at),
            "acknowledged_at": to_iso(a.acknowledged_at),
            "is_acknowledged": a.is_acknowledged,
        })

    return jsonify({
        "alerts": alerts,
        "total": pagination.total,
        "page": pagination.page,
        "pages": pagination.pages,
    })


@api_bp.route("/alerts/open-count")
@login_required
def api_open_alert_count():
    """Contagem de alertas abertos (não reconhecidos), p/ o badge do navbar.

    Query params: profile_id (opcional — sem ele, conta todos os perfis).
    Endpoint leve: uma única contagem, chamado em polling pelo front-end.
    """
    profile_id = request.args.get("profile_id", type=int)
    query = Alert.query.filter(Alert.acknowledged_at.is_(None))
    if profile_id:
        query = query.filter_by(profile_id=profile_id)
    return jsonify({"open_alerts": query.count()})


@api_bp.route("/alerts/<int:alert_id>/acknowledge", methods=["POST"])
@login_required
@require_role(ROLE_OPERATOR)
def api_acknowledge_alert(alert_id):
    """Marca um alerta como reconhecido via API.

    Espelha a RBAC e a auditoria da view alerts.acknowledge: exige operator+
    e registra a ação no AuditLog.
    """
    alert = db.session.get(Alert, alert_id)
    if not alert:
        return jsonify({"error": "Alerta não encontrado."}), 404
    if not alert.acknowledged_at:
        alert.acknowledged_at = _utcnow()
        audit("alert.acknowledge", "alert", alert.id)
        db.session.commit()
    return jsonify({"status": "ok", "alert_id": alert.id})
