"""Helpers de autorização (RBAC) e registro de auditoria."""

from functools import wraps

from flask import abort, flash, redirect, request, url_for
from flask_login import current_user

from app.extensions import db
from app.models import AuditLog, ROLE_ADMIN, ROLE_OPERATOR, ROLE_VIEWER


def require_role(min_role: str):
    """Decorator que exige que o usuário autenticado tenha `min_role` ou superior.

    Hierarquia: viewer < operator < admin.

    Exemplo:
        @require_role(ROLE_ADMIN)
        def some_view(): ...
    """

    def decorator(view_func):
        @wraps(view_func)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for("auth.login", next=request.path))
            if not current_user.has_role(min_role):
                flash(
                    f"Acesso negado. Esta ação exige nível '{min_role}' ou superior.",
                    "danger",
                )
                abort(403)
            return view_func(*args, **kwargs)

        return wrapper

    return decorator


def audit(
    action: str,
    entity_type: str = "",
    entity_id: int | None = None,
    details: str = "",
    username: str | None = None,
    user_id: int | None = None,
):
    """Registra uma ação no AuditLog.

    Não faz commit — o chamador decide quando persistir, para manter a ação
    e o log atômicos na mesma transação. Se o chamador preferir commit
    separado, usar `audit(...); db.session.commit()`.

    Args:
        action: identificador da ação (ex.: "login.success", "device.delete").
        entity_type: tipo de entidade afetada (ex.: "device", "profile").
        entity_id: id da entidade afetada.
        details: texto livre com contexto extra.
        username: usado em ações sem usuário autenticado (ex.: login falho).
        user_id: idem.
    """
    # current_user pode não estar disponível fora de um request context
    # (ex.: jobs do scheduler, comandos CLI). Tenta ler e trata ausência.
    try:
        is_auth = bool(current_user and current_user.is_authenticated)
    except (RuntimeError, AttributeError):
        is_auth = False

    if username is None:
        username = current_user.username if is_auth else ""
    if user_id is None and is_auth:
        user_id = current_user.id

    try:
        ip = request.remote_addr or ""
    except RuntimeError:
        # Fora de contexto de request (ex.: CLI / scheduler).
        ip = ""

    log = AuditLog(
        user_id=user_id,
        username=username or "",
        action=action,
        entity_type=entity_type or "",
        entity_id=entity_id,
        details=details or "",
        ip_address=ip,
    )
    db.session.add(log)
    return log


__all__ = [
    "require_role",
    "audit",
    "ROLE_ADMIN",
    "ROLE_OPERATOR",
    "ROLE_VIEWER",
]
