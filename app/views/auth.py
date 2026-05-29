"""Blueprint de autenticação (login/logout)."""

from datetime import timedelta

from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app
from flask_login import login_user, logout_user, login_required, current_user

from app.auth_utils import audit
from app.extensions import db, limiter
from app.models import User, AuditLog, _utcnow

auth_bp = Blueprint("auth", __name__, template_folder="../templates/auth")


def _failed_attempts_since_success(username: str, window_minutes: int) -> int:
    """Conta logins falhos de ``username`` na janela, desde o último sucesso.

    Um login bem-sucedido zera efetivamente o contador (a contagem só considera
    falhas posteriores ao último ``login.success``). Baseado no AuditLog, então
    sobrevive a reinícios e funciona com múltiplos workers.
    """
    window_start = _utcnow() - timedelta(minutes=window_minutes)

    last_success = (
        AuditLog.query
        .filter(AuditLog.action == "login.success", AuditLog.username == username)
        .order_by(AuditLog.created_at.desc())
        .first()
    )
    effective_start = window_start
    if last_success and last_success.created_at and last_success.created_at > window_start:
        effective_start = last_success.created_at

    return (
        AuditLog.query
        .filter(
            AuditLog.action == "login.fail",
            AuditLog.username == username,
            AuditLog.created_at >= effective_start,
        )
        .count()
    )


def _is_locked_out(username: str) -> bool:
    """True se a conta excedeu o limite de falhas na janela de bloqueio."""
    max_attempts = int(current_app.config.get("LOGIN_MAX_FAILED_ATTEMPTS", 5))
    window = int(current_app.config.get("LOGIN_LOCKOUT_MINUTES", 15))
    if max_attempts <= 0 or not username:
        return False
    return _failed_attempts_since_success(username, window) >= max_attempts


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute; 50 per hour", methods=["POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # Bloqueio por tentativas falhas (antes de verificar a senha).
        if _is_locked_out(username):
            window = int(current_app.config.get("LOGIN_LOCKOUT_MINUTES", 15))
            audit(
                "login.locked",
                entity_type="user",
                details=f"Conta bloqueada por excesso de tentativas (janela {window}min)",
                username=username or "(vazio)",
            )
            db.session.commit()
            flash(
                f"Muitas tentativas falhas. Tente novamente em até {window} minutos.",
                "danger",
            )
            return render_template("auth/login.html"), 429

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            if not user.is_active:
                audit(
                    "login.blocked",
                    entity_type="user",
                    entity_id=user.id,
                    details="Conta desativada",
                    username=user.username,
                    user_id=user.id,
                )
                db.session.commit()
                flash("Esta conta está desativada. Contate o administrador.", "danger")
                return render_template("auth/login.html"), 403
            login_user(user, remember=True)
            audit(
                "login.success",
                entity_type="user",
                entity_id=user.id,
                username=user.username,
                user_id=user.id,
            )
            db.session.commit()
            next_page = request.args.get("next")
            flash("Login realizado com sucesso.", "success")
            return redirect(next_page or url_for("main.dashboard"))

        audit(
            "login.fail",
            entity_type="user",
            details=f"Tentativa de login falhou",
            username=username or "(vazio)",
        )
        db.session.commit()
        flash("Usuário ou senha inválidos.", "danger")

    return render_template("auth/login.html")


@auth_bp.route("/logout")
@login_required
def logout():
    uid = current_user.id
    uname = current_user.username
    logout_user()
    audit("logout", entity_type="user", entity_id=uid, username=uname, user_id=uid)
    db.session.commit()
    flash("Logout realizado.", "info")
    return redirect(url_for("auth.login"))
