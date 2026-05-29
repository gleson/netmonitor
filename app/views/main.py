"""Blueprint principal — Dashboard."""

from datetime import timedelta

from flask import Blueprint, render_template, request, redirect, url_for, current_app, session
from flask_login import login_required

from app.extensions import db
from app.models import Profile, Device, Alert, _utcnow
from app.profile_utils import get_active_profile_id

main_bp = Blueprint("main", __name__, template_folder="../templates/main")


@main_bp.route("/set-profile", methods=["POST"])
@login_required
def set_active_profile():
    """Troca o perfil ativo armazenado na sessão."""
    profile_id = request.form.get("profile_id", type=int)
    next_url = request.form.get("next") or url_for("main.dashboard")
    if profile_id:
        profile = db.session.get(Profile, profile_id)
        if profile and profile.is_active:
            session["active_profile_id"] = profile_id
    return redirect(next_url)


@main_bp.route("/")
@login_required
def dashboard():
    """Dashboard principal com visão geral por perfil."""
    profile_id = get_active_profile_id()

    selected_profile = None
    if profile_id:
        selected_profile = db.session.get(Profile, profile_id)
    if selected_profile is None:
        selected_profile = Profile.query.filter_by(is_active=True).order_by(Profile.name).first()
        if selected_profile:
            session["active_profile_id"] = selected_profile.id

    stats = {}
    if selected_profile:
        now = _utcnow()
        online_minutes = current_app.config.get("HOST_ONLINE_THRESHOLD_MINUTES", 70)
        threshold = now - timedelta(minutes=online_minutes)
        yesterday = now - timedelta(hours=24)

        total_devices = Device.query.filter_by(profile_id=selected_profile.id).count()
        online_devices = Device.query.filter_by(profile_id=selected_profile.id).filter(
            Device.last_seen_at >= threshold
        ).count()
        new_devices_24h = Device.query.filter_by(profile_id=selected_profile.id).filter(
            Device.first_seen_at >= yesterday
        ).count()
        open_alerts = Alert.query.filter_by(profile_id=selected_profile.id).filter(
            Alert.acknowledged_at.is_(None)
        ).count()

        stats = {
            "total_devices": total_devices,
            "online_devices": online_devices,
            "new_devices_24h": new_devices_24h,
            "open_alerts": open_alerts,
        }

    return render_template(
        "main/dashboard.html",
        selected_profile=selected_profile,
        stats=stats,
    )
