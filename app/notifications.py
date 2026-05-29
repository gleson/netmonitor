"""Dispatch de notificações externas para alertas CRITICAL.

Cada alerta pode ser enviado por:
- Webhook HTTP (POST JSON) — URL configurada em Profile.webhook_url.
- Email (SMTP) — endereço em Profile.notify_email + SMTP_* no app.config.

Falhas de envio são registradas em log mas não levantam exceção, para não
interromper o fluxo de scan/alerting. Execução é síncrona em thread separada
para não bloquear a transação que criou o alerta.
"""

from __future__ import annotations

import json
import logging
import smtplib
import threading
from email.message import EmailMessage
from urllib import request as urlrequest
from urllib.error import URLError

from flask import current_app

logger = logging.getLogger(__name__)


def _build_payload(alert, profile, device) -> dict:
    return {
        "alert_id": alert.id,
        "alert_type": alert.alert_type.value if alert.alert_type else "",
        "severity": alert.severity.value if alert.severity else "",
        "message": alert.message,
        "created_at": alert.created_at.isoformat() if alert.created_at else "",
        "profile": {"id": profile.id, "name": profile.name} if profile else None,
        "device": (
            {
                "id": device.id,
                "display_name": device.display_name,
                "mac": device.mac,
                "ip": device.current_ip,
            }
            if device
            else None
        ),
    }


def _send_webhook(url: str, payload: dict, timeout: int = 5) -> None:
    data = json.dumps(payload).encode("utf-8")
    req = urlrequest.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "NetMonitor-Flask"},
        method="POST",
    )
    try:
        with urlrequest.urlopen(req, timeout=timeout) as resp:
            if resp.status >= 400:
                logger.warning("Webhook %s respondeu %d", url, resp.status)
    except (URLError, TimeoutError, OSError) as e:
        logger.warning("Falha ao enviar webhook %s: %s", url, e)


def _send_email(config: dict, to_addr: str, subject: str, body: str) -> None:
    host = config.get("SMTP_HOST", "")
    if not host:
        logger.debug("SMTP_HOST vazio — email não enviado.")
        return

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = config.get("SMTP_FROM", "netmonitor@localhost")
    msg["To"] = to_addr
    msg.set_content(body)

    try:
        with smtplib.SMTP(host, int(config.get("SMTP_PORT", 587)), timeout=10) as s:
            if config.get("SMTP_USE_TLS", True):
                s.starttls()
            user = config.get("SMTP_USER", "")
            pwd = config.get("SMTP_PASSWORD", "")
            if user and pwd:
                s.login(user, pwd)
            s.send_message(msg)
    except (smtplib.SMTPException, OSError) as e:
        logger.warning("Falha ao enviar email para %s: %s", to_addr, e)


def _dispatch(app, payload: dict, webhook_url: str, email: str, subject: str, body: str) -> None:
    with app.app_context():
        cfg = {
            k: app.config.get(k)
            for k in (
                "SMTP_HOST",
                "SMTP_PORT",
                "SMTP_USER",
                "SMTP_PASSWORD",
                "SMTP_FROM",
                "SMTP_USE_TLS",
            )
        }
        if webhook_url:
            _send_webhook(webhook_url, payload)
        if email:
            _send_email(cfg, email, subject, body)


def notify_alert(alert, profile=None, device=None) -> None:
    """Dispara notificações para um alerta recém-criado.

    Lê `webhook_url` e `notify_email` do profile. Só envia se o profile tiver
    algum canal configurado. A execução roda em thread separada para não
    bloquear a transação chamadora. Seguro chamar antes ou depois do commit.
    """
    try:
        app = current_app._get_current_object()
    except RuntimeError:
        logger.debug("notify_alert fora de app context — ignorando.")
        return

    if not app.config.get("NOTIFICATIONS_ENABLED", True):
        return

    if profile is None and alert.profile_id:
        from app.models import Profile
        from app.extensions import db
        profile = db.session.get(Profile, alert.profile_id)

    webhook_url = (profile.webhook_url or "").strip() if profile else ""
    email = (profile.notify_email or "").strip() if profile else ""

    if not webhook_url and not email:
        return

    if device is None and alert.device_id:
        from app.models import Device
        from app.extensions import db
        device = db.session.get(Device, alert.device_id)

    payload = _build_payload(alert, profile, device)
    subject = f"[NetMonitor] {payload['severity']} — {payload['alert_type']}"
    body_lines = [
        f"Severity: {payload['severity']}",
        f"Type: {payload['alert_type']}",
        f"Profile: {payload['profile']['name'] if payload['profile'] else '-'}",
        f"Device: {payload['device']['display_name'] if payload['device'] else '-'}",
        f"IP: {payload['device']['ip'] if payload['device'] else '-'}",
        f"When: {payload['created_at']}",
        "",
        payload["message"],
    ]
    body = "\n".join(body_lines)

    t = threading.Thread(
        target=_dispatch,
        args=(app, payload, webhook_url, email, subject, body),
        daemon=True,
    )
    t.start()


__all__ = ["notify_alert"]
