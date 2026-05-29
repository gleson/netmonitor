"""Testes de geração de alertas e endpoints de API."""

from datetime import datetime, timezone

from app.models import Device, DeviceIp, Alert, AlertType, Severity


def test_create_new_device_alert(db, sample_profile):
    """Verifica criação de alerta para novo dispositivo."""
    device = Device(
        profile_id=sample_profile.id,
        mac="AA:BB:CC:DD:EE:01",
        hostname="newhost",
    )
    db.session.add(device)
    db.session.flush()

    alert = Alert(
        profile_id=sample_profile.id,
        device_id=device.id,
        alert_type=AlertType.NEW_DEVICE,
        severity=Severity.INFO,
        message=f"Novo dispositivo: {device.mac}",
    )
    db.session.add(alert)
    db.session.commit()

    assert alert.id is not None
    assert alert.alert_type == AlertType.NEW_DEVICE
    assert not alert.is_acknowledged


def test_create_ip_change_alert(db, sample_profile):
    """Verifica alerta de mudança de IP para mesmo MAC."""
    device = Device(profile_id=sample_profile.id, mac="AA:BB:CC:DD:EE:02")
    db.session.add(device)
    db.session.flush()

    alert = Alert(
        profile_id=sample_profile.id,
        device_id=device.id,
        alert_type=AlertType.NEW_IP_FOR_MAC,
        severity=Severity.WARNING,
        message=f"IP mudou: 192.168.1.10 -> 192.168.1.20",
    )
    db.session.add(alert)
    db.session.commit()

    assert alert.severity == Severity.WARNING


def test_acknowledge_alert(db, sample_profile):
    """Testa reconhecimento de alerta."""
    alert = Alert(
        profile_id=sample_profile.id,
        alert_type=AlertType.NEW_PORT,
        severity=Severity.WARNING,
        message="Nova porta: tcp/443",
    )
    db.session.add(alert)
    db.session.commit()

    assert not alert.is_acknowledged

    alert.acknowledged_at = datetime.now(timezone.utc)
    db.session.commit()

    assert alert.is_acknowledged


def test_api_alerts_list(auth_client, db, sample_profile):
    """Testa endpoint JSON de listagem de alertas."""
    # Cria alguns alertas
    for i in range(3):
        db.session.add(Alert(
            profile_id=sample_profile.id,
            alert_type=AlertType.NEW_DEVICE,
            severity=Severity.INFO,
            message=f"Alerta de teste {i}",
        ))
    db.session.commit()

    resp = auth_client.get(f"/api/alerts?profile_id={sample_profile.id}")
    assert resp.status_code == 200

    data = resp.get_json()
    assert data["total"] == 3
    assert len(data["alerts"]) == 3


def test_api_acknowledge_alert(auth_client, db, sample_profile):
    """Testa endpoint de reconhecimento de alerta via API (operator+)."""
    from app.models import User, ROLE_OPERATOR

    # auth_client loga como viewer por padrão; eleva para operator.
    User.query.filter_by(username="testuser").update({"role": ROLE_OPERATOR})
    db.session.commit()

    alert = Alert(
        profile_id=sample_profile.id,
        alert_type=AlertType.HOST_DOWN,
        severity=Severity.CRITICAL,
        message="Host down",
    )
    db.session.add(alert)
    db.session.commit()

    resp = auth_client.post(f"/api/alerts/{alert.id}/acknowledge")
    assert resp.status_code == 200

    data = resp.get_json()
    assert data["status"] == "ok"

    # Verifica no banco
    db.session.refresh(alert)
    assert alert.is_acknowledged


def test_api_open_alert_count(auth_client, db, sample_profile):
    """Endpoint de contagem de alertas abertos (badge do navbar)."""
    db.session.add(Alert(
        profile_id=sample_profile.id, alert_type=AlertType.NEW_DEVICE,
        severity=Severity.INFO, message="aberto 1",
    ))
    ack = Alert(
        profile_id=sample_profile.id, alert_type=AlertType.NEW_DEVICE,
        severity=Severity.INFO, message="reconhecido",
        acknowledged_at=datetime.now(timezone.utc).replace(tzinfo=None),
    )
    db.session.add(ack)
    db.session.commit()

    resp = auth_client.get(f"/api/alerts/open-count?profile_id={sample_profile.id}")
    assert resp.status_code == 200
    assert resp.get_json()["open_alerts"] == 1


def test_notify_min_severity_gating(db, sample_profile):
    """_maybe_notify respeita Profile.notify_min_severity."""
    from app.scanner import scheduling

    sent = []
    # Stub do notify_alert para não tocar rede.
    import app.notifications as notifications
    original_notify = notifications.notify_alert
    notifications.notify_alert = lambda alert, profile=None, device=None: sent.append(alert)
    try:
        sample_profile.notify_min_severity = "WARNING"
        db.session.commit()

        info_alert = Alert(profile_id=sample_profile.id, alert_type=AlertType.NEW_DEVICE,
                           severity=Severity.INFO, message="info")
        warn_alert = Alert(profile_id=sample_profile.id, alert_type=AlertType.IP_CONFLICT,
                           severity=Severity.WARNING, message="warn")
        db.session.add_all([info_alert, warn_alert])
        db.session.commit()

        scheduling._maybe_notify(info_alert, sample_profile, None)
        scheduling._maybe_notify(warn_alert, sample_profile, None)
    finally:
        notifications.notify_alert = original_notify

    # INFO abaixo do mínimo (WARNING) não notifica; WARNING sim.
    assert info_alert not in sent
    assert warn_alert in sent


def test_api_acknowledge_alert_viewer_forbidden(auth_client, db, sample_profile):
    """Viewer não pode reconhecer alertas via API (RBAC espelha a view)."""
    alert = Alert(
        profile_id=sample_profile.id,
        alert_type=AlertType.HOST_DOWN,
        severity=Severity.CRITICAL,
        message="Host down",
    )
    db.session.add(alert)
    db.session.commit()

    # auth_client é viewer por padrão.
    resp = auth_client.post(f"/api/alerts/{alert.id}/acknowledge")
    assert resp.status_code == 403

    db.session.refresh(alert)
    assert not alert.is_acknowledged
