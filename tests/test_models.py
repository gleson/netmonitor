"""Testes dos modelos SQLAlchemy."""

from app.models import (
    User, Profile, Device, DeviceIp, Port, Alert,
    DeviceType, AlertType, Severity,
)


def test_user_password(db):
    """Verifica hash/check de senha."""
    user = User(username="admin")
    user.set_password("s3cr3tpass42")
    db.session.add(user)
    db.session.commit()

    assert user.check_password("s3cr3tpass42")
    assert not user.check_password("wrong")


def test_user_password_policy(db):
    """Senhas fracas devem ser rejeitadas."""
    import pytest
    user = User(username="weak")
    for bad in ("short", "toolongbutnodigits", "1234567890", ""):
        with pytest.raises(ValueError):
            user.set_password(bad)
    # Válida não explode
    user.set_password("Valid1pass99")


def test_device_display_name(db, sample_profile):
    """Display name deve priorizar friendly_name > hostname > mac."""
    device = Device(
        profile_id=sample_profile.id,
        mac="AA:BB:CC:DD:EE:FF",
        hostname="myhost",
    )
    db.session.add(device)
    db.session.commit()

    assert device.display_name == "myhost"

    device.friendly_name = "Meu PC"
    assert device.display_name == "Meu PC"

    device.friendly_name = None
    device.hostname = ""
    assert device.display_name == "AA:BB:CC:DD:EE:FF"


def test_device_current_ip(db, sample_profile):
    """Verifica que current_ip retorna o IP marcado como is_current."""
    device = Device(profile_id=sample_profile.id, mac="11:22:33:44:55:66")
    db.session.add(device)
    db.session.flush()

    dip = DeviceIp(device_id=device.id, ip="192.168.1.10", is_current=True)
    db.session.add(dip)
    db.session.commit()

    assert device.current_ip == "192.168.1.10"


def test_port_is_open(db, sample_profile):
    """Porta sem last_seen_closed_at deve ser considerada aberta."""
    device = Device(profile_id=sample_profile.id, mac="AA:BB:CC:00:11:22")
    db.session.add(device)
    db.session.flush()

    port = Port(device_id=device.id, protocol="tcp", port=80, service_name="http")
    db.session.add(port)
    db.session.commit()

    assert port.is_open is True
    assert device.open_ports_count == 1


def test_alert_acknowledged(db, sample_profile):
    """Alerta é reconhecido quando acknowledged_at está preenchido."""
    from datetime import datetime, timezone

    alert = Alert(
        profile_id=sample_profile.id,
        alert_type=AlertType.NEW_DEVICE,
        severity=Severity.INFO,
        message="Novo device",
    )
    db.session.add(alert)
    db.session.commit()

    assert not alert.is_acknowledged

    alert.acknowledged_at = datetime.now(timezone.utc)
    assert alert.is_acknowledged
