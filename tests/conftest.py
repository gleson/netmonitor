"""Fixtures compartilhadas para os testes."""

import pytest

from app import create_app, db as _db
from app.models import User, Profile, IpRange


@pytest.fixture(scope="session")
def app():
    """Cria a instância Flask para testes."""
    app = create_app("testing")
    with app.app_context():
        _db.create_all()
        yield app
        _db.drop_all()


@pytest.fixture(scope="function")
def db(app):
    """Fornece uma sessão de banco limpa para cada teste."""
    with app.app_context():
        _db.create_all()
        yield _db
        _db.session.rollback()
        for table in reversed(_db.metadata.sorted_tables):
            _db.session.execute(table.delete())
        _db.session.commit()


@pytest.fixture
def client(app):
    """Client HTTP de teste."""
    return app.test_client()


@pytest.fixture
def auth_client(app, db):
    """Client autenticado (já logado)."""
    user = User(username="testuser")
    user.set_password("testpass123")
    db.session.add(user)
    db.session.commit()

    client = app.test_client()
    with client.session_transaction() as sess:
        # Simula login via flask-login
        sess["_user_id"] = str(user.id)
    return client


@pytest.fixture
def sample_profile(db):
    """Cria um perfil de teste."""
    profile = Profile(
        name="Test Network",
        description="Rede de teste",
        host_discovery_interval_minutes=10,
        port_scan_interval_minutes=5,
    )
    db.session.add(profile)
    db.session.commit()
    return profile


@pytest.fixture
def sample_range(db, sample_profile):
    """Cria uma faixa de IP de teste."""
    ip_range = IpRange(
        profile_id=sample_profile.id,
        cidr="192.168.1.0/24",
        description="LAN teste",
    )
    db.session.add(ip_range)
    db.session.commit()
    return ip_range
