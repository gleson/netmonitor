"""Testes de autenticação: login, logout e bloqueio por tentativas falhas."""

from app.models import User, AuditLog


def _make_user(db, username="bob", password="senha123456"):
    user = User(username=username)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    return user


def test_login_success(client, db):
    _make_user(db)
    resp = client.post(
        "/login",
        data={"username": "bob", "password": "senha123456"},
        follow_redirects=False,
    )
    # Redireciona para o dashboard após login.
    assert resp.status_code in (302, 303)


def test_login_lockout_after_max_attempts(client, db, app):
    """Após LOGIN_MAX_FAILED_ATTEMPTS falhas, o login é bloqueado (429)."""
    _make_user(db)
    max_attempts = app.config["LOGIN_MAX_FAILED_ATTEMPTS"]

    # Esgota as tentativas com senha errada.
    for _ in range(max_attempts):
        resp = client.post(
            "/login", data={"username": "bob", "password": "errada"}
        )
        assert resp.status_code == 200  # falha normal, ainda não bloqueado

    # Próxima tentativa deve ser bloqueada, mesmo com a senha correta.
    resp = client.post(
        "/login", data={"username": "bob", "password": "senha123456"}
    )
    assert resp.status_code == 429
    assert AuditLog.query.filter_by(action="login.locked").count() >= 1


def test_login_success_resets_failures(client, db, app):
    """Um login bem-sucedido zera o contador de falhas (não bloqueia depois)."""
    _make_user(db)
    max_attempts = app.config["LOGIN_MAX_FAILED_ATTEMPTS"]

    # Algumas falhas, abaixo do limite.
    for _ in range(max_attempts - 1):
        client.post("/login", data={"username": "bob", "password": "errada"})

    # Login correto reseta.
    ok = client.post("/login", data={"username": "bob", "password": "senha123456"})
    assert ok.status_code in (302, 303)
    client.get("/logout")

    # Novas falhas até o limite-1 ainda não bloqueiam (contador resetou).
    for _ in range(max_attempts - 1):
        resp = client.post("/login", data={"username": "bob", "password": "errada"})
        assert resp.status_code == 200
