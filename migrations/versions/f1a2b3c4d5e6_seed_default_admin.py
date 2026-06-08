"""seed default admin user

Cria automaticamente o usuário administrador padrão quando o banco ainda não
tem nenhum usuário. Assim, quem clona o repositório e roda `flask db upgrade`
já consegue logar sem precisar do `flask seed-admin`.

Padrão:
    usuário: admin
    senha:   umaSenhaForte123   (TROQUE após o primeiro acesso!)

Pode ser sobrescrito por variáveis de ambiente no momento do upgrade:
    SEED_ADMIN_USERNAME, SEED_ADMIN_PASSWORD

Idempotente: só insere o admin se a tabela `users` estiver vazia — nunca
sobrescreve usuários existentes nem altera senhas já definidas.

Revision ID: f1a2b3c4d5e6
Revises: e5f6a7b8c9d0
Create Date: 2026-06-08 10:30:00.000000

"""
import os
from datetime import datetime, timezone

from alembic import op
import sqlalchemy as sa
from werkzeug.security import generate_password_hash


# revision identifiers, used by Alembic.
revision = "f1a2b3c4d5e6"
down_revision = "e5f6a7b8c9d0"
branch_labels = None
depends_on = None


DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "umaSenhaForte123"


def upgrade():
    bind = op.get_bind()

    # Não faz nada se já existir qualquer usuário (deploy existente / re-run).
    existing = bind.execute(sa.text("SELECT COUNT(*) FROM users")).scalar()
    if existing and existing > 0:
        return

    username = os.environ.get("SEED_ADMIN_USERNAME", DEFAULT_USERNAME)
    password = os.environ.get("SEED_ADMIN_PASSWORD", DEFAULT_PASSWORD)
    now = datetime.now(timezone.utc).replace(tzinfo=None)  # UTC naive (igual ao app)

    bind.execute(
        sa.text(
            "INSERT INTO users (username, password_hash, is_active, role, created_at) "
            "VALUES (:username, :password_hash, :is_active, :role, :created_at)"
        ),
        {
            "username": username,
            "password_hash": generate_password_hash(password),
            "is_active": True,
            "role": "admin",
            "created_at": now,
        },
    )


def downgrade():
    # Remove apenas o admin padrão criado por esta migration.
    username = os.environ.get("SEED_ADMIN_USERNAME", DEFAULT_USERNAME)
    op.get_bind().execute(
        sa.text("DELETE FROM users WHERE username = :username AND role = 'admin'"),
        {"username": username},
    )
