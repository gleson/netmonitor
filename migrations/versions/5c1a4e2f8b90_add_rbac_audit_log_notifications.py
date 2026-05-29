"""Add RBAC role, audit log and notification columns

Revision ID: 5c1a4e2f8b90
Revises: 273e8aa900ec
Create Date: 2026-04-22 13:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = "5c1a4e2f8b90"
down_revision = "273e8aa900ec"
branch_labels = None
depends_on = None


def upgrade():
    # users.role
    with op.batch_alter_table("users") as batch_op:
        batch_op.add_column(
            sa.Column("role", sa.String(length=20), nullable=False, server_default="viewer")
        )

    # Primeira conta de usuário ganha admin (compatibilidade com deploy existente).
    op.execute(
        "UPDATE users SET role='admin' WHERE id = (SELECT id FROM users ORDER BY id LIMIT 1)"
    )

    # profiles — notificações
    with op.batch_alter_table("profiles") as batch_op:
        batch_op.add_column(
            sa.Column("webhook_url", sa.String(length=500), nullable=False, server_default="")
        )
        batch_op.add_column(
            sa.Column("notify_email", sa.String(length=200), nullable=False, server_default="")
        )

    # audit_logs
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("username", sa.String(length=80), nullable=False, server_default=""),
        sa.Column("action", sa.String(length=80), nullable=False),
        sa.Column("entity_type", sa.String(length=50), nullable=False, server_default=""),
        sa.Column("entity_id", sa.Integer(), nullable=True),
        sa.Column("details", sa.Text(), nullable=False, server_default=""),
        sa.Column("ip_address", sa.String(length=45), nullable=False, server_default=""),
    )
    op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"])
    op.create_index("ix_audit_logs_user_id", "audit_logs", ["user_id"])
    op.create_index("ix_audit_logs_action", "audit_logs", ["action"])


def downgrade():
    op.drop_index("ix_audit_logs_action", table_name="audit_logs")
    op.drop_index("ix_audit_logs_user_id", table_name="audit_logs")
    op.drop_index("ix_audit_logs_created_at", table_name="audit_logs")
    op.drop_table("audit_logs")

    with op.batch_alter_table("profiles") as batch_op:
        batch_op.drop_column("notify_email")
        batch_op.drop_column("webhook_url")

    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_column("role")
