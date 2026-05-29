"""Add profiles.default_ports column

Revision ID: 3e9f1a4c7d08
Revises: 7d2b5f8a1c04
Create Date: 2026-04-24 14:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = "3e9f1a4c7d08"
down_revision = "7d2b5f8a1c04"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("profiles") as batch_op:
        batch_op.add_column(
            sa.Column("default_ports", sa.Text(), nullable=False, server_default="")
        )


def downgrade():
    with op.batch_alter_table("profiles") as batch_op:
        batch_op.drop_column("default_ports")
