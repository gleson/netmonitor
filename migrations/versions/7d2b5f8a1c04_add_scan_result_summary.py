"""Add scans.result_summary column

Revision ID: 7d2b5f8a1c04
Revises: 5c1a4e2f8b90
Create Date: 2026-04-24 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = "7d2b5f8a1c04"
down_revision = "5c1a4e2f8b90"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("scans") as batch_op:
        batch_op.add_column(sa.Column("result_summary", sa.Text(), nullable=True))


def downgrade():
    with op.batch_alter_table("scans") as batch_op:
        batch_op.drop_column("result_summary")
