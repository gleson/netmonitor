"""add last_port_scanned_at to device

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-05-12 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = 'b2c3d4e5f6a7'
down_revision = 'a1b2c3d4e5f6'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('devices', schema=None) as batch_op:
        batch_op.add_column(sa.Column('last_port_scanned_at', sa.DateTime(), nullable=True))


def downgrade():
    with op.batch_alter_table('devices', schema=None) as batch_op:
        batch_op.drop_column('last_port_scanned_at')
