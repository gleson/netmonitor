"""add is_priority to alerts and create app_settings table

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
Create Date: 2026-05-25 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = 'd4e5f6a7b8c9'
down_revision = 'c3d4e5f6a7b8'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('alerts', schema=None) as batch_op:
        batch_op.add_column(sa.Column('is_priority', sa.Boolean(), nullable=False, server_default=sa.false()))

    op.create_table(
        'app_settings',
        sa.Column('key', sa.String(length=80), primary_key=True),
        sa.Column('value', sa.Text(), nullable=False, server_default=''),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
    )


def downgrade():
    op.drop_table('app_settings')
    with op.batch_alter_table('alerts', schema=None) as batch_op:
        batch_op.drop_column('is_priority')
