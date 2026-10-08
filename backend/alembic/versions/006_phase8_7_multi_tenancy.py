"""Phase 8.7: Multi-tenancy, per-user data isolation, and constraint updates.

Revision ID: 006
Revises: 005
Create Date: 2026-10-08 05:25:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '006'
down_revision: Union[str, None] = '005'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Add owner_id to assets table (FK -> users.id, nullable for system/seed assets)
    op.add_column(
        'assets',
        sa.Column('owner_id', sa.Integer(), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    )
    op.create_index('ix_assets_owner_id', 'assets', ['owner_id'], unique=False)

    # 2. Drop the global unique index on ip_address to allow per-user asset targets (e.g. shared targets like 172.20.0.5)
    # Re-create as a standard non-unique index
    op.drop_index('ix_assets_ip_address', table_name='assets')
    op.create_index('ix_assets_ip_address', 'assets', ['ip_address'], unique=False)

    # 3. Add created_by to scans table (FK -> users.id, nullable)
    op.add_column(
        'scans',
        sa.Column('created_by', sa.Integer(), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    )
    op.create_index('ix_scans_created_by', 'scans', ['created_by'], unique=False)

    # 4. Backfill existing records to admin user (admin@aegis.internal)
    # Real user/operator assets get owner_id = admin, seed assets keep owner_id = NULL
    op.execute("""
        UPDATE assets
        SET owner_id = (SELECT id FROM users WHERE email = 'admin@aegis.internal' LIMIT 1)
        WHERE is_seed = false OR is_seed IS NULL
    """)
    op.execute("UPDATE assets SET owner_id = NULL WHERE is_seed = true")

    # Backfill existing scans: assign to admin user
    op.execute("""
        UPDATE scans
        SET created_by = (SELECT id FROM users WHERE email = 'admin@aegis.internal' LIMIT 1)
        WHERE created_by IS NULL
    """)


def downgrade() -> None:
    op.drop_index('ix_scans_created_by', table_name='scans')
    op.drop_column('scans', 'created_by')

    op.drop_index('ix_assets_ip_address', table_name='assets')
    op.create_index('ix_assets_ip_address', 'assets', ['ip_address'], unique=True)

    op.drop_index('ix_assets_owner_id', table_name='assets')
    op.drop_column('assets', 'owner_id')
