"""Phase 8.2: Direct target scanning and demo data management columns.

Revision ID: 004
Revises: 003
Create Date: 2026-10-06 17:15:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '004'
down_revision: Union[str, None] = '003'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

SEED_ASSET_NAMES = (
    "'web-server-01', 'db-cluster-primary', 'api-gateway', 'fileserver-nas', "
    "'mail-relay-edge', 'legacy-app-host', 'vpn-endpoint-perimeter', "
    "'backup-server-vault', 'owasp-juice-shop'"
)


def upgrade() -> None:
    # 1. Add auto_created column to assets (default False)
    op.add_column(
        'assets',
        sa.Column('auto_created', sa.Boolean(), nullable=False, server_default=sa.text('false')),
    )

    # 2. Add is_seed column to assets (default False)
    op.add_column(
        'assets',
        sa.Column('is_seed', sa.Boolean(), nullable=False, server_default=sa.text('false')),
    )

    # 3. Backfill is_seed flag for pre-seeded demo assets
    op.execute(f"UPDATE assets SET is_seed = true WHERE name IN ({SEED_ASSET_NAMES})")


def downgrade() -> None:
    op.drop_column('assets', 'is_seed')
    op.drop_column('assets', 'auto_created')
