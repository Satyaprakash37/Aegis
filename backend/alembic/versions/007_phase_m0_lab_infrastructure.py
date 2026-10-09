"""Phase M0: Lab Infrastructure - add is_lab flag and lab environment to assets.

Revision ID: 007
Revises: 006
Create Date: 2026-10-09 07:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '007'
down_revision: Union[str, None] = '006'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Add 'lab' value to asset_environment_enum if not already present
    op.execute("ALTER TYPE asset_environment_enum ADD VALUE IF NOT EXISTS 'lab'")

    # 2. Add is_lab column to assets table
    op.add_column(
        'assets',
        sa.Column('is_lab', sa.Boolean(), server_default='false', nullable=False)
    )

    # 3. Backfill: mark existing juice-shop assets as lab assets
    op.execute("""
        UPDATE assets
        SET is_lab = true
        WHERE name ILIKE '%juice%'
           OR ip_address IN ('172.20.0.5', '172.20.0.2', 'vulnerable-target', 'aegis-juice-shop')
    """)


def downgrade() -> None:
    op.drop_column('assets', 'is_lab')
