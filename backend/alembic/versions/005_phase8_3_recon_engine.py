"""Phase 8.3: Real-world web reconnaissance engine, live progress, and ssl_verified enum.

Revision ID: 005
Revises: 004
Create Date: 2026-10-07 04:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '005'
down_revision: Union[str, None] = '004'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Add 'ssl_verified' to verification_type_enum in PostgreSQL
    op.execute("ALTER TYPE verification_type_enum ADD VALUE IF NOT EXISTS 'ssl_verified'")

    # 2. Add progress JSONB column to scans table
    op.add_column(
        'scans',
        sa.Column('progress', postgresql.JSONB(astext_type=sa.Text()), nullable=True)
    )


def downgrade() -> None:
    op.drop_column('scans', 'progress')
