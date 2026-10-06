"""Phase 8: Deep scanning, active verification, and danger assessment columns.

Revision ID: 002
Revises: 001
Create Date: 2026-10-06 14:15:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '002'
down_revision: Union[str, None] = '001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Add 'deep' to scan_type_enum
    # In PostgreSQL, we can use ALTER TYPE ... ADD VALUE
    op.execute("ALTER TYPE scan_type_enum ADD VALUE IF NOT EXISTS 'deep'")

    # 2. Create verification_type_enum
    verification_type = postgresql.ENUM(
        'version_match', 'nse_verified', 'nuclei_verified',
        name='verification_type_enum'
    )
    verification_type.create(op.get_bind(), checkfirst=True)

    # 3. Add columns to vulnerabilities table
    op.add_column(
        'vulnerabilities',
        sa.Column(
            'verification',
            sa.Enum('version_match', 'nse_verified', 'nuclei_verified', name='verification_type_enum'),
            nullable=False,
            server_default='version_match'
        )
    )
    op.add_column('vulnerabilities', sa.Column('evidence', sa.Text(), nullable=True))
    op.add_column('vulnerabilities', sa.Column('danger_score', sa.Float(), nullable=True))
    op.add_column('vulnerabilities', sa.Column('exploitability', sa.Text(), nullable=True))
    op.add_column('vulnerabilities', sa.Column('impact', sa.Text(), nullable=True))
    op.add_column(
        'vulnerabilities',
        sa.Column('public_exploit', sa.Boolean(), nullable=False, server_default=sa.text('false'))
    )


def downgrade() -> None:
    op.drop_column('vulnerabilities', 'public_exploit')
    op.drop_column('vulnerabilities', 'impact')
    op.drop_column('vulnerabilities', 'exploitability')
    op.drop_column('vulnerabilities', 'danger_score')
    op.drop_column('vulnerabilities', 'evidence')
    op.drop_column('vulnerabilities', 'verification')

    verification_type = postgresql.ENUM(
        'version_match', 'nse_verified', 'nuclei_verified',
        name='verification_type_enum'
    )
    verification_type.drop(op.get_bind(), checkfirst=True)
