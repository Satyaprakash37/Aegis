"""Phase 8.1: Support domain names and URLs as asset targets with auto DNS resolution.

Revision ID: 003
Revises: 002
Create Date: 2026-10-06 16:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '003'
down_revision: Union[str, None] = '002'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create target_type_enum
    target_type = postgresql.ENUM('ip', 'domain', name='target_type_enum')
    target_type.create(op.get_bind(), checkfirst=True)

    # 2. Widen assets.ip_address column from 45 to 255 chars to support domain names
    op.alter_column(
        'assets',
        'ip_address',
        existing_type=sa.String(length=45),
        type_=sa.String(length=255),
        existing_nullable=False,
    )

    # 3. Add target_type column (defaulting to 'ip' for existing rows)
    op.add_column(
        'assets',
        sa.Column(
            'target_type',
            sa.Enum('ip', 'domain', name='target_type_enum'),
            nullable=False,
            server_default='ip',
        ),
    )

    # 4. Add resolved_ip column (nullable)
    op.add_column(
        'assets',
        sa.Column('resolved_ip', sa.String(length=45), nullable=True),
    )


def downgrade() -> None:
    op.drop_column('assets', 'resolved_ip')
    op.drop_column('assets', 'target_type')

    op.alter_column(
        'assets',
        'ip_address',
        existing_type=sa.String(length=255),
        type_=sa.String(length=45),
        existing_nullable=False,
    )

    target_type = postgresql.ENUM('ip', 'domain', name='target_type_enum')
    target_type.drop(op.get_bind(), checkfirst=True)
