"""Phase R2: Attack Surface Intelligence - attack_surface_report on assets.

Revision ID: 010
Revises: 009
Create Date: 2026-10-09 17:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '010'
down_revision: Union[str, None] = '009'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'assets',
        sa.Column('attack_surface_report', postgresql.JSONB(astext_type=sa.Text()), nullable=True)
    )
    op.add_column(
        'assets',
        sa.Column('report_generated_at', sa.DateTime(timezone=True), nullable=True)
    )


def downgrade() -> None:
    op.drop_column('assets', 'report_generated_at')
    op.drop_column('assets', 'attack_surface_report')
