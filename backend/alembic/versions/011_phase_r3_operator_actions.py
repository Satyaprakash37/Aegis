"""Phase R3: Red Team Console - operator_actions audit logging table.

Revision ID: 011
Revises: 010
Create Date: 2026-10-09 19:10:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '011'
down_revision: Union[str, None] = '010'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'operator_actions',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('asset_id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('tool', sa.String(length=50), nullable=False),
        sa.Column('command_or_action', sa.Text(), nullable=False),
        sa.Column('result_summary', sa.Text(), nullable=False),
        sa.Column('evidence', sa.Text(), nullable=True),
        sa.Column('linked_cves', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_operator_actions_asset_id', 'operator_actions', ['asset_id'], unique=False)
    op.create_index('ix_operator_actions_user_id', 'operator_actions', ['user_id'], unique=False)
    op.create_index('ix_operator_actions_created_at', 'operator_actions', ['created_at'], unique=False)
    op.create_index('ix_operator_actions_asset_created', 'operator_actions', ['asset_id', 'created_at'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_operator_actions_asset_created', table_name='operator_actions')
    op.drop_index('ix_operator_actions_created_at', table_name='operator_actions')
    op.drop_index('ix_operator_actions_user_id', table_name='operator_actions')
    op.drop_index('ix_operator_actions_asset_id', table_name='operator_actions')
    op.drop_table('operator_actions')
