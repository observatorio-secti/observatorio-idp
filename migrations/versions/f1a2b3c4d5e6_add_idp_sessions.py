"""add_idp_sessions

Revision ID: f1a2b3c4d5e6
Revises: e6ab78f1234c
Create Date: 2026-11-20 17:12:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'f1a2b3c4d5e6'
down_revision: Union[str, Sequence[str], None] = 'e6ab78f1234c'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema: create idp_sessions table."""
    op.create_table(
        'idp_sessions',
        sa.Column('user_id', sa.Uuid(), nullable=False),
        sa.Column('token_hash', sa.String(length=64), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            'created_at',
            sa.DateTime(timezone=True),
            server_default=sa.text('(CURRENT_TIMESTAMP)'),
            nullable=False,
        ),
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        op.f('ix_idp_sessions_token_hash'),
        'idp_sessions',
        ['token_hash'],
        unique=True,
    )
    op.create_index(
        op.f('ix_idp_sessions_user_id'),
        'idp_sessions',
        ['user_id'],
        unique=False,
    )


def downgrade() -> None:
    """Downgrade schema: drop idp_sessions table."""
    op.drop_index(op.f('ix_idp_sessions_user_id'), table_name='idp_sessions')
    op.drop_index(op.f('ix_idp_sessions_token_hash'), table_name='idp_sessions')
    op.drop_table('idp_sessions')
