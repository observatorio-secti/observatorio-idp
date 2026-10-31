"""add_user_role

Revision ID: e6ab78f1234c
Revises: d5fe30a5e5f1
Create Date: 2026-10-31 13:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e6ab78f1234c'
down_revision: Union[str, Sequence[str], None] = 'd5fe30a5e5f1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema: add role column to users."""
    op.add_column(
        'users',
        sa.Column(
            'role',
            sa.String(length=50),
            nullable=False,
            server_default='DEFAULT',
        ),
    )


def downgrade() -> None:
    """Downgrade schema: drop role column from users."""
    op.drop_column('users', 'role')
