"""add user.gender

Revision ID: fd69e9ec5447
Revises: 
Create Date: 2024-04-21 20:46:39.481019

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'fd69e9ec5447'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('users', sa.Column('gender', sa.String(20)))


def downgrade() -> None:
    op.drop_column('users', 'gender')
