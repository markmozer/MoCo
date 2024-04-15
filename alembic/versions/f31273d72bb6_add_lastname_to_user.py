"""add lastname to user

Revision ID: f31273d72bb6
Revises: a637cad9f3cb
Create Date: 2024-04-15 23:26:45.492023

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f31273d72bb6'
down_revision: Union[str, None] = 'a637cad9f3cb'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('users', sa.Column('lastname', sa.String))


def downgrade() -> None:
    op.drop_column('users', 'lastname')
