"""add fields to user

Revision ID: a637cad9f3cb
Revises: 
Create Date: 2024-04-15 20:49:52.030082

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a637cad9f3cb'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('users', sa.Column('firstname', sa.String))


def downgrade() -> None:
    op.drop_column('users', 'firstname')
