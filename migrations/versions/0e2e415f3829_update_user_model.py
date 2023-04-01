"""Update User model

Revision ID: 0e2e415f3829
Revises: 3dfc546bd7d3
Create Date: 2023-04-01 12:02:01.705987

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0e2e415f3829'
down_revision = '3dfc546bd7d3'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('test_table')
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.alter_column('username',
               existing_type=sa.VARCHAR(length=100),
               type_=sa.String(length=200),
               existing_nullable=False)
        batch_op.alter_column('password',
               existing_type=sa.VARCHAR(length=100),
               type_=sa.String(length=200),
               existing_nullable=False)
        batch_op.drop_column('email')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('email', sa.VARCHAR(length=120), autoincrement=False, nullable=True))
        batch_op.alter_column('password',
               existing_type=sa.String(length=200),
               type_=sa.VARCHAR(length=100),
               existing_nullable=False)
        batch_op.alter_column('username',
               existing_type=sa.String(length=200),
               type_=sa.VARCHAR(length=100),
               existing_nullable=False)

    op.create_table('test_table',
    sa.Column('id', sa.INTEGER(), autoincrement=True, nullable=False),
    sa.Column('name', sa.VARCHAR(length=50), autoincrement=False, nullable=False),
    sa.Column('age', sa.INTEGER(), autoincrement=False, nullable=False),
    sa.PrimaryKeyConstraint('id', name='test_table_pkey')
    )
    # ### end Alembic commands ###
