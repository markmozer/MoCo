from myapp import db
from flask_login import UserMixin
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import Integer, String, Date, DateTime, Boolean
from werkzeug.security import generate_password_hash
from datetime import date, datetime, UTC


class User(UserMixin, db.Model):
    __tablename__ = "users"         # noqa
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    password: Mapped[str] = mapped_column(String(100), nullable=False)
    created_on: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.now())
    is_admin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_confirmed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    confirmed_on: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    firstname: Mapped[str] = mapped_column(String(100), nullable=True, unique=False)
    lastname: Mapped[str] = mapped_column(String(100), nullable=True, unique=False)
    mobile: Mapped[str] = mapped_column(String(100), nullable=True, unique=False)
    date_of_birth: Mapped[date] = mapped_column(Date, nullable=True, unique=False)
    gender: Mapped[str] = mapped_column(String(10), nullable=False, unique=False, default='U')

    def __init__(self, username, password, is_admin=False, is_confirmed=False, confirmed_on=None):
        # Hash and salt the password
        hash_and_salted_password = generate_password_hash(
            password,
            method='pbkdf2:sha256',
            salt_length=8
        )
        self.username = username
        self.password = hash_and_salted_password  # noqa
        self.created_on = datetime.now(tz=UTC)  # noqa
        self.is_admin = is_admin  # noqa
        self.is_confirmed = is_confirmed  # noqa
        self.confirmed_on = confirmed_on

    def __repr__(self):
        return f"<email {self.email}>"
