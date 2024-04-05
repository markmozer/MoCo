from datetime import datetime, UTC
from flask import Flask, flash, render_template, redirect, request, url_for
from flask_bootstrap import Bootstrap5
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from flask_wtf import FlaskForm
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy import Integer, String, Date, DateTime, Boolean
from config import Config
from wtforms import StringField, EmailField, PasswordField, SubmitField, DateField
from wtforms.validators import DataRequired, Email, Length, EqualTo, Regexp
from werkzeug.security import generate_password_hash, check_password_hash
from libgravatar import Gravatar
from msgraphapi import MSGraphAPI
from functools import wraps
from moco_token import generate_token, confirm_token



class Base(DeclarativeBase):  # noqa
    pass


db = SQLAlchemy(model_class=Base)
login_manager = LoginManager()

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
login_manager.init_app(app)
Bootstrap5(app)


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    password: Mapped[str] = mapped_column(String(100), nullable=False)
    created_on: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.now())
    is_admin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_confirmed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    confirmed_on: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    def __init__(self, username, password, is_admin=False, is_confirmed=False, confirmed_on=None):

        # Hash and salt the password
        hash_and_salted_password = generate_password_hash(
            password,
            method='pbkdf2:sha256',
            salt_length=8
        )
        self.username = username
        self.password = hash_and_salted_password            # noqa
        self.created_on = datetime.now(tz=UTC)              # noqa
        self.is_admin = is_admin                            # noqa
        self.is_confirmed = is_confirmed                    # noqa
        self.confirmed_on = confirmed_on

    def __repr__(self):
        return f"<email {self.email}>"


class RegisterUserForm(FlaskForm):
    username = EmailField("Username (e-mail)", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[
        DataRequired(),
        Length(min=8),
        EqualTo(fieldname='confirm'),
        Regexp(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$", message="Regex message!")
    ])
    confirm = PasswordField('Confirm Password')
    submit = SubmitField("Register")


class LoginUserForm(FlaskForm):
    username = EmailField("Username (e-mail)", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


with app.app_context():
    db.create_all()


def logout_required(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated:
            flash("You are already authenticated.", "info")
            return redirect(url_for("home"))
        return func(*args, **kwargs)

    return decorated_function


# Routes
@app.route("/")
def home():
    return render_template('index.html')


@app.route("/register", methods=['GET', 'POST'])
@logout_required
def register():
    form = RegisterUserForm()
    if form.validate_on_submit():
        # Check if username already exists in the database
        result = db.session.execute(db.select(User).where(User.username == form.username.data))
        user = result.scalar()
        if user:
            flash('Username is already registered! Please login', "info")
            return redirect(url_for('login'))
        # Add new user to the database
        new_user = User(
            username=form.data.get('username'),
            password=form.data.get('password'),
        )
        db.session.add(new_user)
        db.session.commit()

        token = generate_token(new_user.username)
        confirm_url = url_for("confirm_email", token=token, _external=True)
        html = render_template("confirm_email.html", confirm_url=confirm_url)
        subject = "Please confirm your email"

        mail_api = MSGraphAPI()
        mail_api.send_email(subject=subject, body=html, recipient=new_user.username)

        login_user(new_user)

        flash(f'A confirmation email has been sent to {new_user.username}.', 'success')

        return redirect(url_for('inactive'))
    return render_template('register.html', form=form)


@app.route("/inactive")
@login_required
def inactive():
    if current_user.is_confirmed:
        return redirect(url_for("home"))
    return render_template("inactive.html")


@app.route("/resend")
@login_required
def resend_confirmation():
    if current_user.is_confirmed:
        flash("Your account has already been confirmed.", "success")
        return redirect(url_for("home"))
    token = generate_token(current_user.username)
    confirm_url = url_for("confirm_email", token=token, _external=True)
    html = render_template("confirm_email.html", confirm_url=confirm_url)
    subject = "Please confirm your email"

    mail_api = MSGraphAPI()
    mail_api.send_email(subject=subject, body=html, recipient=current_user.username)

    flash(f'A new confirmation email has been sent to {current_user.username}.', 'success')
    return redirect(url_for("inactive"))


@app.route("/confirm/<token>")
@login_required
def confirm_email(token):
    if current_user.is_confirmed:
        flash("Account already confirmed.", "success")
        return redirect(url_for("home"))
    email = confirm_token(token)
    user = User.query.filter_by(username=current_user.username).first_or_404()
    if user.username == email:
        user.is_confirmed = True
        user.confirmed_on = datetime.now()
        db.session.add(user)
        db.session.commit()
        flash("You have confirmed your account. Thanks!", "success")
    else:
        flash("The confirmation link is invalid or has expired.", "danger")
    return redirect(url_for("home"))


@app.route("/login", methods=['GET', 'POST'])
@logout_required
def login():
    form = LoginUserForm()
    if form.validate_on_submit():
        # Check if user is already registered
        result = db.session.execute(db.select(User).where(User.username == form.username.data))
        user = result.scalar()
        if not user:
            flash(f'User {form.username.data} is not registered! Try again or proceed to registration.', "warning")
            return redirect(url_for('login'))
        # Check if provided password is correct
        if not check_password_hash(user.password, form.password.data):
            flash("The password you've entered is incorrect! Please try again", "warning")
            return redirect(url_for('login'))
        login_user(user)
        return redirect(url_for('home'))
    return render_template('login.html', form=form)


@app.route("/logout")
def logout():
    print('Test')
    logout_user()
    return redirect(url_for('home'))


@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


@app.context_processor
def inject_now():
    if current_user.is_authenticated:
        gravatar = Gravatar(current_user.username)
        img_url = gravatar.get_image()
    else:
        img_url = "https://www.gravatar.com/avatar/59235f35e4763abb0b547bd093562f6e"
    return {'now': datetime.now(UTC), 'img_url': img_url}


@app.cli.command("create_admin")
def create_admin():
    """Creates the admin user."""
    username = input("Enter email address: ")
    password = input("Enter password: ")
    confirm_password = input("Enter password again: ")
    if password != confirm_password:
        print("Passwords don't match")
    else:
        try:
            user = User(
                username=username,
                password=password,
                is_admin=True,
                is_confirmed=True,
                confirmed_on=datetime.now(),
            )
            db.session.add(user)
            db.session.commit()
            print(f"Admin with email {username} created successfully!")
        except Exception:
            print("Couldn't create admin user.")



if __name__ == "__main__":
    app.run(debug=False)
