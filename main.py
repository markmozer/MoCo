from msal import ConfidentialClientApplication
import requests
from typing import Optional
from itsdangerous import URLSafeTimedSerializer
from datetime import datetime, UTC, date
from flask import Flask, flash, render_template, redirect, request, url_for
from flask_bootstrap import Bootstrap5
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from flask_wtf import FlaskForm
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Date, DateTime, Boolean
from config import Config
from wtforms import StringField, EmailField, PasswordField, SubmitField, DateField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Email, Length, EqualTo, Regexp
from werkzeug.security import generate_password_hash, check_password_hash
from libgravatar import Gravatar
from functools import wraps


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


class RegisterUserForm(FlaskForm):
    username = EmailField("Username (e-mail)", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[
        DataRequired(),
        Length(min=8),
        EqualTo(fieldname='confirm'),
        Regexp(
            r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$",
            message="Field must contain uppercase, lowercase, number and special character!"
        )
    ])
    confirm = PasswordField('Confirm Password')
    submit = SubmitField("Register")


class LoginUserForm(FlaskForm):
    username = EmailField("Username (e-mail)", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


class ChgContactDetailsForm(FlaskForm):
    username = EmailField("Username (e-mail)", render_kw={'readonly': True, 'class': 'disabled-field'}, validators=[])
    firstname = StringField("Firstname", validators=[DataRequired()])
    lastname = StringField("Lastname", validators=[DataRequired()])
    mobile = StringField("Mobile number +#(#)#",
                         validators=[Regexp(r"^\+[0-9]+\([0-9]+\)[0-9]+$", message="Regex message!")])
    date_of_birth = DateField("Date of birth", validators=[])
    gender = SelectField(u'Gender', choices=[('M', 'Male'), ('F', 'Female'), ('U', 'Unspecified')])
    submit1 = SubmitField("Save changes")


class ChgPasswordForm(FlaskForm):
    old_password = PasswordField("Old password")
    password = PasswordField("New Password", validators=[
        DataRequired(),
        Length(min=8),
        EqualTo(fieldname='confirm'),
        Regexp(
            r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$",
            message="Field must contain uppercase, lowercase, number and special character!")
    ])
    confirm = PasswordField('Confirm Password')
    submit2 = SubmitField("Change Password")


class ContactForm(FlaskForm):
    name = StringField("Full name", validators=[DataRequired()])
    email = EmailField("Email", validators=[DataRequired(), Email()])
    phone = StringField("Phone number")
    message = TextAreaField("Message", validators=[DataRequired()])
    submit = SubmitField("Submit")


class MSGraphAPI:
    def __init__(self):
        self.access_token = self.get_access_token()

    def get_access_token(self):         # noqa
        authority = f'https://login.microsoftonline.com/{Config.MSAL_TENANT_ID}'
        scopes = ['https://graph.microsoft.com/.default']
        msal_app = ConfidentialClientApplication(
            Config.MSAL_CLIENT_ID,
            authority=authority,
            client_credential=Config.MSAL_CLIENT_SECRET
        )
        token_response = msal_app.acquire_token_for_client(scopes=scopes)
        access_token = token_response['access_token']

        if not access_token:
            print("Failed to acquire token")
            return None
        else:
            print("Token acquired for graph API")
            return access_token

    def send_email(self, subject: str, body: str, to_recipients: list, cc_recipients: Optional[list] = None):
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }

        to_list = [{"emailAddress": {"address": recipient}} for recipient in to_recipients]

        if cc_recipients:
            cc_list = [{"emailAddress": {"address": recipient}} for recipient in cc_recipients]
        else:
            cc_list = []

        # Replace the following email details
        email_data = {
            "message": {
                "subject": subject,
                "body": {
                    "contentType": "HTML",
                    "content": body
                },
                "toRecipients": to_list,
                "ccRecipients": cc_list,
            }
        }

        response = requests.post(
            f'https://graph.microsoft.com/v1.0/users/{Config.UPN}/sendMail',
            headers=headers,
            json=email_data
        )

        print(response.status_code, response.reason)


with app.app_context():
    db.create_all()


def admin_required(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash("You are not authorized for this page.", "error")
            return redirect(url_for("home"))
        return func(*args, **kwargs)

    return decorated_function


def logout_required(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated:
            flash("You are already authenticated.", "info")
            return redirect(url_for("home"))
        return func(*args, **kwargs)

    return decorated_function


def generate_token(email):
    serializer = URLSafeTimedSerializer(Config.SECRET_KEY)
    return serializer.dumps(email, salt=Config.SECURITY_PASSWORD_SALT)


def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(Config.SECRET_KEY)
    try:
        email = serializer.loads(
            token, salt=Config.SECURITY_PASSWORD_SALT, max_age=expiration
        )
        return email
    except Exception:       # noqa
        return False


# Routes
@app.route("/", methods=['GET', 'POST'])
def home():
    form = ContactForm()
    if request.method == 'POST':
        html = render_template("contact_email.html", form=form)
        subject = "Thank you for reaching out to Mozer Consulting"

        mail_api = MSGraphAPI()
        mail_api.send_email(
            subject=subject,
            body=html,
            to_recipients=[request.form.get('email')],
            cc_recipients=[Config.UPN]
        )
        flash("Your message has been sent successfully!", "success")
        return redirect(url_for('home') + "#top")
    return render_template('index.html', form=form)


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
        mail_api.send_email(subject=subject, body=html, to_recipients=[new_user.username])

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
    mail_api.send_email(subject=subject, body=html, to_recipients=[current_user.username])

    flash(f'A new confirmation email has been sent to {current_user.username}.', 'success')
    return redirect(url_for("inactive"))


@app.route("/confirm/<token>")
def confirm_email(token):
    email = confirm_token(token)
    result = db.session.execute(db.select(User).where(User.username == email))
    user = result.scalar()
    if not user:
        flash("The confirmation link is invalid or has expired.", "danger")
        return redirect(url_for("home"))
    if user.is_confirmed:
        flash("Account already confirmed.", "success")
        return redirect(url_for("home"))
    user.is_confirmed = True
    user.confirmed_on = datetime.now()
    db.session.add(user)
    db.session.commit()
    flash("You have confirmed your account. Thanks!", "success")
    return redirect(url_for("home"))


@app.errorhandler(401)
def not_found(e):
    return render_template("401.html", error=e)


@app.errorhandler(404)
def not_found(e):
    return render_template("404.html", error=e)


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
    logout_user()
    return redirect(url_for('home'))


@app.route("/profile", methods=['GET', 'POST'])
@login_required
def profile():
    form = ChgContactDetailsForm()
    if form.validate_on_submit():
        # Handle Form submission
        current_user.firstname = form.firstname.data
        current_user.lastname = form.lastname.data
        current_user.mobile = form.mobile.data
        current_user.date_of_birth = form.date_of_birth.data
        current_user.gender = form.gender.data
        db.session.commit()
        flash("Contact details updated", "success")
        redirect(url_for('profile'))

    form.username.data = current_user.username
    form.firstname.data = current_user.firstname
    form.lastname.data = current_user.lastname
    form.date_of_birth.data = current_user.date_of_birth
    form.mobile.data = current_user.mobile
    if current_user.gender is None:
        form.gender.data = 'Unspecified'
    else:
        form.gender.data = current_user.gender
    return render_template('profile.html', form=form)


@app.route("/changepwd", methods=['GET', 'POST'])
@login_required
def changepwd():
    form = ChgPasswordForm()
    if form.validate_on_submit():
        # Handle Form2 submission
        if not check_password_hash(current_user.password, form.old_password.data):
            flash("The old password you've entered is incorrect! Please try again", "warning")
        else:
            # Hash and salt the password
            hash_and_salted_password = generate_password_hash(
                form.password.data,
                method='pbkdf2:sha256',
                salt_length=8
            )

            current_user.password = hash_and_salted_password
            db.session.commit()
            flash("Your password is changed!", "success")
        return redirect(url_for('changepwd'))
    return render_template('changepwd.html', form=form)


@app.route('/admin')
@admin_required
def admin():
    result = db.session.execute(db.select(User))
    users = result.scalars()
    return render_template('admin.html', users=users)


@app.route('/copyright')
def my_copyright():
    return render_template('copyright.html')


@app.route('/disclaimer')
def disclaimer():
    return render_template('disclaimer.html')


@app.route('/terms')
def terms():
    return render_template('terms.html')


@app.route('/privacy')
def privacy():
    return render_template('privacy.html')


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
        except Exception:       # noqa
            print("Couldn't create admin user.")


if __name__ == "__main__":
    app.run(debug=False)
