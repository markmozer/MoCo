from datetime import datetime, UTC
from flask import Flask, flash, render_template, redirect, request, url_for
from flask_bootstrap import Bootstrap5
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
from sqlalchemy.orm import DeclarativeBase
from config import Config
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

from myapp.models.user import User                                      # noqa
from myapp.forms.registeruserform import RegisterUserForm               # noqa
from myapp.forms.loginuserform import LoginUserForm                     # noqa
from myapp.forms.chgcontactdetailsform import ChgContactDetailsForm     # noqa
from myapp.forms.chgpasswordform import ChgPasswordForm                 # noqa
from myapp.forms.contactform import ContactForm                         # noqa
from myapp.msgraphapi import MSGraphAPI                                 # noqa
from myapp.check_token import generate_token, confirm_token             # noqa

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


@app.route('/user/change/<int:id>', methods=['GET', 'POST'])
@admin_required
def change_user(id: int):
    result = db.session.execute(db.select(User).where(User.id == id))
    user = result.scalar()
    if not user:
        flash('This ID is not valid!', category='error')
        return redirect(url_for('admin'))

    form = ChgContactDetailsForm()
    if form.validate_on_submit():
        # Handle Form submission
        user.firstname = form.firstname.data
        user.lastname = form.lastname.data
        user.mobile = form.mobile.data
        user.date_of_birth = form.date_of_birth.data
        user.gender = form.gender.data
        db.session.commit()
        flash("Contact details updated", "success")
        return redirect(url_for('admin'))

    form.username.data = user.username
    form.firstname.data = user.firstname
    form.lastname.data = user.lastname
    form.date_of_birth.data = user.date_of_birth
    form.mobile.data = user.mobile
    if user.gender is None:
        form.gender.data = 'Unspecified'
    else:
        form.gender.data = user.gender

    return render_template('change_user.html', form=form)


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
    app.run(debug=True)
