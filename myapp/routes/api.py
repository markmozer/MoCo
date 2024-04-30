from myapp import db
from myapp.models.user import User                                      # noqa
from myapp.forms.registeruserform import RegisterUserForm               # noqa
from myapp.forms.loginuserform import LoginUserForm                     # noqa
from myapp.forms.chgcontactdetailsform import ChgContactDetailsForm     # noqa
from myapp.forms.chgpasswordform import ChgPasswordForm                 # noqa
from myapp.website.forms.contactform import ContactForm                         # noqa
from myapp.msgraphapi import MSGraphAPI                                 # noqa
from myapp.check_token import generate_token, confirm_token             # noqa

from datetime import datetime
from flask import flash, render_template, redirect, request, url_for, Blueprint
from flask_login import login_user, current_user, logout_user, login_required
from config import Config
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

api = Blueprint('api', __name__)


def admin_required(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash("You are not authorized for this page.", 'error')
            return redirect(url_for('api.home'))
        return func(*args, **kwargs)

    return decorated_function


def logout_required(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated:
            flash("You are already authenticated.", 'info')
            return redirect(url_for('api.home'))
        return func(*args, **kwargs)

    return decorated_function


# Routes
@api.route("/", methods=['GET', 'POST'])
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
        flash("Your message has been sent successfully!", 'success')
        return redirect(url_for('api.home') + "#top")
    return render_template('index.html', form=form)


@api.route("/register", methods=['GET', 'POST'])
@logout_required
def register():
    form = RegisterUserForm()
    if form.validate_on_submit():
        # Check if username already exists in the database
        result = db.session.execute(db.select(User).where(User.username == form.username.data))
        user = result.scalar()
        if user:
            flash('Username is already registered! Please login', 'info')
            return redirect(url_for('api.login'))
        # Add new user to the database
        new_user = User(
            username=form.data.get('username'),
            password=form.data.get('password'),
        )
        db.session.add(new_user)
        db.session.commit()

        token = generate_token(new_user.username)
        confirm_url = url_for('api.confirm_email', token=token, _external=True)
        html = render_template("confirm_email.html", confirm_url=confirm_url)
        subject = "Please confirm your email"

        mail_api = MSGraphAPI()
        mail_api.send_email(subject=subject, body=html, to_recipients=[new_user.username])

        login_user(new_user)

        flash(f'A confirmation email has been sent to {new_user.username}.', 'success')

        return redirect(url_for('api.inactive'))
    return render_template('register.html', form=form)


@api.route("/inactive")
@login_required
def inactive():
    if current_user.is_confirmed:
        return redirect(url_for('api.home'))
    return render_template('inactive.html')


@api.route("/resend")
@login_required
def resend_confirmation():
    if current_user.is_confirmed:
        flash("Your account has already been confirmed.", 'success')
        return redirect(url_for('api.home'))
    token = generate_token(current_user.username)
    confirm_url = url_for('api.confirm_email', token=token, _external=True)
    html = render_template("confirm_email.html", confirm_url=confirm_url)
    subject = "Please confirm your email"

    mail_api = MSGraphAPI()
    mail_api.send_email(subject=subject, body=html, to_recipients=[current_user.username])

    flash(f'A new confirmation email has been sent to {current_user.username}.', 'success')
    return redirect(url_for('api.inactive'))


@api.route("/confirm/<token>")
def confirm_email(token):
    email = confirm_token(token)
    result = db.session.execute(db.select(User).where(User.username == email))
    user = result.scalar()
    if not user:
        flash("The confirmation link is invalid or has expired.", 'danger')
        return redirect(url_for('api.home'))
    if user.is_confirmed:
        flash("Account already confirmed.", 'success')
        return redirect(url_for('api.home'))
    user.is_confirmed = True
    user.confirmed_on = datetime.now()
    db.session.add(user)
    db.session.commit()
    flash("You have confirmed your account. Thanks!", 'success')
    return redirect(url_for('api.home'))


@api.errorhandler(401)
def not_found(e):
    return render_template("401.html", error=e)


@api.route("/login", methods=['GET', 'POST'])
@logout_required
def login():
    form = LoginUserForm()
    if form.validate_on_submit():
        # Check if user is already registered
        result = db.session.execute(db.select(User).where(User.username == form.username.data))
        user = result.scalar()
        if not user:
            flash(f'User {form.username.data} is not registered! Try again or proceed to registration.', 'warning')
            return redirect(url_for('api.login'))
        # Check if provided password is correct
        if not check_password_hash(user.password, form.password.data):
            flash("The password you've entered is incorrect! Please try again", 'warning')
            return redirect(url_for('api.login'))
        login_user(user)
        return redirect(url_for('api.home'))
    return render_template('login.html', form=form)


@api.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('api.home'))


@api.route("/profile", methods=['GET', 'POST'])
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
        flash("Contact details updated", 'success')
        redirect(url_for('api.profile'))

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


@api.route("/changepwd", methods=['GET', 'POST'])
@login_required
def changepwd():
    form = ChgPasswordForm()
    if form.validate_on_submit():
        # Handle Form2 submission
        if not check_password_hash(current_user.password, form.old_password.data):
            flash("The old password you've entered is incorrect! Please try again", 'warning')
        else:
            # Hash and salt the password
            hash_and_salted_password = generate_password_hash(
                form.password.data,
                method='pbkdf2:sha256',
                salt_length=8
            )

            current_user.password = hash_and_salted_password
            db.session.commit()
            flash("Your password is changed!", 'success')
        return redirect(url_for('api.changepwd'))
    return render_template('changepwd.html', form=form)


@api.route('/admin')
@admin_required
def admin():
    result = db.session.execute(db.select(User))
    users = result.scalars()
    return render_template('admin.html', users=users)


@api.route('/user/change/<int:id>', methods=['GET', 'POST'])
@admin_required
def change_user(id: int):
    result = db.session.execute(db.select(User).where(User.id == id))
    user = result.scalar()
    if not user:
        flash('This ID is not valid!', category='error')
        return redirect(url_for('api.admin'))

    form = ChgContactDetailsForm()
    if form.validate_on_submit():
        # Handle Form submission
        user.firstname = form.firstname.data
        user.lastname = form.lastname.data
        user.mobile = form.mobile.data
        user.date_of_birth = form.date_of_birth.data
        user.gender = form.gender.data
        db.session.commit()
        flash("Contact details updated", 'success')
        return redirect(url_for('api.admin'))

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


@api.route('/user/delete/<int:id>', methods=['GET', 'POST'])
@admin_required
def delete_user(id: int):
    result = db.session.execute(db.select(User).where(User.id == id))
    user = result.scalar()
    if not user:
        flash('This ID is not valid!', category='error')
    else:
        db.session.delete(user)
        db.session.commit()
        flash(f'User {user.id} was deleted!', category='success')
    return redirect(url_for('api.admin'))


@api.route('/copyright')
def my_copyright():
    return render_template('copyright.html')


@api.route('/disclaimer')
def disclaimer():
    return render_template('disclaimer.html')


@api.route('/terms')
def terms():
    return render_template('terms.html')


@api.route('/privacy')
def privacy():
    return render_template('privacy.html')
