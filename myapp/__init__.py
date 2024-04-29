from flask import Flask, render_template
from flask_bootstrap import Bootstrap5
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, current_user
from sqlalchemy.orm import DeclarativeBase
from datetime import datetime, UTC
from libgravatar import Gravatar
from config import Config


class Base(DeclarativeBase):  # noqa
    pass


db = SQLAlchemy(model_class=Base)
login_manager = LoginManager()
bootstrap5 = Bootstrap5()


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    login_manager.init_app(app)
    bootstrap5.init_app(app)

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

    from myapp.routes.api import api as api_blueprint
    app.register_blueprint(api_blueprint)

    @login_manager.user_loader
    def load_user(user_id):
        return db.get_or_404(User, user_id)

    @app.errorhandler(404)
    def not_found(e):
        return render_template("404.html", error=e)

    @app.context_processor
    def inject_now():
        if current_user.is_authenticated:
            gravatar = Gravatar(current_user.username)
            img_url = gravatar.get_image()
        else:
            img_url = "https://www.gravatar.com/avatar/59235f35e4763abb0b547bd093562f6e"
        return {'now': datetime.now(UTC), 'img_url': img_url}

    return app
