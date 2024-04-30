from flask import Flask, render_template
from flask_bootstrap import Bootstrap5
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from sqlalchemy.orm import DeclarativeBase
from datetime import datetime, UTC
from config import Config
from myapp.msgraphapi import MSGraphAPI
from myapp.check_token import generate_token, confirm_token

class Base(DeclarativeBase):  # noqa
    pass


db = SQLAlchemy(model_class=Base)
login_manager = LoginManager()
bootstrap5 = Bootstrap5()


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    bootstrap5.init_app(app)

    with app.app_context():
        db.create_all()

    from myapp.website.routes import website_bp
    app.register_blueprint(website_bp, url_prefix=None)

    # Register CLI command
    register_cli_commands(app)

    @app.errorhandler(404)
    def not_found(e):
        return render_template("404.html", error=e)

    @app.context_processor
    def inject_now():
        img_url = "https://www.gravatar.com/avatar/59235f35e4763abb0b547bd093562f6e"
        return {'now': datetime.now(UTC), 'img_url': img_url}

    return app


def register_cli_commands(app):
    @app.cli.command('create_admin')
    def create_admin():
        print("Hello world!")
