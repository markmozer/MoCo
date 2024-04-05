import os


class Config(object):
    SECRET_KEY = os.environ.get('SECRET_KEY')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DB_URI', "sqlite:///moco.db")
    MSAL_CLIENT_ID = os.environ.get('MSAL_CLIENT_ID')
    MSAL_TENANT_ID = os.environ.get('MSAL_TENANT_ID')
    MSAL_CLIENT_SECRET = os.environ.get('MSAL_CLIENT_SECRET')
    SECURITY_PASSWORD_SALT = os.environ.get('SECURITY_PASSWORD_SALT')
    UPN = os.environ.get('USER_PRINCIPAL_NAME')
