from flask_wtf import FlaskForm
from wtforms import PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo, Regexp


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
