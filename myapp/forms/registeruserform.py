from flask_wtf import FlaskForm
from wtforms import EmailField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo, Regexp


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
