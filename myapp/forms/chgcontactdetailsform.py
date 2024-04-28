from flask_wtf import FlaskForm
from wtforms import StringField, EmailField, SubmitField, DateField, SelectField
from wtforms.validators import DataRequired, Regexp


class ChgContactDetailsForm(FlaskForm):
    username = EmailField("Username (e-mail)", render_kw={'readonly': True, 'class': 'disabled-field'}, validators=[])
    firstname = StringField("Firstname", validators=[DataRequired()])
    lastname = StringField("Lastname", validators=[DataRequired()])
    mobile = StringField("Mobile number +#(#)#",
                         validators=[Regexp(r"^\+[0-9]+\([0-9]+\)[0-9]+$", message="Regex message!")])
    date_of_birth = DateField("Date of birth", validators=[])
    gender = SelectField(u'Gender', choices=[('M', 'Male'), ('F', 'Female'), ('U', 'Unspecified')])
    submit1 = SubmitField("Save changes")
