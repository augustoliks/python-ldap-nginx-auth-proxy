from flask_wtf import (
    FlaskForm,
    RecaptchaField
)
from wtforms import (
    PasswordField,
    StringField,
    SubmitField,
    HiddenField
)
from wtforms.validators import (
    DataRequired,
    Email
)


class LoginForm(FlaskForm):
    target = HiddenField("target")
    email = StringField(
        "Email", [
            Email(message="Not a valid email address."), DataRequired()
        ]
    )
    password = PasswordField(
        "Password",
        [
            DataRequired(message="Please enter a password."),
        ],
    )
    recaptcha = RecaptchaField()
    submit = SubmitField("Submit")
