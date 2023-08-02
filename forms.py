from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL, Email, Length
from flask_ckeditor import CKEditorField
import email_validator


##WTForm
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


class RegisterForm(FlaskForm):
    username = StringField(
        label="Username",
        validators=[
            DataRequired(),
            Length(min=4, max=18, message="Username must be between 4 to 18 characters long")
        ]
    )
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField(
        label="Password",
        validators=[
            DataRequired(),
            Length(min=8, message="Password must be at least 8 characters long.")
        ]
    )
    submit = SubmitField("Sign Up")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Sign In")


class CommentForm(FlaskForm):
    body = CKEditorField("Comment", validators=[DataRequired()])
    submit = SubmitField("Submit Comment")
