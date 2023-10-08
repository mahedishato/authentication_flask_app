from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField
from wtforms.validators import DataRequired, Email, ValidationError
import base64
import bcrypt
from flask_mysqldb import MySQL

app = Flask(__name__)

# MYSQL Configaretion
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'mydatabase'
app.secret_key = 'ami mahedi'
mysql = MySQL(app)


class Register_form(FlaskForm):
    name = StringField('name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Register')


class login_form(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Register')


@app.route('/')
def index():
    return render_template('home.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = Register_form()
    if form.validate_on_submit() and request.method == 'POST':
        name = form.name.data
        email = form.email.data
        password = form.password.data

        # Generate a new salt and hash the password.
        salt = bcrypt.gensalt()
        encoded_salt = base64.b64encode(salt)

        # Check if the salt is corrupted.
        try:
            salt = base64.b64decode(encoded_salt)
        except ValueError as e:
            print(e)
            # The salt is corrupted. Generate a new salt and try again.
            salt = bcrypt.gensalt()
            encoded_salt = base64.b64encode(salt)

        # Check if the salt is long enough.
        if len(encoded_salt) < 16:
            # The salt is too short. Generate a new salt and try again.
            salt = bcrypt.gensalt()
            encoded_salt = base64.b64encode(salt)

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

        # Store the hashed password in the database.
        cursor = mysql.connection.cursor()
        cursor.execute("INSERT INTO users (name, email, password) VALUES(%s, %s, %s)", (name, email, encoded_salt))
        mysql.connection.commit()
        cursor.close()

        # Redirect the user to the login page.
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = login_form()
    if form.validate_on_submit() and request.method == 'POST':
        email = form.email.data
        password = form.password.data

        try:
            user = mysql.connection.cursor().execute("SELECT * FROM users WHERE email = %s", (email,)).fetchone()
            if user and bcrypt.checkpw(password.encode('utf-8'), user[3].encode('utf-8')):
                session['user_id'] = user[0]
                return redirect(url_for('dashbord'))
            else:
                flash('Login failed. Please check your Email and Passwprd')
                return redirect(url_for('login'))
        except Exception as e:
            flash('An error occurred while logging in. Please try again later.')
            return redirect(url_for('login'))

    return render_template('login.html', form=form)


@app.route('/dashbord')
def dashbord():
    return render_template('dashbord.html')


if __name__ == '__main__':
    app.run(debug=True)
