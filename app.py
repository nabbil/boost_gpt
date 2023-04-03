import os
from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import psycopg2
from flask_migrate import Migrate
from forms import UserForm
from forms import LoginForm
from flask_wtf import FlaskForm
from functools import wraps
from wtforms import StringField, PasswordField, SubmitField, ValidationError
from wtforms.validators import DataRequired, Email, EqualTo, Length
from flask import Flask
from flask import session
from extensions import db
from models import User
from flask import request, render_template, url_for, flash, redirect
from flask_sqlalchemy import SQLAlchemy
from models import db

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://boost_gpt:Workhard7!@localhost/boost_gpt'
migrate = Migrate(app, db)


# Initialize the database instance with the application
db.init_app(app)

# Use app.app_context() to ensure the application context is set up
with app.app_context():
    # Create the database tables
    db.create_all()

# Replace the values with your PostgreSQL database credentials
conn = psycopg2.connect(
    host="localhost",
    database="boost_gpt",
    user="boost_gpt",
    password="Workhard7!"
)

app.url_map.strict_slashes = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.secret_key = 'supersecretkey'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

class User(UserMixin, db.Model):
    __table_args__ = {'extend_existing': True}
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(200), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)  # Add this line
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)


ALLOWED_EXTENSIONS = {'csv'}

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

from wtforms import SelectField

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    role = SelectField('Role', choices=[('user', 'User'), ('admin', 'Admin')])
    submit = SubmitField('Sign Up')


    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is already taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is already taken. Please choose a different one.')

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or session.get('user_role') != 'Admin':
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

with app.app_context():
    db.create_all()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
@login_required
def home():
    users = User.query.all()
    return render_template('users.html', active='users', home_url=url_for('home'), users_url=url_for('get_users'), users=users)

@app.route('/index')
def index():
    return 'Hello, World!'

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if current_user.role.lower() != 'admin':
        flash('You do not have permission to access this feature.', 'danger')
        return redirect(url_for('home'))
    if request.method == 'POST':
        file = request.files['file']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            flash('File uploaded successfully', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid file type. Please upload a CSV file.', 'danger')

    return render_template('upload.html')

@app.route('/create_user', methods=['GET', 'POST'])
@login_required
def create_user():
    if current_user.role.lower() != 'admin':
        flash('You do not have permission to access this feature.', 'danger')
        return redirect(url_for('home'))

    form = UserForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        role = form.role.data
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('A user with that username already exists. Please choose a different username.', 'danger')
        elif not username or not password:
            flash('Please enter a valid username and password.', 'danger')
        else:
            hashed_password = generate_password_hash(password, method='sha256')
            new_user = User(username=username, password=hashed_password, role=role)
            db.session.add(new_user)
            db.session.commit()
            flash('User created successfully', 'success')
            return redirect(url_for('get_users'))
    print(f'form.errors: {form.errors}')  # Add a print statement to check form errors
    print(f'form.is_submitted(): {form.is_submitted()}')  # Add a print statement to check if the form has been submitted
    return render_template('create_user.html', active='create_user', form=form)



from flask_login import login_user, logout_user


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', title='Login', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password, role=form.role.data)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


@app.route("/logout")
@login_required
def logout():
    session.pop('user_role', None)
    logout_user()
    return redirect(url_for('login'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        existing_user = User.query.filter_by(username=username).first()
        if existing_user is None:
            hashed_password = generate_password_hash(password, method='sha256')
            user = User(username=username, password=hashed_password, role=role)
            db.session.add(user)
            db.session.commit()
            flash('User created successfully.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Username already exists.', 'danger')
    return render_template('signup.html')


@app.route('/users')
@login_required
def get_users():
    if current_user.role != 'Admin':
        return redirect(url_for('home'))

@app.route('/update_user/int:id', methods=['GET', 'POST'])
def update_user(id):
    user = User.query.get_or_404(id)
    form = UserForm(obj=user)
    if form.validate_on_submit():
        form.populate_obj(user)
        db.session.commit()
        return redirect(url_for('get_users'))
    return render_template('create_user.html', active='users', home_url=url_for('home'), users_url=url_for('get_users'), form=form)

from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, validators

class EditUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), validators.Length(min=4, max=25)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    first_name = StringField('First Name', validators=[DataRequired(), validators.Length(min=2, max=25)])
    last_name = StringField('Last Name', validators=[DataRequired(), validators.Length(min=2, max=25)])
    submit = SubmitField('Update User')
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    form = EditUserForm(obj=user)
    if form.validate_on_submit():
        user.username = form.username.data
        user.email = form.email.data
        db.session.commit()
        flash('User updated successfully!', 'success')
        return redirect(url_for('get_users'))
    return render_template('edit_user.html', form=form, user=user)

@app.route('/delete_user/int:id', methods=['POST'])
def delete_user(id):
    user = User.query.get_or_404(id)
    db.session.delete(user)
    db.session.commit()
    return redirect(url_for('get_users'))

@app.route('/about')
def about():
    return render_template('about.html', active='about')




if __name__ == '__main__':
    app.run(debug=True)