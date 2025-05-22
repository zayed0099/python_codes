import os
from flask import Flask, url_for, render_template, redirect, flash, request
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# Making a flask app instance
app = Flask(__name__)	# Declaring app as a flask instance
app.secret_key = 'hirudora'	# secret key to save app from csrf atack

# Making a LoginManager class instance. 
login_manager = LoginManager()	
# Adding that instance to the code
login_manager.init_app(app)
'''By default, when a user attempts to access a login_required view without being logged in, 
Flask-Login will flash a message and redirect them to the log in view. '''
login_manager.login_view = 'login'

# Getting the directory of the code
basedir = os.path.abspath(os.path.dirname(__file__))
# Initializing the database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Creating database table. Also added UserMixin to use it in the user_loader
class User_data(db.Model, UserMixin):
	id = db.Column(db.Integer, primary_key=True)
	email = db.Column(db.String(80), unique=True, nullable=False)
	password = db.Column(db.String(200), nullable=False) 

# Creating the db column
with app.app_context():
	db.create_all()

# Class for form
class NameForm(FlaskForm):
	email = StringField('Enter Email', validators=[DataRequired()]) 
	pass_ = PasswordField('Enter Password', validators=[DataRequired()])
	submit = SubmitField('Submit')

'''User loader to retrieve data of the user when visits other pages while logged in.
It loades data using the id column(Primary Key=true) to give to flask-login'''
@login_manager.user_loader
def load_user(user_id):
    return User_data.query.get(int(user_id)) 

# Main Route
@app.route("/home")
def home():
	return "Welcome To Website"

@app.route("/dashboard")
@login_required
def dashboard():
	return render_template("home.html")

# login function
@app.route('/login', methods=['GET', 'POST'])
def login():
	form = NameForm()

	# Get data from the form
	if request.method == 'POST':
		if form.validate_on_submit():
			email = form.email.data
			password_txt = form.pass_.data
			
			'''Check if that email exists in the db . 
			(check the email coulumn for the email provided in the variable 
			above which takes input from the form.)
			email_check is a object now. it can be used like 'email_check.id' etc'''
			email_check = User_data.query.filter_by(email=email).first()

			# Logic for logging the user
			if email_check:
				chk = check_password_hash(email_check.password, password_txt)
				if chk:
					login_user(email_check)
					return redirect(url_for('dashboard'))
				else:
					flash('An error occured! Try again.')
					return render_template('user.html', form=form)
			else:
				flash('An error occured! Try again.')
				return render_template('user.html', form=form)
						
	return render_template('user.html', form=form)

# User registration route
@app.route("/signin", methods=["POST", "GET"])
def signin():
	form = NameForm() 	# This should be outside post blk so it shows when its get request

	if request.method == "POST":
		
		if form.validate_on_submit():
		# Saving the form data into database
			email = form.email.data
			password_txt = form.pass_.data

		# Checking existing user by email
		existing_user = User_data.query.filter_by(email=email).first()

		# Checking if the user already exists
		if existing_user:
			flash('User already exists.')
			return redirect(url_for('login'))

		# If user doesnt exists.
		else:				
			# Hashing the password for better protection
			hashed_pw = generate_password_hash(password_txt)				

			# Adding new entry to the database
			new_input = User_data(email=email, password=hashed_pw)
			db.session.add(new_input)
			db.session.commit()
			return render_template("home.html")
	else:
		return render_template("user.html", form=form)

@app.route('/logout')  	# A simple function to logout user
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


if __name__ == '__main__':
	app.run(debug=True)
