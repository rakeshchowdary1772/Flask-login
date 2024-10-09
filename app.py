from bson import ObjectId
from flask import Flask,render_template,request,redirect,url_for,session,flash
from pymongo import MongoClient 
from datetime import timedelta
from flask_mail import Mail, Message
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from functools import wraps
from flask import abort

import random

from flask_bcrypt import Bcrypt 



app=Flask(__name__)
app.secret_key = 'rakeshdodla'
client = MongoClient('mongodb+srv://rakeshchowdary1772:Rakesh123@cluster0.op8ms.mongodb.net/login?retryWrites=true&w=majority&appName=Cluster0') 

db = client['login'] 
bcrypt = Bcrypt(app) 
# app.permanent_session_lifetime = timedelta(minutes=20 ) 

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login_view'
login_manager.login_message = 'Please log in to access this page.'



# Flask-Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'rakeshchowdary1772@gmail.com'
app.config['MAIL_PASSWORD'] = 'aiuy awpu mfoi cyrf'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True


mail = Mail(app)



def role_required(role):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # if session.get('role')!="admin":
            if current_user.role!='admin':
                return redirect(request.referrer or url_for('index'))
            return func(*args, **kwargs)
        return wrapper
    return decorator


class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data['_id'])  # Use MongoDB's ObjectId
        self.username = user_data['username']
        self.role = user_data.get('role')
        

@login_manager.user_loader
def load_user(user_id):
    user_data = db.user.find_one({"_id": ObjectId(user_id)})  # Find user by ObjectId
    if user_data:
        return User(user_data)  # Return a User object
    return None


@app.route("/",methods=['GET'])
def index():
    return "hey BRO"
    

@app.route('/login',methods=['GET','POST'])
def login_view():
    if request.method=='POST':
        username=request.form.get('username')
        password=request.form.get('password')
        data=db.user.find_one({"username":username})
        # if data :
        #     print(data['username'])
        #     print("data found")
        # else:
        #     print("data not found ")
        if data:
            try:
                if bcrypt.check_password_hash(data['password'], password):
                    user = User(data)  # Create a User object
                    login_user(user, remember=False)   # Log the user in using Flask-Login
                    flash('Login successful!')
                    return redirect( url_for('dashboard'))
                else:
                    flash("  Invalid credentials")
                    return redirect(url_for('login_view'))
            except ValueError as ve:
                flash("Error while checking password:", ve)
                flash("Error verifying password")
                return redirect(url_for('login_view'))
        else:
            flash("  Invalid credentials")
            return redirect(url_for('login_view'))
    else:
        return render_template('login.html')

@app.route('/registration',methods=['POST','GET'])
def register():
    if request.method=='POST':
        username=request.form.get('username')
        password=request.form.get('password')
        email=request.form.get('email')
        role=request.form.get('role')
        data=db.user.find_one({"username":username})
        if data:
            flash("user already exists")
            return redirect(url_for('login_view'))
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        db.user.insert_one({"username":username,"password":hashed_password,"role":role,"email":email})
        return redirect(url_for('login_view'))
    else:
        return render_template('register.html')


@app.route('/logout')
def logout_view():
    logout_user()
    session.clear()
    # session.modified = True
    flash('you are logged out')
    return redirect(url_for('login_view'))


@app.route('/updatepassword',methods=['POST','GET'])
@login_required
@role_required('admin')
def update_password():
    if request.method=="POST":
        Old_password=request.form['old_password']
        New_password=request.form['new_password']
        # username=session.get('username')
        username=current_user.username
        print(username)
        data=db.user.find_one({"username":username})
        print(data)
        if data:
            print("yes")
        else:
            print("No")
        if data and bcrypt.check_password_hash(data['password'], Old_password):
            hashed_password = bcrypt.generate_password_hash(New_password).decode('utf-8')
            db.user.update_one(
                {'username': data['username']},  # Find the user by username
                {'$set': {'password': hashed_password}}  # Set the new hashed password
            )
            flash('Password updated successfully!')
            return redirect(url_for('dashboard'))
        else:
            flash("user not found ")
            return redirect(url_for('dashboard'))

    else:
        return render_template('update_pass.html')
    
    
# @app.route('/forgotpassword',methods=['GET','POST'])
# def forgot_password():
#     if request.method=="POST":
#         username=request.form['username']
#         New_password=request.form['new_password']
#         data=db.user.find_one({"username":username})
#         if data:
#             hashed_password = bcrypt.generate_password_hash(New_password).decode('utf-8')
#             db.user.update_one(
#                 {'username': data['username']},  # Find the user by username
#                 {'$set': {'password': hashed_password}}  # Set the new hashed password
#             )
#             return redirect(url_for('dashboard'))
#         else:
#             return "user not found"
#     else:
#         return render_template('forgot.html')



@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')
        print(email)
        user = db.user.find_one({"username": username,"email":email})
        print(user)
        if not user:
            flash("Email not found!", "error")
            return redirect(url_for('forgot_password'))

        # Generate OTP (4 or 6 digit OTP)
        otp = random.randint(1000, 9999)

        session['username'] = username
        session['email'] = email
        session['otp'] = otp

        # Send OTP email
        msg = Message('Your OTP for Password Reset', 
                    sender='rakeshchowdary1772@gmail.com', 
                    recipients=[email])
        msg.body = f'Your OTP is: {otp}'
        mail.send(msg)

        flash('OTP has been sent to your email!')
        return redirect(url_for('verify_otp'))

    return render_template('forgot_password.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        otp_input = request.form.get('otp')

        # Check OTP from session
        if 'otp' not in session:
            flash('No OTP found. Please request OTP again.')
            return redirect(url_for('forgot_password'))

        if int(otp_input) == session['otp']:
            flash('OTP verified successfully!', 'success')
            return redirect(url_for('reset_password'))

        else:
            flash('Invalid OTP. Please try again')
            return redirect(url_for('verify_otp'))

    return render_template('verify_otp.html')


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        
        username = session.get('username')
        # username=current_user.username
        if not username:
            flash('Session expired. Please try again.')
            return redirect(url_for('forgot_password'))

        # Hash the new password
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')

        # Update user's password in the database
        db.user.update_one(
            {"username": username},
            {"$set": {"password": hashed_password}}
        )

        # Clear session
        session.clear()
        

        flash('Password reset successfully!')
        return redirect(url_for('login_view'))

    return render_template('reset_password.html')


@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.is_authenticated:
        # role=session.get('role')
        role = current_user.role
        if role == "admin":
            return render_template('admin_dashboard.html')
        else:
            return render_template('user_dashboard.html')
    else:
        flash("You are not logged in.")
        return redirect(url_for('login_view'))


if __name__ == '__main__':
    app.run(debug=True)