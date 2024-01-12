import os
import time
from flask import Flask, abort, request, jsonify, g, url_for,session
from flask_login import LoginManager, current_user, login_user, logout_user, login_required, UserMixin
from flask_sqlalchemy import SQLAlchemy
from flask_httpauth import HTTPBasicAuth
import jwt
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
import bcrypt 
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired
from datetime import datetime
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
import random
import string
#Initialize variables
app = Flask(__name__)
app.config['SECRET_KEY'] = 'use a random string to construct the hash'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=1)  # Session timeout set to 20 minute

app.config['MAIL_SERVER']='sandbox.smtp.mailtrap.io'
app.config['MAIL_PORT'] = 2525
app.config['MAIL_USERNAME'] = 'be0a6c784846e6'
app.config['MAIL_PASSWORD'] = 'b03e20aa793568'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False


mail = Mail(app)
s = URLSafeTimedSerializer('Thisisasecret!')
# Extensions
db = SQLAlchemy(app)
auth = HTTPBasicAuth()

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
        # since the user_id is just the primary key of our user table, use it in the query for the user
        return User.query.get(int(user_id))

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(32), index = True)
    password_hash = db.Column(db.String(64))
    email = db.Column(db.String(100), nullable=False)
    is_verified = db.Column(db.Boolean, nullable=False, default=False)

    def is_active(self):
        return True

    def is_authenticated(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id

    def hash_password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def generate_auth_token(self, expires_in = 5):
        return jwt.encode(
            { 'id': self.id, 'exp': time.time() + expires_in }, 
            app.config['SECRET_KEY'], algorithm='HS256')
    

    @staticmethod
    def verify_auth_token(token):
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'],
            algorithm=['HS256'])
        except:
            return 
        return User.query.get(data['id'])



def generate_token(username):
        s = Serializer(app.config['SECRET_KEY'], expires_in=500)  # Token expires in 1 hour
        return s.dumps({"username": username}).decode("utf-8")

@auth.verify_password
def verify_password(username,password):

    user = User.verify_auth_token(username)
    # then check for username and password pair
    if not user:
        user = User.query.filter_by(username = username).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True

def generate_registration_code():
    timestamp = str(int(time.time()))
    random_chars = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    return f"NITDA-{timestamp}-{random_chars}"

@app.route('/api/users/<int:id>')
def get_user(id):
    user = User.query.get(id)
    if not user:
        abort(400)
    return jsonify({'username': user.username})


@app.route('/get_all_users', methods=['GET'])
@login_required
def get_all_users():
    users = User.query.order_by(User.id).all()
    data = {'User': [users.username for users in users]}
    return jsonify(data)

@app.route('/reset_password_email', methods=['POST'])
def reset_password_email():
    email = request.json.get('email')
    if email is None:
        abort(400)
    user = User.query.filter_by(email=email).first()
    if user is None:
        abort(404)
    token = s.dumps(email, salt='reset-password')
    link = f"http://127.0.0.1:5000/reset_password/{token}"
    print(link)
    msg = Message('Password Reset', sender='certificate@nitda.gov.ng', recipients=[email])
    msg.body = 'Your password reset link is {}'.format(link)
    mail.send(msg)
    return jsonify({'message': 'A password reset link has been sent.'})


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):

    if request.method == 'POST':
        password = request.json.get('password')
        confirm_password = request.json.get('confirm_password')
        if password != confirm_password:
            return jsonify({'error': "Passwords do not match."}), 400
        email = s.loads(token, salt="reset-password")
        user = User.query.filter_by(email=email).first()
        user.hash_password(password)
        db.session.commit()
        return jsonify({'message': 'Password Reset successfully'})
    try:
        email = s.loads(token, salt='reset-password', max_age=300)
    except SignatureExpired:
        return 'The confirmation link has expired.'
    return 'Done'

@app.route('/send_token_email', methods=['POST'])
def send_token_email():
    email = request.json.get('email')
    if email is None:
        abort(400)
    user = User.query.filter_by(email=email).first()
    if user is None:
        abort(404)
    token = s.dumps(email, salt='email-confirm')
    link = f"http://127.0.0.1:5000/confirm_email/{token}"
    print(link)
    msg = Message('Token Resend', sender='certificate@nitda.gov.ng', recipients=[email])
    msg.body = 'Your token reset link is {}'.format(link)
    mail.send(msg)
    return jsonify({'message': 'A new token has been sent.'})


@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=300)
    except SignatureExpired:
        return 'The confirmation link has expired.'
    user = User.query.filter_by(email=email).first()
    user.is_verified= True
    db.session.commit()
    return 'Done'

@app.route('/api/register', methods=['POST'])
def register():
    username = generate_registration_code() 
    password = request.json.get('password')
    confirm_password = request.json.get('confirm_password')
    email = request.json.get('email')
    # Check for blank requests
    if username is None or password is None or confirm_password is None:
        abort(400, 'Cannot be blank')
        # Check that passwords match
    if password != confirm_password:
        abort(400, 'The password did not match')
    # Check for existing users
    if User.query.filter_by(email = email).first() is not None:
        abort(400, 'User exists')
    user = User(username = username, email=email)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()

    token = s.dumps(email, salt='email-confirm')
    link = f"http://127.0.0.1:5000/confirm_email/{token}"
    print(link)
    msg = Message('Confirm Email', sender='certificate@nitda.gov.ng', recipients=[email])
    msg.body = 'Your verification link is {}'.format(link)
    mail.send(msg)
    #if send_activation_email(username, email):
    #    return jsonify({'status':'ok','message':'Activation mail sent.'}), 2
    #else:
    #    return jsonify({'status':'error','message':'Registration failed!'}), 50

    return (jsonify({'username': user.email}), 201)

# Login endpoint with session management
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    user = User.query.filter_by(email=email).first()

    if ((user != None) and (user.is_verified ==1) and (user.email ==email) and (user.verify_password(password))):  # Check hashed password
        token = generate_token(email)
        #session['token'] = token
        login_user(user)
        print(current_user.username)
        return jsonify({'message': 'Logged in successfully!'})

    # Generate a token for the authenticated user
     
    
    # Store the token in the session
      # Make the session permanent (20 minutes)
    return jsonify({'message': 'Invalid credentials!'}), 401

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logged out successfully!'})



@app.route('/api/change_password', methods=['PUT'])
@login_required
def change_password():
    data = request.get_json()
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    if not current_password or not new_password:
        return jsonify({'message': 'Both current and new passwords are required.'}), 400
    
    #user = current_user.id
    if not check_password_hash(current_user.password_hash, current_password):
        return jsonify({'message': 'Current password is incorrect.'}), 401

    current_user.hash_password(new_password)
    db.session.commit()

    return jsonify({'message': 'Password changed successfully.'})

# Logout endpoint to terminate session
#@app.route('/api/logout', methods=['GET'])
#def logout():

#    session.pop('token', None)  # Remove the token from the session
#   print(session.pop('token', None))


#    return jsonify({'message': 'Logged out successfully!'})


@app.route('/api/check-token', methods=['POST'])
def check_token():
    data = request.get_json()
    token = data.get('token')

    if not token:
        return jsonify({'message': 'Token is required!'}), 400

    try:
        s = Serializer(app.config['SECRET_KEY'])
        # Decode the token without verifying
        data = s.loads(token, return_header=True)
        
        # Extract the token's expiration time from its header
        expiration_time = data[1]['exp']

        # Get the current time
        current_time = datetime.utcnow()

        # Check if the token has expired
        if expiration_time < current_time.timestamp():
            return jsonify({'message': 'Token has expired!', 'expired': True})
        else:
            return jsonify({'message': 'Token is valid!', 'expired': False})

    except SignatureExpired:
        return jsonify({'message': 'Token has expired!', 'expired': True}), 401
    except BadSignature:
        return jsonify({'message': 'Invalid token!', 'expired': True}), 401


#@app.route('/api/login')
#@auth.login_required
#def get_token():

#    token = g.user.generate_auth_token(600)
#    return jsonify({ 'token': token.encode().decode('ascii'), 'duration': 600, 'user': g.user.username })




@app.route('/api/dothis', methods=['GET'])
@login_required
def do_this():
    print(current_user.username)
    return jsonify({'user': current_user.username })


    

if __name__ == "__main__":
    if not os.path.exists('db.sqlite'):
        db.create_all()
    app.run(debug=True)
