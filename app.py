import os
import time
from flask import Flask, abort, request, jsonify, g, url_for,session
from flask_sqlalchemy import SQLAlchemy
from flask_httpauth import HTTPBasicAuth
import jwt
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
import bcrypt 
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired
from datetime import datetime

#Initialize variables
app = Flask(__name__)
app.config['SECRET_KEY'] = 'use a random string to construct the hash'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=1)  # Session timeout set to 20 minute


# Extensions
db = SQLAlchemy(app)
auth = HTTPBasicAuth()


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(32), index = True)
    password_hash = db.Column(db.String(64))

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
   
    # then check for username and password pair
    if not user:
        user = User.query.filter_by(username = username).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True

@app.route('/api/users/<int:id>')
def get_user(id):
    user = User.query.get(id)
    if not user:
        abort(400)
    return jsonify({'username': user.username})

@app.route('/api/register', methods=['POST'])
def register():
    username = request.json.get('username') 
    password = request.json.get('password')
    # Check for blank requests
    if username is None or password is None:
        abort(400)
    # Check for existing users
    if User.query.filter_by(username = username).first() is not None:
        abort(400)
    user = User(username = username)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    return (jsonify({'username': user.username}), 201)

# Login endpoint with session management
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Both username and password are required!'}), 400

    user = User.query.filter_by(username=username).first()

    if not user or not user.verify_password(password):  # Check hashed password
        return jsonify({'message': 'Invalid credentials!'}), 401

    # Generate a token for the authenticated user
    token = generate_token(username) 
    
    # Store the token in the session
    session['token'] = token  # Make the session permanent (20 minutes)

    return jsonify({'message': 'Logged in successfully!', 'token': token})

    

# Logout endpoint to terminate session
@app.route('/api/logout', methods=['GET'])
def logout():

    session.pop('token', None)  # Remove the token from the session
    print(session.pop('token', None))


    return jsonify({'message': 'Logged out successfully!'})


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


@app.route('/api/dothis', methods=['GET'])
@auth.login_required
def do_this():
    return jsonify({ 'message':'It is done {}'.format(g.user.username) })


if __name__ == "__main__":
    if not os.path.exists('db.sqlite'):
        db.create_all()
    app.run(debug=True)
