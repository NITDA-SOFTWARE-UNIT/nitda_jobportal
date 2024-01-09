import os
import time
from flask import Flask, abort, request, jsonify, g, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_httpauth import HTTPBasicAuth
import jwt
from werkzeug.security import generate_password_hash, check_password_hash
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


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(32), index = True)
    password_hash = db.Column(db.String(64))
    email = db.Column(db.String(100), nullable=False)
    is_verified = db.Column(db.Boolean, nullable=False, default=False)

    def hash_password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def generate_auth_token(self, expires_in = 600):
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

@auth.verify_password
def verify_password(username_or_token, password):
    # first try token
    user = User.verify_auth_token(username_or_token)
    # then check for username and password pair
    if not user:
        user = User.query.filter_by(username = username_or_token).first()
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


@app.route('/api/login')
@auth.login_required
def get_token():

    token = g.user.generate_auth_token(600)
    return jsonify({ 'token': token.encode().decode('ascii'), 'duration': 600, 'user': g.user.username })




@app.route('/api/dothis', methods=['GET'])
@auth.login_required
def do_this():
    return jsonify({ 'message':'It is done {}'.format(g.user.username) })


if __name__ == "__main__":
    if not os.path.exists('db.sqlite'):
        db.create_all()
    app.run(debug=True)
