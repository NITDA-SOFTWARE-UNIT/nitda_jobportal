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


class Contact(UserMixin, db.Model):
    __tablename__ = 'contacts'
    id = db.Column(db.Integer, primary_key = True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    email = db.Column(db.String(100), nullable=False)
    address = db.Column(db.String(500), nullable=False)
    city = db.Column(db.String(100), nullable=False)
    PostalCode = db.Column(db.String(100), nullable=True)
    TelephoneNo = db.Column(db.String(100), nullable=False)
    Ename = db.Column(db.String(100), nullable=False)
    Eemail = db.Column(db.String(100), nullable=False)
    Etelephone = db.Column(db.String(100), nullable=False)
    Erelationship = db.Column(db.String(100), nullable=False)

#with app.app_context():
#    db.create_all()

    def is_active(self):
        return True

    def is_authenticated(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id

class WorkExperience(UserMixin, db.Model):
    __tablename__ = 'workexperience'
    id = db.Column(db.Integer, primary_key = True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    CompanyName = db.Column(db.String(100), nullable=False)
    Sector = db.Column(db.String(100), nullable=False)
    Occupation = db.Column(db.String(100), nullable=False)
    FromDate = db.Column(db.String(100), nullable=False)
    ToDate = db.Column(db.String(100), nullable=False)
    CurrentlyEmployed = db.Column(db.Boolean, nullable=False, default=False)
    ReasonForLeaving = db.Column(db.String(500), nullable=False)

#with app.app_context():
#    db.create_all()

    def is_active(self):
        return True

    def is_authenticated(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id

class Publication(UserMixin, db.Model):
    __tablename__ = 'publications'
    id = db.Column(db.Integer, primary_key = True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    NameOfPublication = db.Column(db.String(100), nullable=False)
    ProofOfPublication = db.Column(db.String(500), nullable=False)


#with app.app_context():
#    db.create_all()

    def is_active(self):
        return True

    def is_authenticated(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id

class Reference(UserMixin, db.Model):
    __tablename__ = 'references'
    id = db.Column(db.Integer, primary_key = True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    Rname = db.Column(db.String(100), nullable=False)
    Designation = db.Column(db.String(100), nullable=False)
    Telephone = db.Column(db.String(100), nullable=False)
    Relationship = db.Column(db.String(100), nullable=False)
    Organization = db.Column(db.String(100), nullable=False)
    Email = db.Column(db.String(100), nullable=False)
    Address = db.Column(db.String(100), nullable=False)
    ReferenceLetter = db.Column(db.String(200), nullable=False)


#with app.app_context():
#    db.create_all()

    def is_active(self):
        return True

    def is_authenticated(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id



class Verification(UserMixin, db.Model):
    __tablename__ = 'verification'
    id = db.Column(db.Integer, primary_key = True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    LevelOfEdu = db.Column(db.String(100), nullable=False)
    UniversityName = db.Column(db.String(100), nullable=False)
    ProgramOfStudy = db.Column(db.String(100), nullable=False)
    AwardedDegree = db.Column(db.String(100), nullable=False)
    Country = db.Column(db.String(100), nullable=False)
    ClassOfDegree = db.Column(db.String(100), nullable=False)
    AwardIssueDate = db.Column(db.String(100), nullable=False)
    QualificationDoc = db.Column(db.String(100), nullable=False)


#with app.app_context():
#    db.create_all()

    def is_active(self):
        return True

    def is_authenticated(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id   


class Documents(UserMixin, db.Model):
    __tablename__ = 'documents'
    id = db.Column(db.Integer, primary_key = True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    CV = db.Column(db.String(100), nullable=False)


#with app.app_context():
#    db.create_all()

    def is_active(self):
        return True

    def is_authenticated(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id   



class Coverletter(UserMixin, db.Model):
    __tablename__ = 'coverletter'
    id = db.Column(db.Integer, primary_key = True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    CoverLetter = db.Column(db.String(100), nullable=False)
    CLetter = db.Column(db.String(100), nullable=True)


#with app.app_context():
#    db.create_all()

    def is_active(self):
        return True

    def is_authenticated(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id   
    

    

class Education(UserMixin, db.Model):
    __tablename__ = 'education'
    id = db.Column(db.Integer, primary_key = True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    LevelOfEdu = db.Column(db.String(100), nullable=False)
    UniversityName = db.Column(db.String(100), nullable=False)
    ProgramOfStudy = db.Column(db.String(100), nullable=False)
    AwardedDegree = db.Column(db.String(100), nullable=False)
    Country = db.Column(db.String(100), nullable=False)
    ClassOfDegree = db.Column(db.String(100), nullable=False)
    AwardIssueDate = db.Column(db.String(100), nullable=False)
    Transcript = db.Column(db.String(100), nullable=False)
    Certificate =db.Column(db.String(100), nullable=False)


#with app.app_context():
#    db.create_all()

    def is_active(self):
        return True

    def is_authenticated(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id        

class Profile(UserMixin, db.Model):
    __tablename__ = 'profile'
    id = db.Column(db.Integer, primary_key = True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    FirstName = db.Column(db.String(100), nullable=False)
    MiddleName = db.Column(db.String(100), nullable=False)
    FamilyName = db.Column(db.String(100), nullable=False)
    PreviousFamilyName = db.Column(db.String(100), nullable=True)
    Gender = db.Column(db.String(100), nullable=False)
    NIN = db.Column(db.String(100), nullable=False)
    DOB = db.Column(db.String(100), nullable=False)
    POB = db.Column(db.String(100), nullable=False)
    StateOfOrigin = db.Column(db.String(100), nullable=False)
    LGA = db.Column(db.String(100), nullable=False)
    Photos = db.Column(db.String(200), nullable=False)

#with app.app_context():
#    db.create_all()

    def is_active(self):
        return True

    def is_authenticated(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id        

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(32), index = True)
    password_hash = db.Column(db.String(64))
    email = db.Column(db.String(100), nullable=False)
    is_verified = db.Column(db.Boolean, nullable=False, default=False)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    #applications = db.relationship('Application', backref='user')

#with app.app_context():
#    db.create_all()

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

class Application(UserMixin, db.Model):
    __tablename__ = 'applications'
    id = db.Column(db.Integer, primary_key = True)
    role_id = db.Column(db.Integer, db.ForeignKey('jobroles.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    app_status = db.Column(db.Boolean, nullable=False, default=False)

#with app.app_context():
#    db.create_all()

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


class Role(UserMixin, db.Model):
    __tablename__ = 'jobroles'
    id = db.Column(db.Integer, primary_key = True)
    role_name = db.Column(db.String(100),nullable=False)
    role_status =  db.Column(db.Boolean, nullable=False, default=False)

#with app.app_context():
 #   db.create_all()

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

def save_publication(file):
    if file:
        user = User.query.filter_by(id=current_user.id).first()
        file_path = f"C:/Users/Maryam Ibrahim Magam/nitda_jobportal/publications/{user.username+file.filename}"
        file.save(file_path)
        return file_path
    return None

def save_reference(file):
    if file:
        user = User.query.filter_by(id=current_user.id).first()
        file_path = f"C:/Users/Maryam Ibrahim Magam/nitda_jobportal/references/{user.username+file.filename}"
        file.save(file_path)
        return file_path
    return None

@app.route('/api/submit/<int:id>', methods=['GET'])
@login_required
def submit(id):
    user_id = current_user.id

    # Retrieve the profile information for the current user
    profile_exists = Profile.query.filter_by(user_id=user_id).first() 
    education_exists=Education.query.filter_by(user_id=user_id).first() 
    coverletter_exists=Coverletter.query.filter_by(user_id=user_id).first()
    documents_exists=Documents.query.filter_by(user_id=user_id).first() 
    contact_exists=Contact.query.filter_by(user_id=user_id).first() 
    workexperience_exists=WorkExperience.query.filter_by(user_id=user_id).first()
    publication_exists=Publication.query.filter_by(user_id=user_id).first()
    application=Application.query.filter_by(id=id,user_id=user_id).first()

    if application:
        # If application exists
        if (profile_exists and education_exists and coverletter_exists and documents_exists and contact_exists and publication_exists ) or workexperience_exists:
            application.app_status = True
            db.session.commit()
            return jsonify({'message' : 'Application completed'})
        else:
            application.app_status = False
            db.session.commit()
            return jsonify({'message' : 'Application incomplete'})
        # If no profile exists, return a message indicating no profile is found
        
    return jsonify({'message': 'Application doesnt exist for user'})


@app.route('/api/verification', methods=['GET'])
@login_required
def get_profile():
    user_id = current_user.id

    # Retrieve the profile information for the current user
    user_profile = Profile.query.filter_by(user_id=user_id).first()

    if user_profile:
        # If a profile exists, return the profile information
        profile_data = {
            'FirstName': user_profile.FirstName,
            'MiddleName': user_profile.MiddleName,
            'FamilyName': user_profile.FamilyName,
            'PreviousFamilyName': user_profile.PreviousFamilyName,
            'Gender': user_profile.Gender,
            'NIN': user_profile.NIN,
            'DOB': user_profile.DOB,
            'POB': user_profile.POB,
            'StateOfOrigin': user_profile.StateOfOrigin,
            'LGA': user_profile.LGA,
            'Photos': user_profile.Photos
        }
        return jsonify(profile_data)
    else:
        # If no profile exists, return a message indicating no profile is found
        return jsonify({'message': 'No profile found for the current user'}), 404


@app.route('/api/contact', methods=['POST'])
@login_required
def contact():
    if request.method == 'POST':
        data = request.json

        # Extracting data from the JSON request with default values if keys are not present
        address = data.get('address', '')
        city = data.get('city', '')
        PostalCode = data.get('PostalCode', '')
        TelephoneNo = data.get('TelephoneNo', '')
        Ename = data.get('Ename', '')
        Eemail = data.get('Eemail', '')
        Etelephone = data.get('Etelephone', '')
        Erelationship = data.get('Erelationship', '')

        # Retrieving the current user
        user = User.query.get(current_user.id)
        if user:
            # Check for existing contact with the same email
            existing_contact = Contact.query.filter_by(user_id=user.id).first()

            if existing_contact:
                # If contact with the same email exists, update the existing contact
                existing_contact.address = address
                existing_contact.city = city
                existing_contact.PostalCode = PostalCode
                existing_contact.TelephoneNo = TelephoneNo
                existing_contact.Ename = Ename
                existing_contact.Eemail=Eemail
                existing_contact.Etelephone = Etelephone
                existing_contact.Erelationship = Erelationship

                db.session.commit()
                return jsonify({'message': 'Contact updated successfully!'})
            else:
                # If no existing contact, create a new contact
                new_contact = Contact(
                    user_id=user.id,
                    email=user.email,
                    address=address,
                    city=city,
                    PostalCode=PostalCode,
                    TelephoneNo=TelephoneNo,
                    Ename=Ename,
                    Eemail=Eemail,
                    Etelephone=Etelephone,
                    Erelationship=Erelationship
                )

                db.session.add(new_contact)
                db.session.commit()
                return jsonify({'message': 'Contact created successfully!'})

    return jsonify({'message': 'Invalid request'})

@app.route('/api/work_experience', methods=['POST'])
@login_required
def work_experience():
    if request.method == 'POST':
        data = request.json

        # Extracting data from the JSON request with default values if keys are not present
        CompanyName = data.get('CompanyName', '')
        Sector = data.get('Sector', '')
        Occupation = data.get('Occupation', '')
        FromDate = data.get('FromDate', '')
        ToDate = data.get('ToDate', '')
        CurrentlyEmployed = data.get('CurrentlyEmployed', False)
        ReasonForLeaving = data.get('ReasonForLeaving', '')

        # Retrieving the current user
        user_id = current_user.id

        # Check for existing work experience with the same CompanyName and Occupation
        existing_work_experience = WorkExperience.query.filter_by(
            user_id=user_id,
            #CompanyName=CompanyName,
            #Occupation=Occupation
        ).first()

        if existing_work_experience:
            # If work experience with the same CompanyName and Occupation exists, update the existing entry
            existing_work_experience.CompanyName = CompanyName
            existing_work_experience.Occupation = Occupation
            existing_work_experience.Sector = Sector
            existing_work_experience.FromDate = FromDate
            existing_work_experience.ToDate = ToDate
            existing_work_experience.CurrentlyEmployed = CurrentlyEmployed
            existing_work_experience.ReasonForLeaving = ReasonForLeaving

            db.session.commit()
            return jsonify({'message': 'Work Experience updated successfully!'})
        else:
            # If no existing work experience, create a new entry
            new_work_experience = WorkExperience(
                user_id=user_id,
                CompanyName=CompanyName,
                Sector=Sector,
                Occupation=Occupation,
                FromDate=FromDate,
                ToDate=ToDate,
                CurrentlyEmployed=CurrentlyEmployed,
                ReasonForLeaving=ReasonForLeaving
            )

            db.session.add(new_work_experience)
            db.session.commit()
            return jsonify({'message': 'Work Experience created successfully!'})

    return jsonify({'message': 'Invalid request'})



@app.route('/api/publication', methods=['POST'])
@login_required
def publication():
    if request.method == 'POST':
        data = request.form
        NameOfPublication = data.get('NameOfPublication')
        ProofOfPublication = request.files.get('ProofOfPublication')

        # Retrieve the current user
        user = User.query.filter_by(id=current_user.id).first()

        # Handle file upload
        publication_path = save_publication(ProofOfPublication)

        # Check for an existing publication with the same NameOfPublication
        existing_publication = Publication.query.filter_by(
            user_id=user.id,
            NameOfPublication=NameOfPublication
        ).first()

        if existing_publication:
            # If publication with the same NameOfPublication exists, update the existing entry
            existing_publication.ProofOfPublication = publication_path
            db.session.commit()
            return jsonify({'message': 'Publication updated successfully!'})
        else:
            # If no existing publication, create a new entry
            new_publication = Publication(
                user_id=user.id,
                NameOfPublication=NameOfPublication,
                ProofOfPublication=publication_path
            )

            db.session.add(new_publication)
            db.session.commit()
            return jsonify({'message': 'Publication created successfully!'})

    return jsonify({'message': 'Invalid request'})

@app.route('/api/reference', methods=['POST'])
@login_required
def reference():
    if request.method == 'POST':
        data = request.form
        Rname = data.get('Rname')
        Designation = data.get('Designation')
        Telephone = data.get('Telephone')
        Relationship = data.get('Relationship')
        Organization = data.get('Organization')
        Email = data.get('Email')
        Address = data.get('Address')
        ReferenceLetter = request.files.get('ReferenceLetter')

        # Retrieve the current user
        user = User.query.filter_by(id=current_user.id).first()

        # Handle file upload
        reference_path = save_reference(ReferenceLetter)

        # Check for an existing reference with the same Rname and Email
        existing_reference = Reference.query.filter_by(
            user_id=user.id,
            Rname=Rname,
            Email=Email
        ).first()

        if existing_reference:
            # If reference with the same Rname and Email exists, update the existing entry
            existing_reference.Designation = Designation
            existing_reference.Telephone = Telephone
            existing_reference.Relationship = Relationship
            existing_reference.Organization = Organization
            existing_reference.Address = Address
            existing_reference.ReferenceLetter = reference_path
            db.session.commit()
            return jsonify({'message': 'Reference updated successfully!'})
        else:
            # If no existing reference, create a new entry
            new_reference = Reference(
                user_id=user.id,
                Rname=Rname,
                Designation=Designation,
                Telephone=Telephone,
                Relationship=Relationship,
                Organization=Organization,
                Email=Email,
                Address=Address,
                ReferenceLetter=reference_path
            )

            db.session.add(new_reference)
            db.session.commit()
            return jsonify({'message': 'Reference created successfully!'})

    return jsonify({'message': 'Invalid request'})



@app.route('/api/profile',methods=['GET','POST'])
@login_required
def profile():
    if request.method == 'POST':
        data = request.form
        user_id = current_user.id

        # Check if the user already has a profile
        existing_profile = Profile.query.filter_by(user_id=user_id).first()
        user=User.query.filter_by(id=current_user.id).first()

        if existing_profile:
            # If the profile exists, update the fields
            existing_profile.FirstName = data.get('FirstName', existing_profile.FirstName)
            existing_profile.MiddleName = data.get('MiddleName', existing_profile.MiddleName)
            existing_profile.FamilyName = data.get('FamilyName', existing_profile.FamilyName)
            existing_profile.PreviousFamilyName = data.get('PreviousFamilyName', existing_profile.PreviousFamilyName)
            existing_profile.Gender = data.get('Gender', existing_profile.Gender)
            existing_profile.NIN = data.get('NIN', existing_profile.NIN)
            existing_profile.DOB = data.get('DOB', existing_profile.DOB)
            existing_profile.POB = data.get('POB', existing_profile.POB)
            existing_profile.StateOfOrigin = data.get('StateOfOrigin', existing_profile.StateOfOrigin)
            existing_profile.LGA = data.get('LGA', existing_profile.LGA)

            # Handle file upload
            
            if 'Photos' in request.files:
                Photos = request.files['Photos']
                photo_path = f"C:/Users/mukth/nitda_jobportal/profile_photo/{user.username + Photos.filename}"
                Photos.save(photo_path)
                existing_profile.Photos = photo_path

            db.session.commit()
            return jsonify({'message': 'Profile updated successfully'})

        else:
            # If no existing profile, create a new one
            new_profile = Profile(
                user_id=user_id,
                FirstName=data.get('FirstName'),
                MiddleName=data.get('MiddleName'),
                FamilyName=data.get('FamilyName'),
                PreviousFamilyName=data.get('PreviousFamilyName'),
                Gender=data.get('Gender'),
                NIN=data.get('NIN'),
                DOB=data.get('DOB'),
                POB=data.get('POB'),
                StateOfOrigin=data.get('StateOfOrigin'),
                LGA=data.get('LGA'),
            )

            # Handle file upload
            if 'Photos' in request.files:
                Photos = request.files['Photos']
                photo_path = f"C:/Users/mukth/nitda_jobportal/profile_photo/{user.username + Photos.filename}"
                Photos.save(photo_path)
                new_profile.Photos = photo_path

            db.session.add(new_profile)
            db.session.commit()
            return jsonify({'message': 'Profile saved successfully'})

    return jsonify({'message': 'Invalid request'})





@app.route('/api/education', methods=['GET', 'POST'])
@login_required
def education():
    if request.method == 'POST':
        data = request.form
        user_id = current_user.id

        # Check if the user already has an education entry
        existing_education = Education.query.filter_by(user_id=user_id).first()

        LevelOfEdu = data.get('LevelOfEdu')
        UniversityName = data.get('UniversityName')
        ProgramOfStudy = data.get('ProgramOfStudy')
        AwardedDegree = data.get('AwardedDegree')
        Country = data.get('Country')
        ClassOfDegree = data.get('ClassOfDegree')
        AwardIssueDate = data.get('AwardIssueDate')
        Transcript = request.files.get('Transcript')
        Certificate = request.files.get('Certificate')

        # Save uploaded files
        transcript_path = save_file(Transcript)
        certificate_path = save_file(Certificate)

        if existing_education:
            # If education entry exists, update the fields
            existing_education.LevelOfEdu = LevelOfEdu
            existing_education.UniversityName = UniversityName
            existing_education.ProgramOfStudy = ProgramOfStudy
            existing_education.AwardedDegree = AwardedDegree
            existing_education.Country = Country
            existing_education.ClassOfDegree = ClassOfDegree
            existing_education.AwardIssueDate = AwardIssueDate
            existing_education.Transcript = transcript_path
            existing_education.Certificate = certificate_path

            db.session.commit()
            return jsonify({'message': 'Education entry updated successfully'})
        else:
            # If no education entry exists, create a new one
            new_education = Education(
                user_id=user_id,
                LevelOfEdu=LevelOfEdu,
                UniversityName=UniversityName,
                ProgramOfStudy=ProgramOfStudy,
                AwardedDegree=AwardedDegree,
                Country=Country,
                ClassOfDegree=ClassOfDegree,
                AwardIssueDate=AwardIssueDate,
                Transcript=transcript_path,
                Certificate=certificate_path
            )

            db.session.add(new_education)
            db.session.commit()
            return jsonify({'message': 'Education entry saved successfully'})

    return jsonify({'message': 'Invalid request'})


def save_file(file):
    if file:
        user = User.query.filter_by(id=current_user.id).first()
        file_path = f"C:/Users/mukth/nitda_jobportal/documents/{user.username+file.filename}"
        file.save(file_path)
        return file_path
    return None




@app.route('/api/coverletter', methods=['GET', 'POST'])
@login_required
def coverletter():
    if request.method == 'POST':
        data = request.form
        user_id = current_user.id

        # Check if the user already has a cover letter entry
        existing_cletter = Coverletter.query.filter_by(user_id=user_id).first()

        CoverLetter = data.get('CoverLetter')
        CLetter = request.files.get('CLetter')

        # Save uploaded file
        cletter_path = save_file(CLetter)

        if existing_cletter:
            # If cover letter entry exists, update the fields
            existing_cletter.CoverLetter = CoverLetter
            existing_cletter.CLetter = cletter_path

            db.session.commit()
            return jsonify({'message': 'Cover Letter entry updated successfully'})
        else:
            # If no cover letter entry exists, create a new one
            new_cletter = CoverLetter(
                user_id=user_id,
                CoverLetter=CoverLetter,
                CLetter=cletter_path
            )

            db.session.add(new_cletter)
            db.session.commit()
            return jsonify({'message': 'Cover Letter entry saved successfully'})

    return jsonify({'message': 'Invalid request'})


def save_file(file):
    if file:
        user = User.query.filter_by(id=current_user.id).first()
        file_path = f"C:/Users/mukth/nitda_jobportal/coverletter/{user.username+file.filename}"
        file.save(file_path)
        return file_path
    return None






@app.route('/api/documents', methods=['GET', 'POST'])
@login_required
def documents():
    if request.method == 'POST':
        data = request.form
        user_id = current_user.id

        # Check if the user already has a document entry
        existing_document = Documents.query.filter_by(user_id=user_id).first()

        CV = request.files.get('CV')

        # Save uploaded file
        cv_path = save_file(CV)

        if existing_document:
            # If document entry exists, update the fields
            existing_document.CV = cv_path

            db.session.commit()
            return jsonify({'message': 'CV entry updated successfully'})
        else:
            # If no document entry exists, create a new one
            new_cv = Documents(
                user_id=user_id,
                CV=cv_path
            )

            db.session.add(new_cv)
            db.session.commit()
            return jsonify({'message': 'CV entry saved successfully'})

    return jsonify({'message': 'Invalid request'})


def save_file(file):
    if file:
        user = User.query.filter_by(id=current_user.id).first()
        file_path = f"C:/Users/mukth/nitda_jobportal/cv/{user.username+file.filename}"
        file.save(file_path)
        return file_path
    return None



@app.route('/api/create_admin',methods=['POST'])
@login_required
def create_admin():
    data = request.get_json()
    email=data.get('email')
    password=data.get('password')
    username=data.get('name')
    if not email or not password:
        return jsonify({'message': 'Both username and password are required.'}), 400
    user = User.query.filter_by(email=email).first()
    if user:
        return jsonify({'message' : 'Admin with this email already exists.'}), 409
    new_admin= User(email=email,username=username)
    new_admin.hash_password(password)
    new_admin.is_admin=True
    new_admin.is_verified=True
    db.session.add(new_admin)
    db.session.commit()
    return jsonify({'message' :'Admin created successfully!'})


@app.route('/api/add_role',methods=['POST'])
@login_required
def add_role():
    data = request.get_json()
    role_name=data.get('role_name')
    if not role_name :
        return jsonify({'message': 'Role name Required'}), 400
    user = current_user
    if not user.is_admin:
        return jsonify({'message' : 'Only Admin can create job role'}), 409
    if Role.query.filter_by(role_name = role_name).first() is not None:
        return jsonify({'message': 'Role Exists'}), 400   
    new_role= Role(role_name=role_name)
    db.session.add(new_role)
    db.session.commit()
    return jsonify({'message' :'New Job role created successfully!'})

@app.route('/api/add_application',methods=['POST'])
@login_required
def add_application():
    data = request.get_json()
    role_id=data.get('role_id')
    if not role_id:
        return jsonify({'message': 'Role name Required'}), 400
    user = current_user
    Role = Application.query.filter_by(role_id = role_id).first()
    userapplication = Application.query.filter_by(user_id = user.id).first()
    print(Role)
    print(userapplication)
    if Role and userapplication :
        return jsonify({'message' : 'You cant apply for the same role'}), 400
    #if Role.query.filter_by(role_name = role_name).first() is not None:
    #    return jsonify({'message': 'Role Exists'}), 400   
    new_application= Application(role_id=role_id, user_id=user.id)
    db.session.add(new_application)
    db.session.commit()
    return jsonify({'message' :'New Application created successfully!'})


@app.route('/api/status/<int:id>',methods=['GET','POST'])
@login_required
def update_role_status(id):
    user = current_user
    role=Role.query.filter_by(id=id).first()
    if user.is_admin:  
        if role.role_status ==False:
            role.role_status=1
            db.session.commit()
            return jsonify({'message': 'Role is activated'}), 400
        else:
            role.role_status=0
            db.session.commit()
            return jsonify({'message' : 'Role is now deactivated'})
        
    return jsonify({'message': 'Not an admin'}), 400
    


@app.route('/api/users/<int:id>')
def get_user(id):
    user = User.query.get(id)
    if not user:
        abort(400)
    return jsonify({'username': user.username})

@app.route('/api/get_apps/<int:id>')
def get_app(id):
    user = Application.query.filter_by(user_id=current_user.id).all()
    #if not user:
    #    abort(400)
    for i in user:
        role = i.role_id
        print(role)
        rolename = Role.query.filter_by(id=role).first()
        r_name = rolename.role_name
        print(r_name)
    #apps = Application.query.join(Role,Application.role_id==Role.id)
    return jsonify({'username': 'r_name'})



@app.route('/get_all_users', methods=['GET'])
@login_required
def get_all_users():
    users = User.query.order_by(User.id).all()
    data = {'User': [users.username for users in users]}
    return jsonify(data)

@app.route('/get_active_roles', methods=['GET'])
@login_required
def get_active_roles():
    active = 1
    inactive = 0
    active_roles = Role.query.filter_by(role_status=active).all()
    #users = User.query.order_by(User.id).all()
    data = {'Active Roles': [active_roles.role_name for active_roles in active_roles]}
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
