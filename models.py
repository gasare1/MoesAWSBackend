from logging import info
from os import name
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager
 
login = LoginManager()
db = SQLAlchemy()
 
class Login(UserMixin, db.Model):
    __tablename__ = 'registeredusers'
 
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(80), unique=True)
    username = db.Column(db.String(100))
    password_hash = db.Column(db.String())
 
    def set_password(self,password):
        self.password_hash = generate_password_hash(password)
     
    def check_password(self,password):
        return check_password_hash(self.password_hash,password)
 
class SubmitForm(UserMixin,db.Model):
    __tablename__ = 'submitform'
 
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True)
    email = db.Column(db.String(80), unique=True)
    phone = db.Column(db.Integer)
    additional_information = db.Column(db.String())

@login.user_loader
def load_user(id):
    return Login.query.get(int(id))
# Change this to your secret key (can be anything, it's for extra protection)
