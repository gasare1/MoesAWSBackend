from os import name
from flask import Flask, jsonify, request, session, redirect
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_required, current_user, login_user, logout_user
from flask_cors import CORS #pip install -U flask-cors
from datetime import timedelta
from models import SubmitForm
from models import Login, db

 
import psycopg2 #pip install psycopg2 
import psycopg2.extras

app = Flask(__name__)
db.init_app(app)
app.config['SECRET_KEY'] = 'cairocoders-ednalan'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] =  timedelta(minutes=10)
app.config["JWT_SECRET_KEY"] = "hkajhskjdhakjhsjkdhaksjydkagsbvhdajkshdas4546asd"
app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://fvfkyplb:xNtNNQZjhMksOec28bJH_g_gisWeZAcZ@chunee.db.elephantsql.com/fvfkyplb"  
CORS(app) 
 
DB_HOST = "chunee.db.elephantsql.com"
DB_NAME = "fvfkyplb"
DB_USER = "fvfkyplb"
DB_PASS = "xNtNNQZjhMksOec28bJH_g_gisWeZAcZ"
     
conn = psycopg2.connect(dbname=DB_NAME, user=DB_USER, password=DB_PASS, host=DB_HOST)

 
@app.route('/')
def home():
    passhash = generate_password_hash('cairocoders')
    print(passhash)
    if 'username' in session:
        username = session['username']
        return jsonify({'message' : 'You are already logged in', 'username' : username})
    else:
        resp = jsonify({'message' : 'Unauthorized'})
        resp.status_code = 401
        return resp
@app.route('/registeruser', methods=['POST', 'GET'])
def register():
    if 'username' in session:
        username = session['username']
        return jsonify({'message' : 'You are already logged in', 'username' : username})

    if request.method == 'POST':
        email = request.json.get("email")
        username = request.json.get('username')
        password = request.json.get('password')

        if Login.query.filter_by(email=email).first():
            return ('Email already Present')

        user = Login(email=email, username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        resp = jsonify({'message' : 'You have Registered Successfully'})
        resp.status_code = 200
        return resp
@app.route('/submitrequest', methods=['POST', 'GET'])
def submit():
    if request.method == 'POST':
            name = request.json.get("name")
            email = request.json.get("email")
            phone = request.json.get('phone')
            additional_information = request.json.get('additional_information')

            user = SubmitForm(name=name, email=email,phone=phone, additional_information=additional_information)
            db.session.add(user)
            db.session.commit()
            
            resp = jsonify({'message' : 'You message has been submitted Successfully'})
            resp.status_code = 200
            return resp

@app.route('/login', methods=['POST'])
def login():
    _json = request.json
    _username = _json['username']
    _password = _json['password']
    print(_password)
    # validate the received values
    if _username and _password:
        #check user exists          
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
          
        sql = "SELECT * FROM registeredusers WHERE username=%s"
        sql_where = (_username,)
          
        cursor.execute(sql, sql_where)
        row = cursor.fetchone()
        username = row['username']
        password = row['password_hash']
        if row:
            if check_password_hash(password, _password):
                session['username'] = username
                cursor.close()
                return jsonify({'message' : 'You are logged in successfully'})
            else:
                resp = jsonify({'message' : 'Bad Request - invalid password'})
                resp.status_code = 400
                return resp
    else:
        resp = jsonify({'message' : 'Bad Request - invalid credendtials'})
        resp.status_code = 400
        return resp
          
@app.route('/logout')
def logout():
    if 'username' in session:
        session.pop('username', None)
    return jsonify({'message' : 'You successfully logged out'})
          
if __name__ == "__main__":
    app.run(debug=False)