import os
from enum import Enum

from flask import Flask, request, jsonify, make_response, render_template
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask import send_from_directory
from flask import render_template
import uuid
import jwt
import datetime
from functools import wraps
import cryption
import logging
import secrets
from flask_cors import CORS, cross_origin


logging.basicConfig(filename='error.log', level=logging.FATAL)

app = Flask(__name__, template_folder="web", )

cors = CORS(app)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', "")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///./library.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config["PROPAGATE_EXCEPTIONS"] = True

db = SQLAlchemy(app)




class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.Integer)
    name = db.Column(db.String(50))
    password = db.Column(db.String(50))
    admin = db.Column(db.Boolean)
    ip = db.Column(db.String(20))


class Logs(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    userId = db.Column(db.Integer)
    ip = db.Column(db.String(20))
    type = db.Column(db.Integer)
    time = db.Column(db.DateTime(timezone=True), default=datetime.datetime.utcnow)


class FailedLogin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    userId = db.Column(db.Integer)
    ip = db.Column(db.String(20))
    time = db.Column(db.DateTime(timezone=True), default=datetime.datetime.utcnow)


FLUTTER_WEB_APP = 'web'


@app.route('/<path:name>')
def return_flutter_doc(name):
    """ serves Flutter app files from web path.
    """
    datalist = str(name).split('/')
    DIR_NAME = FLUTTER_WEB_APP

    if len(datalist) > 1:
        for i in range(0, len(datalist) - 1):
            DIR_NAME += '/' + datalist[i]

    return send_from_directory(DIR_NAME, datalist[-1])


@app.route('/')
def render_page_web():
    """ serves Flutter web application.
    """
    return render_template('index.html')


@app.route('/checktoken', methods=['GET'])
def check_token():
    """ checks token is still valid.
        Required params in header:
        x-access-tokens
        return 0 if it's expired, return 1 is valid
    """
    token = None
    if 'x-access-tokens' in request.headers:
        token = request.headers['x-access-tokens']

    if not token:
        return make_response('Token eksik', 401, {'WWW.Authentication': 'Basic realm: "401 Unauthorized"'})

    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
    except:
        return "0"

    return "1"


def token_required(f):
    """ checks token is valid.
        Required params in function:
        function to execute after validation
    """
    @wraps(f)
    def decorator(*args, **kwargs):

        token = None

        if 'x-access-tokens' in request.headers:
            token = request.headers['x-access-tokens']

        if not token:
            return make_response('Token eksik', 401, {'WWW.Authentication': 'Basic realm: "401 Unauthorized"'})

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = Users.query.filter_by(public_id=data['public_id']).first()
        except:
            return make_response('Ge??ersiz token', 401, {'WWW.Authentication': 'Basic realm: "401 Unauthorized"'})

        return f(current_user, *args, **kwargs)

    return decorator


def check_user_exist(data):
    query = Users.query.filter_by(name=data['name']).first()
    return query is not None


@app.route('/register', methods=['GET', 'POST'])
@cross_origin()
def signup_user():
    """ Sign up function.
        Required params in body:
        name, password
        returns error or success message.
    """
    data = request.get_json()
    ip = request.remote_addr

    if (check_user_exist(data)):
        app.logger.info('FAIL : %s failed to create user. User exist : %s ', ip, data['name'])
        return make_response('Kullan??c?? mevcut', 409, {'WWW.Authentication': 'Basic realm: "login required"'})


    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = Users(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False, ip=ip)
    db.session.add(new_user)
    db.session.commit()
    app.logger.info('%s signed in successfully name : %s ', ip, data['name'])
    return jsonify({'message': 'Basariyla Uye olundu'})


@app.route('/login', methods=['GET', 'POST'])
def login_user():
    """ Login function to get JWT token.
        Required params in header:
        Basic auth
        returns JWT token.
    """
    auth = request.authorization
    ip = request.remote_addr
    if not auth or not auth.username or not auth.password:
        app.logger.info('FAIL : - Authorization hatasi eksik alan ip: %s ', ip, )
        return make_response('Eksik Veri', 400, {'WWW.Authentication': 'Basic realm: "login required"'})

    user = Users.query.filter_by(name=auth.username).first()
    if not user or not user.name or not user.password:
        app.logger.info('FAIL : %s Boyle bir kullanici yok ip: %s ', request.authorization.username, ip, )
        return make_response('B??yle bir kullan??c?? yok', 400, {'WWW.Authentication': 'Basic realm: "login required"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode(
            {'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
            app.config['SECRET_KEY'])
        return jsonify({'token': token})

    db.session.add(FailedLogin(userId=user.public_id, ip=request.remote_addr))
    db.session.commit()
    app.logger.info('FAIL : %s Yanl??s sifre ip: %s ', request.authorization.username, ip, )
    return make_response('??ifre ya da  kullan??c?? ad?? yanl????', 400,
                         {'WWW.Authentication': 'Basic realm: "login required"'})


# @app.route('/users', methods=['GET'])
# @token_required
# def get_all_users(user):
#     """ Return all users(Only Admin user)
#         Required params in header:
#         x-access-tokens JWT token
#         Required param in function:
#         user for request sender information.
#         returns all users.
#     """
#     ip = request.remote_addr
#     if (not user.admin):
#         app.logger.fatal('FAIL!!! : %s  YETKISIZ ISTEK DENEMESI ip: %s ', user.name, ip, )
#         return make_response('Yetki Yok', 405, {'WWW.Authentication': 'Basic realm: "login required"'})
#
#     users = Users.query.all()
#
#     result = []
#
#     for user in users:
#         user_data = {}
#         user_data['public_id'] = user.public_id
#         user_data['name'] = user.name
#         user_data['password'] = user.password
#         user_data['admin'] = user.admin
#         user_data['ip'] = user.ip
#
#         result.append(user_data)
#
#     app.logger.info('SUCCESS : %s Tum kullan??c??lar?? okudu ip: %s ', user.name, ip, )
#
#     return jsonify({'users': result})


@app.route("/encrypt", methods=['GET', 'POST'])
@token_required
def encrypt(user):
    """ Encrypt json request body.
        Required params in header:
        x-access-tokens JWT token
        Required params in body:
        passphrase and message
        Required param in function:
        user for request sender information.
        returns encrypted data.
    """
    ip = request.remote_addr
    data = request.get_json()
    db.session.add(Logs(userId=user.public_id, ip=request.remote_addr, type=0))
    db.session.commit()
    app.logger.info('SUCCESS : %s Sifreleme Gerceklestirdi ip: %s ', user.name, ip, )
    return cryption.encrypt_and_encode(data["passphrase"], data["message"])


@app.route("/decrypt", methods=['GET', 'POST'])
@token_required
def decrypt(user):
    """ Decrypt json request body.
        Required params in header:
        x-access-tokens JWT token
        Required params in body:
        passphrase and message
        Required param in function:
        user for request sender information.
        returns decrypted data.
    """
    ip = request.remote_addr
    data = request.get_json()
    db.session.add(Logs(userId=user.public_id, ip=request.remote_addr, type=1))
    db.session.commit()
    app.logger.info('SUCCESS : %s Sifre Cozdu ip: %s ', user.name, ip, )
    return cryption.decode_and_decrypt(data["passphrase"], data["message"])
