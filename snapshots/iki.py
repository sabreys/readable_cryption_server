import os
from enum import Enum

from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import jwt
import datetime
from functools import wraps
import cryption
import logging

logging.basicConfig(filename='error.log', level=logging.FATAL)

file_path = os.path.abspath(os.getcwd()) + "\library.db"

app = Flask(__name__)
app.config['SECRET_KEY'] = 'sdfsdfh3h42fgwdfGDA2H!!!!32E11AASDscc'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + file_path
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


def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):

        token = None

        if 'x-access-tokens' in request.headers:
            token = request.headers['x-access-tokens']

        if not token:
            return jsonify({'message': 'eksik token'})

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = Users.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'Geçersiz token'})

        return f(current_user, *args, **kwargs)

    return decorator


def check_user_exist(data):
    query = Users.query.filter_by(name=data['name']).first()
    return query is not None


@app.route('/register', methods=['GET', 'POST'])
def signup_user():
    data = request.get_json()
    ip = request.remote_addr
    if (check_user_exist(data)):
        app.logger.info('FAIL : %s failed to create user. User exist : %s ', ip, data['name'])
        return jsonify({'message': 'Kullanıcı mevcut'})

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = Users(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False, ip=ip)
    db.session.add(new_user)
    db.session.commit()
    app.logger.info('%s signed in successfully name : %s ', ip, data['name'])
    return jsonify({'message': 'Basariyla Uye olundu'})


@app.route('/login', methods=['GET', 'POST'])
def login_user():
    auth = request.authorization
    ip = request.remote_addr
    if not auth or not auth.username or not auth.password:
        app.logger.info('FAIL : %s Authorization hatasi eksik alan ip: %s ', request.authorization.username, ip, )
        return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})

    user = Users.query.filter_by(name=auth.username).first()

    if not user or not user.name or not user.password:
        app.logger.info('FAIL : %s Boyle bir kullanici yok ip: %s ', request.authorization.username, ip, )
        return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode(
            {'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
            app.config['SECRET_KEY'])
        return jsonify({'token': token})

    db.session.add(FailedLogin(userId=user.public_id, ip=request.remote_addr))
    db.session.commit()
    app.logger.info('FAIL : %s Yanlıs sifre ip: %s ', request.authorization.username, ip, )
    return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})


@app.route('/users', methods=['GET'])
@token_required
def get_all_users(user):
    ip = request.remote_addr
    if (not user.admin):
        app.logger.fatal('FAIL!!! : %s  YETKISIZ ISTEK DENEMESI ip: %s ', user.name, ip, )
        return make_response('Yetki Yok', 405, {'WWW.Authentication': 'Basic realm: "login required"'})

    users = Users.query.all()

    result = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        user_data['ip'] = user.ip

        result.append(user_data)

    app.logger.info('SUCCESS : %s Tum kullanıcıları okudu ip: %s ', user.name, ip, )

    return jsonify({'users': result})


@app.route("/")
@token_required
def index(_):
    return "<p>Readable Cryption uygulamasına hoşgeldiniz \n  /</p>"


@app.route("/encrypt")
@token_required
def encrypt(user):
    ip = request.remote_addr
    data = request.get_json()
    db.session.add(Logs(userId=user.public_id, ip=request.remote_addr, type=0))
    db.session.commit()
    app.logger.info('SUCCESS : %s Sifreleme Gerceklestirdi ip: %s ', user.name, ip, )
    return cryption.encrypt_and_encode(data["passphrase"], data["message"])


@app.route("/decrypt")
@token_required
def decrypt(user):
    ip = request.remote_addr
    data = request.get_json()
    db.session.add(Logs(userId=user.public_id, ip=request.remote_addr, type=1))
    db.session.commit()
    app.logger.info('SUCCESS : %s Sifre Cozdu ip: %s ', user.name, ip, )
    return cryption.decode_and_decrypt(data["passphrase"], data["message"])
