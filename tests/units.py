import base64
import inspect
import json
import random
import time
from datetime import datetime

import jwt
import names
from app import app


def print_result():
    print(inspect.stack()[1][3] + ": Test passed " + u'\u2713')


def signup_fail_test():
    response = app.test_client().post("/register", data=json.dumps({'name': 'test3131', 'password': 'test'}),
                                      content_type='application/json')
    assert response.status_code == 409
    print_result()


def signup_success_test():
    random_nickname = names.get_last_name() + random.randint(1, 1000).__str__()
    response = app.test_client().post("/register",
                                      data=json.dumps({'name': random_nickname, 'password': 'test_password'}),
                                      content_type='application/json')

    assert response.status_code == 200
    print_result()


def login_false_user_test():
    valid_credentials = base64.b64encode(b"testuser:testpassword").decode("utf-8")
    response = app.test_client().post("/login", headers={"Authorization": "Basic " + valid_credentials},
                                      content_type='application/json')
    assert response.data.decode() == "Böyle bir kullanıcı yok" and response.status_code == 400
    print_result()


def login_nouser_test():
    response = app.test_client().post("/login",
                                      content_type='application/json')
    assert response.data.decode() == "Eksik Veri" and response.status_code == 400
    print_result()


def login_false_password_test():
    valid_credentials = base64.b64encode(b"Riveron66:falsepassword").decode("utf-8")
    response = app.test_client().post("/login", headers={"Authorization": "Basic " + valid_credentials},
                                      )
    assert response.data.decode() == "Şifre ya da  kullanıcı adı yanlış" and response.status_code == 400
    print_result()


def login():
    valid_credentials = base64.b64encode(b"test_user:test_password").decode("utf-8")
    response = app.test_client().post("/login", headers={"Authorization": "Basic " + valid_credentials})
    assert response.status_code == 200
    return response


def login_success_test():
    response = login()
    time = datetime.fromtimestamp(
        jwt.decode(json.loads(response.data)["token"], app.config['SECRET_KEY'], algorithms=["HS256"])["exp"])
    diff = time - datetime.now()
    assert diff.total_seconds() > 0

    print_result()


def encrypt_success_test():
    response = login()

    headers = {
        'x-access-tokens': json.loads(response.data)["token"],
        'Content-Type': 'application/json'
    }
    response = app.test_client().post("/encrypt", data=json.dumps({
        "message": "test ! nasılsın ? 12+1 aa",
        "passphrase": "mypass"
    }), headers=headers,

                                      )

    assert response.status_code == 200

    print_result()


def decrypt_success_test():
    response = login()

    headers = {
        'x-access-tokens': json.loads(response.data)["token"],
        'Content-Type': 'application/json'
    }
    response = app.test_client().post("/decrypt", data=json.dumps({
        "message": "rodajire sebesi teya ri topoki hebekigi dosora boto mukizu fu zopeda noni du tu kuni gotihi botano ma boku sodayaru giteya puhodone pi dake ji zukekuho te rehikoke pihakaho nipe kowowowo",
        "passphrase": "mypass"
    }), headers=headers,

                                      )

    assert response.status_code == 200 and response.data.decode("utf-8") == "test ! nasılsın ? 12+1 aa"
    print_result()


def test():
    signup_success_test()
    signup_fail_test()
    login_false_user_test()
    login_nouser_test()
    login_false_password_test()
    login_success_test()
    encrypt_success_test()
    decrypt_success_test()


test()
