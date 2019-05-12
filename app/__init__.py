from flask import Flask, current_app, abort
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from os import environ, path
import requests

# from kazoo import client as kz_client

db = SQLAlchemy()
ma = Marshmallow()

auth_address = 'http://auth:80'
#auth_address = 'http://disastergram.nikolaidis.tech'
storage_address = 'http://storage_1:80/'
# auth_pubkey = requests.get(auth_address+'/auth/pubkey').json()['public_key']
auth_pubkey = None


def create_app(test_config=None):
    # create the app configuration
    myapp = Flask(__name__,
                  instance_path=environ.get('FLASK_APP_INSTANCE', '/user/src/app/instance'))

    myapp.config.from_mapping(
        SQLALCHEMY_DATABASE_URI='postgresql+psycopg2://postgres:1234@app-db/postgres',
        SQLALCHEMY_TRACK_MODIFICATIONS=False
    )
    if test_config is None:
        # load the instance config if it exists, when not testing
        myapp.config.from_pyfile(path.join(myapp.instance_path, 'config.py'), silent=True)
    else:
        myapp.config.from_mapping(test_config)
    # auth_pubkey_json = requests.get('http://disastergram.nikolaidis.tech/auth/pubkey').json()
    # auth_pubkey = auth_pubkey_json['public_key']
    # myapp.config['AUTH_PUBLIC_KEY'] = requests.get(auth_address+'/auth/pubkey').json()['public_key']
    global auth_pubkey
    auth_pubkey = requests.get(auth_address+'/pubkey').json()['public_key']

    if test_config is None:
        # load the instance config if it exists, when not testing
        myapp.config.from_pyfile(path.join(myapp.instance_path, 'config.py'), silent=True)
    else:
        myapp.config.from_mapping(test_config)

    db.init_app(myapp)
    ma.init_app(myapp)
    # for some reason when not in development
    # this call fails /shrug
    flask_env = myapp.config.get('ENV', '')
    if flask_env == 'development':
        from app import models
        models.init_db(myapp)

    from app import app

    myapp.register_blueprint(app.bp)

    return myapp
