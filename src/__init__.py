from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_marshmallow import Marshmallow
from instance.config import Config

#from kazoo import client as kz_client

db = SQLAlchemy()
ma = Marshmallow()
bc = Bcrypt()

#my_client = kz_client.KazooClient(hosts='127.0.0.1:2181')

#def my_listener(state):
#    if state == kz_client.KazooState.CONNECTED:
#        print("Client connected !")

#my_client.add_listener(my_listener)
#my_client.start(timeout=5)


def create_app():
    # create the app configuration
    myapp = Flask(__name__, instance_relative_config=True)
    myapp.config.from_object(Config)
    db.init_app(myapp)
    ma.init_app(myapp)
    bc.init_app(myapp)

    from src import models
    models.init_db(myapp)

    from src import app

    myapp.register_blueprint(app.bp)

    return myapp