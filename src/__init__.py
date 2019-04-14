from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_marshmallow import Marshmallow
from instance.config import Config

db = SQLAlchemy()
ma = Marshmallow()
bc = Bcrypt()

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