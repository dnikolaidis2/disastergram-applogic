from flask import Flask, current_app, abort
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from os import environ, path
#from kazoo.client import KazooClient, KazooRetry, KazooState
#from app.zookeeper import AppZoo
import requests

db = SQLAlchemy()
ma = Marshmallow()

auth_address = 'http://auth:80'
#auth_address = 'http://disastergram.network'
storage_address = 'http://storage_1:80/'
# auth_pubkey = requests.get(auth_address+'/auth/pubkey').json()['public_key']
auth_pubkey = None
#zk = None

def create_app(test_config=None):
    # create the app configuration
    myapp = Flask(__name__,
                  instance_path=environ.get('FLASK_APP_INSTANCE', '/user/src/app/instance'))

    myapp.config.from_mapping(
        SQLALCHEMY_DATABASE_URI='postgresql+psycopg2://postgres:1234@app-db/postgres',
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        #BASEURL=environ.get('BASEURL', ''),
        #DOCKER_HOST=environ.get('DOCKER_HOST', ''),
        #DOCKER_BASEURL='http://{}'.format(environ.get('DOCKER_HOST', '')),
        #TOKEN_ISSUER=environ.get('TOKEN_ISSUER', environ.get('BASEURL', 'app-logic')),
        #ZOOKEEPER_CONNECTION_STR=environ.get('ZOOKEEPER_CONNECTION_STR', 'zoo1,zoo2,zoo3')

    )

    if test_config is None:
        # load the instance config if it exists, when not testing
        myapp.config.from_pyfile(path.join(myapp.instance_path, 'config.py'), silent=True)
    else:
        myapp.config.from_mapping(test_config)

    global auth_pubkey
    auth_pubkey = requests.get(auth_address+'/pubkey').json()['public_key']

    if test_config is None:
        # load the instance config if it exists, when not testing
        myapp.config.from_pyfile(path.join(myapp.instance_path, 'config.py'), silent=True)
    else:
        myapp.config.from_mapping(test_config)

#    znode_data = {
#        'TOKEN_ISSUER': myapp.config['TOKEN_ISSUER'],
#        'BASEURL': myapp.config['BASEURL'],
#        'DOCKER_HOST': myapp.config['DOCKER_HOST'],
#        'DOCKER_BASEURL': myapp.config['DOCKER_BASEURL'],
#        'PUBLIC_KEY': myapp.config['PUBLIC_KEY'].decode('utf-8')
#    }
#    global zk
#    zk = AppZoo(KazooClient(myapp.config['ZOOKEEPER_CONNECTION_STR'], connection_retry=KazooRetry(max_tries=-1),
#                            logger=myapp.logger), znode_data)



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
