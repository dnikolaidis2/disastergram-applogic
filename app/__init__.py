from flask import Flask, current_app, abort
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_marshmallow import Marshmallow
from kazoo.client import KazooClient, KazooRetry
from app.zookeeper import AppZoo
from datetime import timedelta
from os import environ, path
from distutils.util import strtobool
import requests

db = SQLAlchemy()
mi = Migrate()
ma = Marshmallow()

storage_address = 'http://disastergram.network/storage/'
zk = None


def get_auth_info():
    if current_app.config['AUTH_CONFIG_FROM_ZOO']:
        zk.wait_for_znode('/auth')
        auth_info = zk.get_znode_data('/auth')
        if auth_info is None:
            raise Exception('Could not retrieve auth info from zookeeper')

        current_app.config['AUTH_TOKEN_ISSUER'] = auth_info['TOKEN_ISSUER']
        current_app.config['AUTH_PUBLIC_KEY'] = auth_info['PUBLIC_KEY']
        current_app.config['AUTH_DOCKER_BASEURL'] = auth_info['DOCKER_BASEURL']

    else:
        # only for when we are not running the entire project
        current_app.config['AUTH_TOKEN_ISSUER'] = 'auth'
        current_app.config['AUTH_PUBLIC_KEY'] = \
            requests.get('http://disastergram.network/auth/pubkey').json()['public_key']
        current_app.config['AUTH_DOCKER_BASEURL'] = 'http://disastergram.network/auth/'

# # TODO: INITIALIZE IN create_app
# @zk.ChildrenWatch("/storage")
# def get_children_info(children):
#     zk.wait_for_znode('/storage')
#     empty_child_count = 0
#     if children is None:
#         return None
#
#     for child in children:
#         child_info = zk.get_znode_data('/storage/{}'.format(child))
#
#         if child_info is not None:
#             current_app.config['STORAGE_{}_DOCKER_BASEURL'.format(child)] = child_info['DOCKER_BASEURL']
#         else:
#             empty_child_count += 1
#
#     if empty_child_count == len(children):
#         return None
#     return children


def create_app(test_config=None):
    # create the app configuration
    app = Flask(__name__,
                instance_path=environ.get('FLASK_APP_INSTANCE', '/user/src/app/instance'))

    # Itial config stage
    app.config.from_mapping(
        AUTH_LEEWAY=timedelta(seconds=int(environ.get('AUTH_LEEWAY', '30'))),  # leeway in seconds
        POSTGRES_HOST=environ.get('POSTGRES_HOST', ''),
        POSTGRES_USER=environ.get('POSTGRES_USER', ''),
        POSTGRES_DATABASE=environ.get('POSTGRES_DATABASE', environ.get('POSTGRES_USER', '')),
        POSTGRES_PASSWORD=environ.get('POSTGRES_PASSWORD', ''),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        BASEURL=environ.get('BASEURL', ''),
        DOCKER_HOST=environ.get('DOCKER_HOST', ''),
        DOCKER_BASEURL='http://{}'.format(environ.get('DOCKER_HOST', '')),
        TOKEN_ISSUER=environ.get('TOKEN_ISSUER', environ.get('BASEURL', 'app-logic')),
        ZOOKEEPER_CONNECTION_STR=environ.get('ZOOKEEPER_CONNECTION_STR', 'zoo1,zoo2,zoo3'),
        AUTH_CONFIG_FROM_ZOO=bool(strtobool(environ.get('AUTH_CONFIG_FROM_ZOO', 'False')))
    )

    # 'postgresql+psycopg2://username:password@host/databse'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg2://{}:{}@{}/{}'.format(app.config['POSTGRES_USER'],
                                                                                       app.config['POSTGRES_PASSWORD'],
                                                                                       app.config['POSTGRES_HOST'],
                                                                                       app.config['POSTGRES_DATABASE'])

    # TODO: remove and actually user this config
    app.config['TOKEN_ISSUER'] = 'app-logic'

    if test_config is None:
        # load the instance config if it exists, when not testing
        app.config.from_pyfile(path.join(app.instance_path, 'config.py'), silent=True)
    else:
        app.config.from_mapping(test_config)

    if app.config.get('POSTGRES_HOST') == '':
        raise Exception('No postgres database host was provided. '
                        'POSTGRES_HOST environment variable cannot be omitted')

    if app.config.get('POSTGRES_USER') == '':
        raise Exception('No postgres database user was provided. '
                        'POSTGRES_USER environment variable cannot be omitted')

    if app.config.get('POSTGRES_PASSWORD') == '':
        raise Exception('No postgres database user password was provided. '
                        'POSTGRES_PASSWORD environment variable cannot be omitted')

    if app.config.get('BASEURL') == '':
        raise Exception('No service base url was provided. '
                        'BASEURL environment variable cannot be omitted')

    if app.config.get('DOCKER_HOST') == '':
        raise Exception('No network host within docker was provided. '
                        'DOCKER_HOST environment variable cannot be omitted')

    # Zookeeper init and connection stage

    znode_data = {
        'TOKEN_ISSUER': app.config['TOKEN_ISSUER'],
        'BASEURL': app.config['BASEURL'],
        'DOCKER_HOST': app.config['DOCKER_HOST'],
        'DOCKER_BASEURL': app.config['DOCKER_BASEURL'],
        'PUBLIC_KEY': app.config['PUBLIC_KEY'].decode('utf-8')
    }

    global zk
    zk = AppZoo(KazooClient(app.config['ZOOKEEPER_CONNECTION_STR'],
                            connection_retry=KazooRetry(max_tries=-1),
                            logger=app.logger),
                znode_data)

    # Get auth info before first request
    app.before_first_request(get_auth_info)

    db.init_app(app)
    mi.init_app(app, db,
                directory=environ.get('FLASK_APP_MIGRATIONS', 'migrations'))
    ma.init_app(app)

    # for some reason when not in development
    # this call fails /shrug
    if app.env == 'development':
        from app import models
        models.init_db(app)

    from app import service

    app.register_blueprint(service.bp)

    return app
