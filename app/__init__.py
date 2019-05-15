from flask import Flask, current_app, abort
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_marshmallow import Marshmallow
from kazoo.client import KazooClient, KazooRetry
from app.zookeeper import AppZoo
from datetime import timedelta
from os import environ, path

db = SQLAlchemy()
mi = Migrate()
ma = Marshmallow()

storage_address = 'http://disastergram.network/storage/1/'
storage_docker_address = 'http://storage_1:80/'
zk = None


def create_app(test_config=None):
    # create the app configuration
    app = Flask(__name__,
                  instance_path=environ.get('FLASK_APP_INSTANCE', '/user/src/app/instance'))

    # Iitial config stage

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

    # Zookeeper init, connection and other service config stage 

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
    zk.wait_for_znode('/auth')
    auth_info = zk.get_znode_data('/auth')
    if auth_info is None:
        raise Exception('Could not retrieve auth info from zookeeper')

    app.config['AUTH_TOKEN_ISSUER'] = auth_info['TOKEN_ISSUER']
    app.config['AUTH_PUBLIC_KEY'] = auth_info['PUBLIC_KEY']
    app.config['AUTH_DOCKER_BASEURL'] = auth_info['DOCKER_BASEURL']

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
