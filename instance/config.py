import os
basedir = os.path.abspath(os.path.dirname(__file__))

# https://docs.sqlalchemy.org/en/latest/core/engines.html#postgresql
# Instantiates database server.
class Config(object):
    SECRET_KEY =  'its a secret'
    SQLALCHEMY_DATABASE_URI = 'postgresql+psycopg2://postgres:1234@db/postgres'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

#os.ennviron.get('SECRET_KEY') or