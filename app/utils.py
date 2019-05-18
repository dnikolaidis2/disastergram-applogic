from flask import current_app, request, abort, jsonify
from app import db
from app.models import User
from functools import wraps
from datetime import timedelta
import requests
import jwt

# This function resolves the problem of trying to follow, unfollow etc. users that do not exist in the  App-Logic
# db but exist in the auth db.
def generate_user(username):

    if User.query.filter(User.username == str(username)).count() != 0:
        return True

    user_data = requests.get(current_app.config['AUTH_DOCKER_BASEURL'] + '/user/' + str(username)).json()

    if not user_data:
        return False

    dup_user = User.query.filter_by(username=user_data['username']).first()

    if dup_user:
        if dup_user.auth_id != user_data['id']:
            dup_user.update_auth_id(str(user_data['id']))
            db.session.commit()
            return True
    return True

    new_user = User(username=user_data['username'], auth_id=user_data['id'])
    db.session.add(new_user)
    db.session.commit()

    return True


def check_token(pub_key):
    token = ''
    if request.method == 'GET':
        # check if token was sent with request
        if request.args == {}:
            abort(400, 'Token is not part of request')

        # check if token is not empty
        token = request.args.get('token')
        if token is None:
            abort(400, 'Token field is empty')
    else:
        # check json data
        if request.mimetype == 'multipart/form-data':
            if request.args == {}:
                abort(400, 'Token is not part of request form')
            token = request.args.get('token')
        else:
            if not request.json.get('token'):
                abort(400, 'Token is not part of request form')
            token = request.json.get('token')

    if pub_key is None:
        abort(500, "Server error occurred while processing request")

    token_payload = {}
    # verify token
    try:
        token_payload = jwt.decode(token,
                                   pub_key,
                                   leeway=current_app.config.get('AUTH_LEEWAY', timedelta(seconds=30)), # give 30 second leeway on time checks
                                   issuer= current_app.config['AUTH_TOKEN_ISSUER'],
                                   algorithms='RS256')
    except jwt.InvalidSignatureError:
        # signature of token does not match
        abort(403, 'Invalid token signature')
    except jwt.ExpiredSignatureError:
        # token has expired
        abort(403, 'Token has expired')
    except jwt.InvalidIssuerError:
        # token issuer is invalid
        abort(403, 'Invalid token issuer')
    except jwt.ImmatureSignatureError:
        # token has been used too fast
        abort(403, 'Immature token try again')
    except jwt.exceptions.DecodeError:
        # something went wrong here
        abort(403, 'Invalid token')

    return token_payload


# This function acquires the user's id from the token, retrieves the user's information from the auth db
# and adds the user to the App-Logic database (if he doesn't already exist.)
def generate_token_user(payload):
    token = ''

    user_data = requests.get(current_app.config['AUTH_DOCKER_BASEURL'] + '/user/' + str(payload['sub'])).json()
    if User.query.filter(User.auth_id == user_data['id']).count() != 0:
        return
    dup_user = User(username=user_data['username'], auth_id=user_data['id'])
    db.session.add(dup_user)
    db.session.commit()

    return jsonify({'message': 'user created'})


def require_auth(pub_key="AUTH_PUBLIC_KEY"):

    if not callable(pub_key):
        pub_key = lambda: current_app.config.get('AUTH_PUBLIC_KEY')

    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            payload = check_token(pub_key())
            kwargs['token_payload'] = payload
            return f(*args, **kwargs)

        return wrapped
    return decorator