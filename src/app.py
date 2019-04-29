from flask import request, jsonify, Response, abort, Blueprint
from src.models import User, UserSchema, Gallery, Image, Comment
from src import db
from functools import wraps
from datetime import datetime, timedelta
import requests
import jwt

bp = Blueprint('app', __name__, url_prefix='/app')
auth_pubkey_json = requests.get('http://disastergram.nikolaidis.tech:5000/auth/pubkey').json()
auth_pubkey = auth_pubkey_json['public_key']

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
        if request.json.get('token') is None:
            abort(400, 'Token is not part of request form')

        token = request.json.get('token')

    if pub_key is None:
        abort(500, "Server error occurred while processing request")

    token_payload = {}
    # verify token
    try:
        token_payload = jwt.decode(token,
                                   pub_key,
                                   leeway=timedelta(days=30),    # give 30 second leeway on time checks
                                   issuer='auth_server',
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

#This function will be used to check incoming users and add them to the applogic database if they don't already exist.
def generate_user(payload):
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
        if request.json.get('token') is None:
            abort(400, 'Token is not part of request form')

        token = request.json.get('token')

    user_data = requests.get('http://disastergram.nikolaidis.tech/auth/user/'+str(payload['sub'])+'?token='+str(token)).json()
    if User.query.filter(User.auth_id == user_data['id']).count() != 0:
        #return User.query.filter_by(auth_id=user_data['id']).first()
        return
    dup_user = User(username=user_data['username'], auth_id=user_data['id'])
    db.session.add(dup_user)
    db.session.commit()

    return jsonify({'message': 'user created'})
    #return jsonify({'id': user_data['id']})


def require_auth(pub_key="PUBLIC_KEY"):
    #if not callable(pub_key):
    pub_key = auth_pubkey

    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            payload = check_token(pub_key)
            kwargs['token_payload'] = payload
            return f(*args, **kwargs)

        return wrapped
    return decorator


def add_user(auth_id, username):

    if User.query.filter(User.auth_id == auth_id).count() != 0:
        return

    new_user = User(username= username, auth_id = auth_id)
    db.session.add(new_user)
    db.session.commit()

    return

# TESTING TESTING TESTING TESTING
@bp.route('/test', methods=['GET'])
@require_auth()
def test_pubkey(token_payload):
    generate_user(token_payload)
    return jsonify({'Message': 'User added?'})





@bp.route('/user', methods=['GET'])
def get_all_users():
    users = User.query.all()

    output = []

    for user in users:
        user_data = {}
        user_data['id'] = user.id
        user_data['auth_id'] = user.auth_id
        user_data['username'] = user.username
        output.append(user_data)
    return jsonify({'users': output})




@bp.route('/user/friends/<username>', methods=['POST'])
@require_auth()
def add_friend(token_payload, username):

    current_user = generate_user(token_payload) #If user is not in the database, add him.
    if current_user is None:
        abort(403, 'User could not be found.')

    #current_user = User.query.filter_by(username='stavros').first() #Temporary way to declare current user...
    user_data = requests.get('http://disastergram.nikolaidis.tech:5000/auth/user/'+str(username)+'?token='+str(request.args.get('token'))).json()
    if user_data is None:
        return jsonify({'message': 'Could not Follow, user does not exist.'})

    add_user(user_data['id'], user_data['username'])

    user = User.query.filter_by(username=username).first()
    if user is None:
        #TODO : Error Handling.
        return jsonify({'message': 'No user found.'})

    if user.username == current_user.username:
        return jsonify({'message': 'Cannot Follow yourself.'})

    current_user.follow(user)
    db.session.commit()
    return jsonify({'message': 'User {} added to your Friends.'})


@bp.route('/user/friends', methods=['GET'])
@require_auth()
def get_friends(token_payload):
    current_user = generate_user(token_payload)
    users = current_user.followed.all()
    if users is None:
        # TODO : Error Handling.
        return jsonify({'message': 'No friends found.'})

    output = []

    for user in users:
        user_data = {}
        user_data['id'] = user.id
        user_data['username'] = user.username
        user_data['password'] = user.password
        output.append(user_data)
    return jsonify({'Followed users': output})


@bp.route('/user/friends/<username>', methods=['DELETE'])
@require_auth()
def delete_friend(username):
    current_user = User.query.filter_by(username='stavros').first()  # Temporary way to declare current user...
    user = User.query.filter_by(username=username).first()
    if user is None:
        # TODO : Error Handling.
        return jsonify({'message': 'No friends found.'})
    if not current_user.is_following(user):
        return jsonify({'message': 'Cant delete friend that doesnt exist.'})

    current_user.unfollow(user)
    db.session.commit()
    return jsonify({'message': 'User {} deleted from your Friends.'})


# Creates an empty gallery for the user.
@bp.route('/user/gallery', methods=['POST'])
@require_auth()
def create_gallery(token_payload):
    generate_user(token_payload)
    current_user = User.query.filter_by(auth_id=token_payload['sub']).first()
    new_gallery = Gallery(galleryname=request.json['name'], author=current_user)
    db.session.add(new_gallery)
    db.session.commit()
    return jsonify({'message': 'Gallery Created.'})

# Deletes gallery from the user.
@bp.route('/user/gallery', methods=['DELETE'])
@require_auth()
def create_gallery(token_payload):
    generate_user(token_payload)
    current_user = User.query.filter_by(auth_id=token_payload['sub']).first()
    new_gallery = Gallery(galleryname=request.json['name'], author=current_user)
    db.session.delete(new_gallery)
    db.session.commit()
    return jsonify({'message': 'Gallery Deleted.'})




@bp.route('/user/gallery/upload', methods=['POST'])
@require_auth()
def upload_image():

    #https://www.youtube.com/watch?time_continue=381&v=TLgVEBuQURA

    return ''

@bp.route('/user/gallery_id/image_id/comment', methods=['POST'])
def post_comment():
    current_user = User.query.filter_by(username='stavros').first()  # Temporary way to declare current user..
    

#@bp.route('/user/<username>', methods=['DELETE'])
#def delete_user(username):
#    return ''



















