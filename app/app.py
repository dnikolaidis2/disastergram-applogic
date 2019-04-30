from flask import request, jsonify, Response, abort, Blueprint
from app.models import User, UserSchema, Gallery, Image, Comment, GalleryComment
from app import db
from functools import wraps
from datetime import datetime, timedelta
import requests
import jwt

bp = Blueprint('app', __name__, url_prefix='/api')
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


# This function will be used to check incoming users and add them to the applogic database if they don't already exist.
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
        return
    dup_user = User(username=user_data['username'], auth_id=user_data['id'])
    db.session.add(dup_user)
    db.session.commit()

    return jsonify({'message': 'user created'})


def require_auth(pub_key="PUBLIC_KEY"):

    pub_key = auth_pubkey

    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            payload = check_token(pub_key)
            kwargs['token_payload'] = payload
            return f(*args, **kwargs)

        return wrapped
    return decorator


# Adds users to App-Logic Database if they don't already exist.
def sync_user(username):

    if User.query.filter(User.username == username).count() != 0:
        return True

    user_data = requests.get('http://disastergram.nikolaidis.tech/auth/user/' + str(username)).json()

    if user_data is None:
        return False

    new_user = User(username=user_data['username'], auth_id=user_data['id'])
    db.session.add(new_user)
    db.session.commit()

    return True

# TESTING TESTING TESTING TESTING
@bp.route('/test', methods=['GET'])
@require_auth()
def test_pubkey(token_payload):
    generate_user(token_payload)
    return jsonify({'Message': 'User added?'})

# Used for Testing Purposes.
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

# Can Add Friends. Also syncing FLAWLESSLY with Auth - Database!
@bp.route('/user/follow', methods=['POST'])
@require_auth()
def add_friend(token_payload):

    generate_user(token_payload)  # If user is not in the database, add him.
    logged_user = User.query.filter_by(auth_id=token_payload['sub']).first()

    username = request.json.get('username')

    if logged_user is None:
        abort(403, 'Logged in user does not exist.')

    if not sync_user(username):  # Sync_user returns False if the User does not exist in Auth Database.
        return jsonify({'message': 'No user with name '+str(username)+' found.'})

    user = User.query.filter_by(username=username).first()

    if user.username == logged_user.username:
        return jsonify({'message': 'Cannot Follow yourself.'})

    logged_user.follow(user)
    db.session.commit()
    return jsonify({'message': 'User '+str(username)+' added to your Friends.'})


@bp.route('/user/friends', methods=['GET'])
@require_auth()
def get_friends(token_payload):

    generate_user(token_payload)
    logged_user = User.query.filter_by(auth_id=token_payload['sub']).first()

    if logged_user is None:
        abort(403, 'Logged in user does not exist.')

    users = logged_user.followed.all()

    if users is None:
        # TODO : Error Handling.
        return jsonify({'message': 'No friends found.'})

    output = []

    for user in users:
        user_data = {}
        user_data['id'] = user.id
        user_data['username'] = user.username
        output.append(user_data)
    return jsonify({'Followed users': output})


@bp.route('/user/unfollow', methods=['DELETE'])
@require_auth()
def delete_friend(token_payload):

    generate_user(token_payload)
    logged_user = User.query.filter_by(auth_id=token_payload['sub']).first()

    username = request.json.get('username')

    if logged_user is None:
        abort(403, 'Logged in user does not exist.')

    if not sync_user(username):  # Sync_user returns False if the User does not exist in Auth Database.
        return jsonify({'message': 'No user with name '+str(username)+' found.'})

    user = User.query.filter_by(username=username).first()

    if not logged_user.is_following(user):
        return jsonify({'message': 'User already not followed.'})

    logged_user.unfollow(user)
    db.session.commit()

    return jsonify({'message': 'User '+str(username)+' deleted from your Friends.'})


# Creates an empty gallery for the user.
@bp.route('/user/gallery', methods=['POST'])
@require_auth()
def create_gallery(token_payload):

    generate_user(token_payload)
    logged_user = User.query.filter_by(auth_id=token_payload['sub']).first()
    if logged_user is None:
        abort(403, 'Logged in user does not exist.')

    new_gallery = Gallery(galleryname=request.json['name'], author=logged_user)
    db.session.add(new_gallery)
    db.session.commit()

    return jsonify({'message': 'Gallery Created.'})


# GET a list of the user's galleries OR user's friends GALLERIES.
@bp.route('/user/<username>/galleries', methods=['GET'])
@require_auth()
def list_galleries(token_payload, username):

    generate_user(token_payload)
    logged_user = User.query.filter_by(auth_id=token_payload['sub']).first()

    if not sync_user(username):  # Sync_user returns False if the User does not exist in Auth Database.
        return jsonify({'message': 'No user with name '+str(username)+' found.'})

    target_user = User.query.filter_by(username=username).first()

    if logged_user.username != username:

        if target_user is None:
            return jsonify({'message': 'User '+str(username)+' does not Exist'})

        if not target_user.is_following(logged_user):
            return jsonify({'message': 'Cannot view '+str(username)+' Gallery. User is not Following you.'})

    galleries = Gallery.query.filter_by(user_id=target_user.id)

    output = []

    for gallery in galleries:
        gallery_data = {}
        gallery_data['galleryname'] = gallery.galleryname
        output.append(gallery_data)

    return jsonify({'Galleries': output})


# Deletes gallery from the user.
# TODO: Need to Delete Images from the Gallery as well!!
@bp.route('/user/gallery', methods=['DELETE'])
@require_auth()
def delete_gallery(token_payload):

    generate_user(token_payload)
    logged_user = User.query.filter_by(auth_id=token_payload['sub']).first()

    galleryname = request.json.get('galleryname')
    if logged_user is None:
        abort(403, 'Logged in user does not exist.')

    requested_gallery = Gallery.query.filter_by(galleryname=galleryname, author=logged_user).first()
    db.session.delete(requested_gallery)
    db.session.commit()

    return jsonify({'message': 'Gallery Deleted.'})


@bp.route('/user/gallery/upload', methods=['POST'])
@require_auth()
def upload_image():

    #https://www.youtube.com/watch?time_continue=381&v=TLgVEBuQURA

    return ''


# View the Images of a Gallery.
# TODO : Build legit URL Generation and Storing with Storage Server.
@bp.route('/user/<username>/gallery/<galleryname>', methods=['GET'])
@require_auth()
def view_gallery(token_payload, username, galleryname):
    generate_user(token_payload)
    logged_user = User.query.filter_by(auth_id=token_payload['sub']).first()

    if logged_user is None:
        abort(403, 'Logged in user does not exist.')

    if not sync_user(username):  # Sync_user returns False if the User does not exist in Auth Database.
        return jsonify({'message': 'No user with name '+str(username)+' found.'})

    target_user = User.query.filter_by(username=username).first()
    requested_gallery = Gallery.query.filter_by(galleryname=galleryname, author=target_user).first()

    if logged_user.id != target_user.id:

        if target_user is None:
            return jsonify({'message': 'User ' + str(username) + ' does not Exist'})

        if not target_user.is_following(logged_user):
            return jsonify({'message': 'Cannot view ' + str(username) + ' Gallery. User is not Following you.'})

    gallery_images = Image.query.filter_by(gallery_id=requested_gallery.id).all()

    output = []

    for image in gallery_images:
        gallery_data = {}
        gallery_data['image_url'] = image.imageurl
        output.append(gallery_data)

    return jsonify({'gallery_images': output})


# Add comment to a gallery.
@bp.route('/user/<username>/gallery/<galleryname>/comment', methods=['POST'])
@require_auth()
def post_gallery_comment(token_payload, username, galleryname):

    generate_user(token_payload)
    logged_user = User.query.filter_by(auth_id=token_payload['sub']).first()

    if logged_user is None:
        abort(403, 'Logged in user does not exist.')

    if not sync_user(username):  # Sync_user returns False if the User does not exist in Auth Database.
        return jsonify({'message': 'No user with name '+str(username)+' found.'})

    target_user = User.query.filter_by(username=username).first()
    target_gallery = Gallery.query.filter_by(galleryname=galleryname, author=target_user).first()

    if logged_user.id != target_user.id:

        if target_user is None:
            return jsonify({'message': 'User ' + str(username) + ' does not Exist'})

        if not target_user.is_following(logged_user):
            return jsonify({'message': 'Cannot comment ' + str(username) + ' Gallery. User is not Following you.'})

    gallery_comment = GalleryComment(body=request.json['body'], g_comment_author=target_user, gallery_author=target_gallery)
    db.session.add(gallery_comment)
    db.session.commit()

    return jsonify({'message': 'Submitted Comment.'})

















