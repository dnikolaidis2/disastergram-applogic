from flask import request, jsonify, Response, abort, Blueprint, current_app
from app.models import User, UserSchema, Gallery, Image, Comment, GalleryComment, random_generator
from app import db, auth_pubkey, auth_address, storage_address
from functools import wraps
from datetime import datetime, timedelta
from sqlalchemy.dialects.postgresql import UUID
import requests
import jwt
import uuid


bp = Blueprint('app', __name__, url_prefix='/api')

# Adds users to App-Logic Database if they don't already exist.
def sync_user(user_id):
    if User.query.filter(User.auth_id == str(user_id)).count() != 0:
        return True

    user_data = requests.get(auth_address + '/auth/user/' + str(user_id))

    if user_data.status_code == 200:
        abort(400)


    if user_data is None:
        return False

    #new_user = User(auth_id=user_data['id'], username=user_data['username'])
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
                                   issuer='auth',
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
        #check if token was sent with request
        if request.args == {}:
            abort(400, 'Token is not part of request')

        #check if token is not empty
        token = request.args.get('token')
        if token is None:
            abort(400, 'Token field is empty')
    else:
         #check json data
        if request.json.get('token') is None:
            abort(400, 'Token is not part of request form')

        token = request.json.get('token')

    #user_data = requests.get(auth_address + '/auth/user/'+str(payload['sub'])+'?token='+str(token)).json()

    user_data = requests.get(auth_address + '/auth/user/' + str(payload['sub'])).json()
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




# TESTING TESTING TESTING TESTING
@bp.route('/test/<user_id>', methods=['GET'])
@require_auth()
def test_pubkey(token_payload, user_id):
    generate_user(token_payload)
    return jsonify(requests.get(auth_address + '/auth/user/' + str(user_id)).json())


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

# Can Follow Friends.
@bp.route('/user/<user_id>/follow', methods=['POST'])
@require_auth()
def add_friend(token_payload, user_id):

    generate_user(token_payload)  # If user is not in the database, add him.
    logged_user = User.query.filter_by(auth_id=token_payload['sub']).first()

    if logged_user is None:
        abort(403, 'Request Blocked. User Token not Valid.')

    if not user_id:
        abort(400, 'user_id field is empty')

    if not sync_user(user_id):  # Sync_user returns False if the User does not exist in Auth Database.
        abort(404, 'User not Found.')

    user = User.query.filter_by(auth_id=user_id).first()

    if user.id == logged_user.id:
        abort(403, 'Cannot Follow Yourself.')

    if logged_user.is_following(user):
        return jsonify({'message': 'User already followed.'}), 200

    logged_user.follow(user)
    db.session.commit()

    return jsonify({'message': 'User added to your Friends.'}), 201

# Gets a list of users friends names and id's
@bp.route('/user/friends', methods=['GET'])
@require_auth()
def get_friends(token_payload):

    generate_user(token_payload)
    logged_user = User.query.filter_by(auth_id=token_payload['sub']).first()

    if logged_user is None:   # Probably not necessary.
        abort(403, 'Request Blocked. User Token not Valid.')

    users = logged_user.followed.all()

    if not users:
        # TODO : Error Handling.
        return jsonify({'message': 'No friends found.'}), 204

    output = []

    for user in users:
        user_data = {}
        user_data['id'] = user.id
        user_data['username'] = user.username
        output.append(user_data)
    return jsonify({'Followed users': output}), 201

# Unfollow a friend.
@bp.route('/user/<user_id>/unfollow', methods=['DELETE'])
@require_auth()
def delete_friend(token_payload, user_id):

    generate_user(token_payload)
    logged_user = User.query.filter_by(auth_id=token_payload['sub']).first()

    if logged_user is None:
        abort(403, 'Request Blocked. User Token not Valid.')

    if not user_id:
        abort(400, 'user_id field is empty')

    if not sync_user(user_id):  # Sync_user returns False if the User does not exist in Auth Database.
        return jsonify({'message': 'User not found.'}), 404

    user = User.query.filter_by(auth_id=user_id).first()

    if user.id == logged_user.id:
        abort(403, 'Cannot Unfollow Yourself.')

    if not logged_user.is_following(user):
        return jsonify({'message': 'User already not followed.'})

    logged_user.unfollow(user)
    db.session.commit()

    return jsonify({'message': 'Friend Removed.'}), 200


# Creates an empty gallery for the user.
@bp.route('/user/gallery', methods=['POST'])
@require_auth()
def create_gallery(token_payload):

    generate_user(token_payload)
    logged_user = User.query.filter_by(auth_id=token_payload['sub']).first()

    if logged_user is None:
        abort(403, 'Request Blocked. User Token not Valid.')

    galleryname = request.json['galleryname']

    if not galleryname:
        abort(400, 'Gallery Name field is empty.')

    if Gallery.query.filter_by(galleryname=galleryname, author=logged_user) is None:
        return jsonify({'message': 'Gallery name already exists.'}), 200

    new_gallery = Gallery(galleryname=galleryname, author=logged_user)
    db.session.add(new_gallery)
    db.session.commit()

    return jsonify({'message': 'Gallery Created.'}), 201


# GET a list of the user's galleries OR user's friends GALLERIES.
@bp.route('/user/<user_id>/galleries', methods=['GET'])
@require_auth()
def list_galleries(token_payload, user_id):

    generate_user(token_payload)
    logged_user = User.query.filter_by(auth_id=token_payload['sub']).first()
    if logged_user is None:
        abort(403, 'Request Blocked. User Token not Valid.')

    if not user_id:
        abort(400, 'user_id field is empty')

    if not sync_user(user_id):  # Sync_user returns False if the User does not exist in Auth Database.
        abort(404, 'User not Found.')

    target_user = User.query.filter_by(auth_id=user_id).first()

    if logged_user.id != target_user.id:

        if not target_user.is_following(logged_user):
            abort(401, 'User not Following you.')

    galleries = Gallery.query.filter_by(user_id=target_user.id)

    if not galleries:
        return jsonify({'message': 'No galleries found.'}), 204

    output = []

    for gallery in galleries:
        gallery_data = {}
        gallery_data['galleryname'] = gallery.galleryname
        gallery_data['id'] = gallery.id
        output.append(gallery_data)

    return jsonify({'Galleries': output})


# Deletes gallery from the user.
# TODO: Need to Delete Images from the Gallery as well!!
@bp.route('/user/gallery', methods=['DELETE'])
@require_auth()
def delete_gallery(token_payload):

    generate_user(token_payload)
    logged_user = User.query.filter_by(auth_id=token_payload['sub']).first()

    if logged_user is None:
        abort(403, 'Logged in user does not exist.')

    gallery_id = request.json.get('gallery_id')

    if not gallery_id:
        abort(403, 'gallery_id field is empty.')

    requested_gallery = Gallery.query.filter_by(id=gallery_id, author=logged_user).first()
    db.session.delete(requested_gallery)
    db.session.commit()

    return jsonify({'message': 'Gallery Deleted.'}), 200

# Add comment to a gallery.
@bp.route('/user/gallery/<gallery_id>/comment', methods=['POST'])
@require_auth()
def post_gallery_comment(token_payload, gallery_id):

    generate_user(token_payload)
    logged_user = User.query.filter_by(auth_id=token_payload['sub']).first()

    if logged_user is None:
        abort(403, 'Logged in user does not exist.')

    if not request.json['body']:
        abort(400, 'body field is empty.')

    if len(request.json['body']) > 1024:
        abort(413, 'Payload Too Large')

    if not gallery_id :
        abort(400, 'Gallery id field is empty.')

    target_gallery = Gallery.query.filter_by(id=gallery_id).first()

    if not target_gallery:
        abort(404, 'Gallery not Found.')

    target_user = User.query.filter_by(id=target_gallery.user_id).first()

    if not target_user :
        abort(404, 'Gallery owner not found.')

    if logged_user.id != target_user.id:

        if not target_user.is_following(logged_user):
            abort(403, 'User is not Following you.')

    gallery_comment = GalleryComment(body=request.json['body'], g_comment_author=target_user, gallery_author=target_gallery)
    db.session.add(gallery_comment)
    db.session.commit()

    return jsonify({'message': 'Submitted Comment.'}), 201


# View Gallery Comments
@bp.route('/user/gallery/<gallery_id>/comments', methods=['GET'])
@require_auth()
def view_gallery_comment(token_payload, gallery_id):

    generate_user(token_payload)
    logged_user = User.query.filter_by(auth_id=token_payload['sub']).first()

    if logged_user is None:
        abort(403, 'Logged in user does not exist.')

    if not gallery_id:
        abort(400, 'Gallery id field is empty.')

    target_gallery = Gallery.query.filter_by(id=gallery_id).first()

    if not target_gallery:
        abort(404, 'Gallery not Found.')

    target_user = User.query.filter_by(id=target_gallery.user_id).first()

    if target_user is None:
        abort(404, 'Gallery owner not found.')

    if logged_user.id != target_user.id:

        if not target_user.is_following(logged_user):
            abort(403, 'Access Forbidden. User is not Following you.')

    gallery_comments = GalleryComment.query.filter_by(gallery_id=gallery_id, g_comment_author=target_user, gallery_author=target_gallery)

    if not gallery_comments:
        return jsonify({'message': 'No Comments Found.'}), 204

    output = []

    for comment in gallery_comments:
        comment_data = {}
        comment_data['user_id'] = comment.user_id
        comment_data['id'] = comment.id
        comment_data['body'] = comment.body
        output.append(comment_data)

    return jsonify({'comments': output}), 200

# Upload an Image.
@bp.route('/user/gallery/upload', methods=['POST'])
@require_auth()
def upload_image(token_payload):

    generate_user(token_payload)
    logged_user = User.query.filter_by(auth_id=token_payload['sub']).first()
    if logged_user is None:
        abort(403, 'Request Blocked. User Token not Valid.')

    gallery_id = request.json.get('gallery_id')

    if gallery_id is None:
        abort(400, 'Gallery id field is empty.')

    target_gallery=Gallery.query.filter_by(id=gallery_id, author=logged_user)

    if target_gallery is None:
        abort(404, 'Gallery not Found.')

    if 'file' not in request.files:
        abort(400, 'No file part')

    file = request.files['file']

    if file.filename == '':
        abort(400, 'No selected file')

    temp_url = str(uuid.uuid4())  # A temporary URL for inserting the image in the Table and obtaining
    # the image id for crafting the token which will become the image URL.

    image = Image(id=random_generator, imageurl=temp_url, author=target_gallery)
    db.session.add(image)
    db.session.commit()

    #  Once the image is committed and it's id is crafted then we request the image from the db.
    req_image = Image.query.filter_by(imageurl=temp_url, author=target_gallery)

    payload = {  # Short-lived Token for Safe App-logic and Storage service Communication
        'iss': 'app-logic',
        'sub': str(req_image.id),
        'exp': datetime.utcnow() + timedelta(minutes=15),  # 15 minute token,
        'purpose': 'CREATE'
    }

    private_key = current_app.config.get('PRIVATE_KEY')
    if private_key is None:
        abort(500, "Server error occurred while processing request")

    token = jwt.encode(payload, private_key, algorithm='RS256')

    # TODO: Randomly selecting two active Storage Servers. Zookeeper?
    # URL for sending the POST request to the proper storage server.
    url = storage_address+'/'+str(req_image.id)+'/'+str(token.decode('utf-8'))

    files = {'file': ('image_id.jpg', file, 'image/jpeg')}
    response = requests.post(url, files=files)

    if not (response.status_code == 200 or response.status_code == 201):
        abort(500, "Server error occurred while processing request")

    req_image.update_url(url)
    db.session.commit()

    return jsonify ({'message': 'Image Uploaded.'}), 200


# View the Images of a Gallery.
# TODO : Build legit URL Generation and Storing with Storage Server.
@bp.route('/user/gallery/<gallery_id>', methods=['GET'])
@require_auth()
def view_gallery(token_payload, gallery_id):
    generate_user(token_payload)
    logged_user = User.query.filter_by(auth_id=token_payload['sub']).first()

    if logged_user is None:
        abort(403, 'Logged in user does not exist.')

    if gallery_id is None:
        abort(400, 'Gallery id field is empty.')

    target_gallery = Gallery.query.filter_by(id=gallery_id).first()

    if target_gallery is None:
        abort(404, 'Gallery not Found.')

    target_user = User.query.filter_by(id=target_gallery.user_id).first()

    if target_user is None:
        abort(404, 'Gallery owner not found.')

    if logged_user.id != target_user.id:

        if not target_user.is_following(logged_user):
            abort(403, 'Access Forbidden. User is not Following you.')

    gallery_images = Image.query.filter_by(gallery_id=target_gallery.id).all()

    if not gallery_images:
        return jsonify({'message': 'No images in gallery.'}), 204

    output = []

    for image in gallery_images:
        image_data = {}
        image_data['image_id'] = image.id
        image_data['image_url'] = image.imageurl
        output.append(image_data)

    return jsonify({'gallery_images': output}), 200

# Delete an Image.
@bp.route('/user/image/<image_id>', methods=['DELETE'])
@require_auth()
def delete_image(token_payload, image_id):

    generate_user(token_payload)
    logged_user = User.query.filter_by(auth_id=token_payload['sub']).first()

    if logged_user is None:
        abort(403, 'Logged in user does not exist.')

    if image_id is None:
        abort(400, 'Gallery id field is empty.')

    if len(image_id) > Image.id.property.columns[0].type.length:
        abort(413, 'Payload Too Large')

    target_image = Image.query.filter_by(id=image_id).first()

    if target_image is None:
        abort(404, 'Image not Found.')

    if target_image.user_id != logged_user.id:  # Only Image owner has permission to delete.
        abort(403, 'Permission Denied.')

    payload = {  # Short-lived Token for Safe App-logic and Storage service Communication
        'iss': 'app-logic',
        'sub': str(target_image.id),
        'exp': datetime.utcnow() + timedelta(minutes=15),  # 15 minute token,
        'purpose': 'DELETE'
    }

    private_key = current_app.config.get('PRIVATE_KEY')
    if private_key is None:
        abort(500, "Server error occurred while processing request")

    token = jwt.encode(payload, private_key, algorithm='RS256')

    # URL to send image to Storage Server.
    url = storage_address+'/'+str(target_image.id)+'/'+str(token.decode('utf-8'))

    response = requests.delete(url)

    # TODO : Confirm the Responses with Dimitri

    if not (response.status_code == 200 or response.status_code == 204):
        abort(500, "Server error occurred while processing request")

    # TODO : IF AND ONLY IF IT WAS DELETED FROM STORAGE, THEN DELETE FROM APP-LOGIC DB.
    # Delete Image Comments first.
    image_comments = Comment.query.filter_by(image_id=target_image.id).all()

    if not (image_comments is None):

        db.session.delete(image_comments)
        db.session.commit()

    db.session.delete(target_image)
    db.session.commit()

    return jsonify({'message': 'Image successfully deleted.'}), 200

# Add comment to a image.
@bp.route('/user/image/<image_id>/comment', methods=['POST'])
@require_auth()
def post_image_comment(token_payload, image_id):

    generate_user(token_payload)
    logged_user = User.query.filter_by(auth_id=token_payload['sub']).first()

    if logged_user is None:
        abort(403, 'Logged in user does not exist.')

    if request.json['body'] is None:
        abort(400, 'body field is empty.')

    if len(request.json['body']) > Comment.body.property.columns[0].type.length:
        abort(413, 'Payload Too Large')

    if image_id is None:
        abort(400, 'Image id field is empty.')

    target_image = Image.query.filter_by(id=image_id).first()

    if target_image is None:
        abort(404, 'Image not Found.')

    target_user = User.query.filter_by(id=target_image.user_id).first()

    if target_user is None:
        abort(404, 'Gallery owner not found.')

    if logged_user.id != target_user.id:

        if not target_user.is_following(logged_user):
            abort(403, 'Access Forbidden. User is not Following you.')

    image_comment = Comment(body=request.json['body'], comment_author=target_user, image_author=target_image)
    db.session.add(image_comment)
    db.session.commit()

    return jsonify({'message': 'Submitted Comment.'})

# View Image Comments
@bp.route('/user/image/<image_id>/comments', methods=['GET'])
@require_auth()
def view_image_comment(token_payload, image_id):

    generate_user(token_payload)
    logged_user = User.query.filter_by(auth_id=token_payload['sub']).first()

    if logged_user is None:
        abort(403, 'Logged in user does not exist.')

    if image_id is None:
        abort(400, 'Image id field is empty.')

    if len(image_id) > Image.id.property.columns[0].type.length:
        abort(400, 'Payload Too Large.')

    target_image = Image.query.filter_by(id=image_id).first()

    if target_image is None:
        abort(404, 'Image not Found.')

    target_user = User.query.filter_by(id=target_image.user_id).first()

    if target_user is None:
        abort(404, 'Gallery owner not found.')

    if logged_user.id != target_user.id:

        if not target_user.is_following(logged_user):
            abort(403, 'Access Forbidden. User is not Following you.')

    image_comments = Comment.query.filter_by(image_id=image_id, comment_author=target_user, image_author=target_image)

    if not image_comments:
        return jsonify({'message': 'No comments found.'}), 204

    output = []

    for comment in image_comments:
        comment_data = {}
        comment_data['user_id'] = comment.user_id
        comment_data['id'] = comment.id
        comment_data['body'] = comment.body
        output.append(comment_data)

    return jsonify({'comments': output})


@bp.route('/pubkey')
def pub_key():
    public_key = current_app.config.get('PUBLIC_KEY')
    if public_key is None:
        abort(500, "Server error occurred while processing request")

    return jsonify(public_key=public_key.decode('utf-8'))







