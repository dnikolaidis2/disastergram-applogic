from flask import request, jsonify, abort, Blueprint, current_app
from app.models import User, UserSchema, Gallery, Image, Comment, GalleryComment, random_generator
from app import db, sm
from functools import wraps
from datetime import timedelta
import requests
import jwt

bp = Blueprint('app', __name__, url_prefix='/api')
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# Adds users to App-Logic Database if they don't already exist.
def sync_user(username):

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
                                   issuer=current_app.config['AUTH_TOKEN_ISSUER'],
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


# TODO: REMOVE!!!!!!!!
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
@bp.route('/user/follow', methods=['POST'])
@require_auth()
def add_friend(token_payload):

    generate_user(token_payload)  # If user is not in the database, add him.
    logged_user = User.query.filter_by(auth_id=token_payload['sub']).first()

    if logged_user is None:
        abort(403, 'Request Blocked. User Token not Valid.')

    username = request.json.get('username')

    if not username:
        abort(400, 'username field is empty')

    if not sync_user(str(username)):  # Sync_user returns False if the User does not exist in Auth Database.
        abort(404, 'User {} not Found.'.format(repr(username)))

    user = User.query.filter_by(username=username).first()

    if not user:
        abort(404, 'User {} not Found.'.format(repr(username)))

    if user.id == logged_user.id:
        abort(403, 'Cannot Follow Yourself.')

    if logged_user.is_following(user):
        return jsonify({'message': 'User already followed.'}), 200

    logged_user.follow(user)
    db.session.commit()

    return jsonify({'message': 'User added to your Friends.'}), 201

# List of users that the user is following.
@bp.route('/user/following', methods=['GET'])
@require_auth()
def get_following(token_payload):

    generate_user(token_payload)
    logged_user = User.query.filter_by(auth_id=token_payload['sub']).first()

    if logged_user is None:   # Probably not necessary.
        abort(403, 'Request Blocked. User Token not Valid.')

    users = logged_user.followed.all()

    if not users:

        return jsonify({'message': 'No friends found.'}), 204

    output = []

    for user in users:
        user_data = {}
        user_data['id'] = user.id
        user_data['username'] = user.username
        output.append(user_data)
    return jsonify({'Followed users': output}), 200

# List of users that follow the user.
@bp.route('/user/followers', methods=['GET'])
@require_auth()
def get_followed(token_payload):

    generate_user(token_payload)
    logged_user = User.query.filter_by(auth_id=token_payload['sub']).first()

    if logged_user is None:   # Probably not necessary.
        abort(403, 'Request Blocked. User Token not Valid.')

    users = logged_user.followers.all()

    if not users:

        return jsonify({'message': 'No friends found.'}), 204

    output = []

    for user in users:
        user_data = {}
        user_data['id'] = user.id
        user_data['username'] = user.username
        output.append(user_data)
    return jsonify({'Followed users': output}), 200

# Unfollow a friend.
@bp.route('/user/unfollow', methods=['DELETE'])
@require_auth()
def delete_friend(token_payload):

    generate_user(token_payload)
    logged_user = User.query.filter_by(auth_id=token_payload['sub']).first()

    if logged_user is None:
        abort(403, 'Request Blocked. User Token not Valid.')

    username = request.json.get('username')

    if not username:
        abort(400, 'username field is empty')

    if not sync_user(username):  # Sync_user returns False if the User does not exist in Auth Database.
        abort(404, 'User {} not Found.'.format(repr(username)))

    user = User.query.filter_by(username=username).first()

    if not user:
        abort(404, 'User {} not Found.'.format(repr(username)))

    if user.id == logged_user.id:
        abort(403, 'Cannot Unfollow Yourself.')

    if not logged_user.is_following(user):
        return jsonify({'message': 'User already not followed.'}), 200

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

    if Gallery.query.filter_by(galleryname=galleryname, author=logged_user).first():
        return jsonify({'message': 'Gallery name already exists.'}), 200

    new_gallery = Gallery(galleryname=galleryname, author=logged_user)
    db.session.add(new_gallery)
    db.session.commit()

    return jsonify({'message': 'Gallery Created.'}), 201


# GET a list of all the Galleries you have access.
@bp.route('/user/galleries', methods=['GET'])
@require_auth()
def list_galleries(token_payload):

    generate_user(token_payload)
    logged_user = User.query.filter_by(auth_id=token_payload['sub']).first()
    if logged_user is None:
        abort(403, 'Request Blocked. User Token not Valid.')

    galleries = logged_user.followers_galleries().all()

    if not galleries:
        return jsonify({'message': 'No galleries found.'}), 204

    output = []

    for gallery in galleries:
        gallery_data = {}
        gallery_data['galleryname'] = gallery.galleryname
        gallery_data['id'] = gallery.id
        gallery_data['username'] = User.query.filter_by(id=gallery.user_id).first().username
        output.append(gallery_data)

    return jsonify({'Galleries': output}), 200

# GET a list of the user's galleries OR user's friends GALLERIES.
@bp.route('/user/<username>/galleries', methods=['GET'])
@require_auth()
def list_user_galleries(token_payload, username):

    generate_user(token_payload)
    logged_user = User.query.filter_by(auth_id=token_payload['sub']).first()
    if logged_user is None:
        abort(403, 'Request Blocked. User Token not Valid.')

    if not username:
        abort(400, 'username field is empty')

    if sync_user(username) == False:  # Sync_user returns False if the User does not exist in Auth Database.
        abort(404, 'User {} not Found.'.format(repr(username)))

    target_user = User.query.filter_by(username=username).first()

    if not target_user:
        abort(404, 'User {} not Found.'.format(repr(username)))

    if logged_user.id != target_user.id:

        if not target_user.is_following(logged_user):
            abort(401, 'User not Following you.')

    galleries = Gallery.query.filter_by(user_id=target_user.id).all()

    if not galleries:
        return jsonify({'message': 'No galleries found.'}), 204

    output = []

    for gallery in galleries:
        gallery_data = {}
        gallery_data['galleryname'] = gallery.galleryname
        gallery_data['id'] = gallery.id
        output.append(gallery_data)

    return jsonify({'Galleries': output}), 200

# Get a gallery based on id.
@bp.route('/user/gallery/<gallery_id>', methods=['GET'])
@require_auth()
def get_gallery(token_payload, gallery_id):

    generate_user(token_payload)
    logged_user = User.query.filter_by(auth_id=token_payload['sub']).first()
    if logged_user is None:
        abort(403, 'Request Blocked. User Token not Valid.')

    if not gallery_id:
        abort(400, 'gallery_id field is empty')

    target_gallery = Gallery.query.filter_by(id=gallery_id).first()

    if not target_gallery:
        abort(404, 'Gallery not found.')

    target_owner = User.query.filter_by(id=target_gallery.user_id).first()

    if not target_owner:
        abort(404, 'Gallery Owner not found.')

    if logged_user.id != target_owner.id:

        if not target_owner.is_following(logged_user):
            abort(401, 'User not Following you.')

    output = []

    gallery_data = {}
    gallery_data['galleryname'] = target_gallery.galleryname
    gallery_data['username'] = target_owner.username
    gallery_data['user_id'] = target_owner.id
    output.append(gallery_data)

    return jsonify({'Gallery': output}), 200


# Deletes gallery from the user.
@bp.route('/user/gallery/<gallery_id>', methods=['DELETE'])
@require_auth()
def delete_gallery(token_payload, gallery_id):

    generate_user(token_payload)
    logged_user = User.query.filter_by(auth_id=token_payload['sub']).first()

    if logged_user is None:
        abort(403, 'Logged in user does not exist.')

    if not gallery_id:
        abort(400, 'gallery_id field is empty.')

    requested_gallery = Gallery.query.filter_by(id=gallery_id, author=logged_user).first()

    if not requested_gallery:
        abort(404, 'Gallery not Found.')

    requested_images = Image.query.filter_by(gallery_id=gallery_id).all()

    if requested_images:
        for image in requested_images:
            if not sm.delete_image(image.store_id, image.get_locations()):
                abort(500, "Server error occurred while processing request")
        db.session.delete(requested_images)
        db.session.commit()

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

    gallery_comment = GalleryComment(body=request.json['body'], g_comment_author=logged_user, gallery_author=target_gallery)
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

    if not target_user:
        abort(404, 'Gallery owner not found.')

    if logged_user.id != target_user.id:

        if not target_user.is_following(logged_user):
            abort(403, 'Access Forbidden. User is not Following you.')

    gallery_comments = GalleryComment.query.filter_by(gallery_id=gallery_id, gallery_author=target_gallery)

    if not gallery_comments:
        return jsonify({'message': 'No Comments Found.'}), 204

    output = []

    for comment in gallery_comments:
        comment_data = {}
        comment_data['username'] = User.query.filter_by(id=comment.user_id).first().username
        comment_data['comment_id'] = comment.id
        comment_data['body'] = comment.body
        output.append(comment_data)

    return jsonify({'comments': output}), 200


# Deletes gallery comments from the user.
@bp.route('/user/gallery/comment/<comment_id>', methods=['DELETE'])
@require_auth()
def delete_gallery_comments(token_payload, comment_id):

    generate_user(token_payload)
    logged_user = User.query.filter_by(auth_id=token_payload['sub']).first()

    if logged_user is None:
        abort(403, 'Logged in user does not exist.')

    if not comment_id:
        abort(400, 'comment_id field is empty.')

    requested_comment = GalleryComment.query.filter_by(id=comment_id, g_comment_author=logged_user).first()

    if not requested_comment:
        abort(404, 'Comment not Found.')

    db.session.delete(requested_comment)
    db.session.commit()

    return jsonify({'message': 'Gallery Deleted.'}), 200


# Upload an Image.
@bp.route('/user/gallery/<gallery_id>/upload', methods=['POST'])
@require_auth()
def upload_image(token_payload, gallery_id):

    generate_user(token_payload)
    logged_user = User.query.filter_by(auth_id=token_payload['sub']).first()
    if logged_user is None:
        abort(403, 'Request Blocked. User Token not Valid.')

    if not gallery_id:
        abort(400, 'Gallery id field is empty.')

    target_gallery = Gallery.query.filter_by(id=gallery_id).first()

    if not target_gallery:
        abort(404, 'Gallery not Found.')

    if 'file' not in request.files:
        abort(400, 'No file part')

    file = request.files['file']

    if file.filename == '':
        abort(400, 'No selected file')

    if not file:
        abort(400, 'No proper file object.')

    if not allowed_file(file.filename):
        abort(400, 'File type not allowed.')

    image_id = random_generator()

    locations = sm.upload_image(image_id, file)

    if locations is None:
        abort(500, "Server error occurred while processing request")

    # Adds Image in the Database.
    image = Image(store_id=image_id, storage_1=locations[0],
                  storage_2=locations[1], author=target_gallery, image_author=logged_user)
    db.session.add(image)
    db.session.commit()

    return jsonify({'message': 'Image Uploaded.'}), 201


# View the Images of a Gallery.
@bp.route('/user/gallery/<gallery_id>/images', methods=['GET'])
@require_auth()
def view_gallery(token_payload, gallery_id):
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

    if not target_user:
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
        image_data['image_id'] = image.store_id
        image_data['image_url'] = sm.get_image_url(image.store_id, image.get_locations())
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

    if not image_id:
        abort(400, 'Gallery id field is empty.')

    if len(image_id) > Image.store_id.property.columns[0].type.length:
        abort(413, 'Payload Too Large')

    target_image = Image.query.filter_by(store_id=image_id).first()

    if not target_image:
        abort(404, 'Image not Found.')

    if target_image.user_id != logged_user.id:  # Only Image owner has permission to delete.
        abort(403, 'Permission Denied.')
    
    if not sm.delete_image(target_image.store_id, target_image.get_locations()):
        abort(500, "Server error occurred while processing request")

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

    if not request.json['body']:
        abort(400, 'body field is empty.')

    if len(request.json['body']) > Comment.body.property.columns[0].type.length:
        abort(413, 'Payload Too Large')

    if not image_id:
        abort(400, 'Image id field is empty.')

    target_image = Image.query.filter_by(store_id=image_id).first()

    if not target_image:
        abort(404, 'Image not Found.')

    target_user = User.query.filter_by(id=target_image.user_id).first()

    if not target_user:
        abort(404, 'Gallery owner not found.')

    if logged_user.id != target_user.id:

        if not target_user.is_following(logged_user):
            abort(403, 'Access Forbidden. User is not Following you.')

    image_comment = Comment(body=request.json['body'], comment_author=logged_user, image_author=target_image)
    db.session.add(image_comment)
    db.session.commit()

    return jsonify({'message': 'Submitted Comment.'}), 201

# View Image Comments
@bp.route('/user/image/<image_id>/comments', methods=['GET'])
@require_auth()
def view_image_comment(token_payload, image_id):

    generate_user(token_payload)
    logged_user = User.query.filter_by(auth_id=token_payload['sub']).first()

    if logged_user is None:
        abort(403, 'Logged in user does not exist.')

    if not image_id:
        abort(400, 'Image id field is empty.')

    target_image = Image.query.filter_by(store_id=image_id).first()

    if not target_image:
        abort(404, 'Image not Found.')

    target_user = User.query.filter_by(id=target_image.user_id).first()

    if not target_user:
        abort(404, 'Gallery owner not found.')

    if logged_user.id != target_user.id:

        if not target_user.is_following(logged_user):
            abort(403, 'Access Forbidden. User is not Following you.')

    image_comments = Comment.query.filter_by(image_id=target_image.id, image_author=target_image)

    if not image_comments:
        return jsonify({'message': 'No comments found.'}), 204

    output = []

    for comment in image_comments:
        comment_data = {}
        comment_data['username'] = User.query.filter_by(id=comment.user_id).first().username
        comment_data['comment_id'] = comment.id
        comment_data['body'] = comment.body
        output.append(comment_data)

    return jsonify({'comments': output}), 200

# Deletes gallery comments from the user.
@bp.route('/user/image/comment/<comment_id>', methods=['DELETE'])
@require_auth()
def delete_image_comments(token_payload, comment_id):

    generate_user(token_payload)
    logged_user = User.query.filter_by(auth_id=token_payload['sub']).first()

    if logged_user is None:
        abort(403, 'Logged in user does not exist.')

    if not comment_id:
        abort(400, 'comment_id field is empty.')

    requested_comment = Comment.query.filter_by(id=comment_id, comment_author=logged_user).first()

    if not requested_comment:
        abort(404, 'Comment not Found.')

    db.session.delete(requested_comment)
    db.session.commit()

    return jsonify({'message': 'Gallery Deleted.'}), 200


@bp.route('/pubkey')
def pub_key():
    public_key = current_app.config.get('PUBLIC_KEY')

    if public_key is None:
        abort(500, "Server error occurred while processing request")

    return jsonify(public_key=public_key.decode('utf-8'))







