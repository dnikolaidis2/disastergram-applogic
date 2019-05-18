from flask import request, jsonify, abort, Blueprint, current_app
from app.models import User, UserSchema, Gallery, Image, Comment, GalleryComment, random_generator
from app.utils import generate_user, check_token, generate_token_user, require_auth
from app import db, sm

bp = Blueprint('app', __name__, url_prefix='/api')
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])  # Allowed file types for upload.


#  Checks if the file type for upload is allowed.
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# Follow users by username.
@bp.route('/user/follow', methods=['POST'])
@require_auth()
def add_friend(token_payload):

    generate_token_user(token_payload)  # If user is not in the app-logic database, add him.
    logged_user = User.query.filter_by(auth_id=token_payload['sub']).first()

    if logged_user is None:
        abort(403, 'Request Blocked. User Token not Valid.')

    username = request.json.get('username')  # Get username to follow from JSON

    if not username:
        abort(400, 'username field is empty')

    if not generate_user(str(username)):  # generate_user returns False if the User does not exist in Auth Database.
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


# List users that the user is following.
@bp.route('/user/following', methods=['GET'])
@require_auth()
def get_following(token_payload):

    generate_token_user(token_payload)
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


# List users that follow the user.
@bp.route('/user/followers', methods=['GET'])
@require_auth()
def get_followed(token_payload):

    generate_token_user(token_payload)
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


# Unfollow a user by username.
@bp.route('/user/unfollow', methods=['DELETE'])
@require_auth()
def delete_friend(token_payload):

    generate_token_user(token_payload)
    logged_user = User.query.filter_by(auth_id=token_payload['sub']).first()

    if logged_user is None:
        abort(403, 'Request Blocked. User Token not Valid.')

    username = request.json.get('username')

    if not username:
        abort(400, 'username field is empty')

    if not generate_user(username):  # generate_user returns False if the User does not exist in Auth Database.
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

    generate_token_user(token_payload)
    logged_user = User.query.filter_by(auth_id=token_payload['sub']).first()

    if logged_user is None:
        abort(403, 'Request Blocked. User Token not Valid.')

    galleryname = request.json['galleryname']

    if not galleryname:
        abort(400, 'Gallery Name field is empty.')

    # The user cannot have two galleries with the same name.
    if Gallery.query.filter_by(galleryname=galleryname, author=logged_user).first():
        return jsonify({'message': 'Gallery name already exists.'}), 200

    new_gallery = Gallery(galleryname=galleryname, author=logged_user)
    db.session.add(new_gallery)
    db.session.commit()

    return jsonify({'message': 'Gallery Created.'}), 201


# List of all the Galleries the user has access to.
@bp.route('/user/galleries', methods=['GET'])
@require_auth()
def list_galleries(token_payload):

    generate_token_user(token_payload)
    logged_user = User.query.filter_by(auth_id=token_payload['sub']).first()

    if logged_user is None:
        abort(403, 'Request Blocked. User Token not Valid.')

    galleries = logged_user.followers_galleries().all()  # Queries all the galleries of all the users
    # that follow our user.

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

# List of the user's galleries OR user's friends GALLERIES.
@bp.route('/user/<username>/galleries', methods=['GET'])
@require_auth()
def list_user_galleries(token_payload, username):

    generate_token_user(token_payload)
    logged_user = User.query.filter_by(auth_id=token_payload['sub']).first()
    if logged_user is None:
        abort(403, 'Request Blocked. User Token not Valid.')

    if not username:
        abort(400, 'username field is empty')

    if not generate_user(username):  # generate_user returns False if the User does not exist in Auth Database.
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

# Get gallery info based on id.
@bp.route('/user/gallery/<gallery_id>', methods=['GET'])
@require_auth()
def get_gallery(token_payload, gallery_id):

    generate_token_user(token_payload)
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


# Deletes gallery by id from the user.
@bp.route('/user/gallery/<gallery_id>', methods=['DELETE'])
@require_auth()
def delete_gallery(token_payload, gallery_id):

    generate_token_user(token_payload)
    logged_user = User.query.filter_by(auth_id=token_payload['sub']).first()

    if logged_user is None:
        abort(403, 'Logged in user does not exist.')

    if not gallery_id:
        abort(400, 'gallery_id field is empty.')

    requested_gallery = Gallery.query.filter_by(id=gallery_id, author=logged_user).first()

    if not requested_gallery:
        abort(404, 'Gallery not Found.')

    requested_images = Image.query.filter_by(gallery_id=gallery_id).all()

    if requested_images:  # If the gallery has images, delete every image before deleting the gallery.
        for image in requested_images:
            sm.delete_image(image.store_id, image.get_locations())
            db.session.delete(image)

    db.session.delete(requested_gallery)  # All the orphans of the gallery get deleted as well (comments)
    db.session.commit()

    return jsonify({'message': 'Gallery Deleted.'}), 200

# Add Comment to a gallery.
@bp.route('/user/gallery/<gallery_id>/comment', methods=['POST'])
@require_auth()
def post_gallery_comment(token_payload, gallery_id):

    generate_token_user(token_payload)
    logged_user = User.query.filter_by(auth_id=token_payload['sub']).first()

    if logged_user is None:
        abort(403, 'Logged in user does not exist.')

    if not request.json['body']:
        abort(400, 'body field is empty.')

    if len(request.json['body']) > 1024:  # Accepted comment size.
        abort(413, 'Payload Too Large')

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
            abort(403, 'User is not Following you.')

    gallery_comment = GalleryComment(body=request.json['body'], g_comment_author=logged_user, gallery_author=target_gallery)
    db.session.add(gallery_comment)
    db.session.commit()

    return jsonify({'message': 'Submitted Comment.'}), 201


# View Gallery Comments
@bp.route('/user/gallery/<gallery_id>/comments', methods=['GET'])
@require_auth()
def view_gallery_comment(token_payload, gallery_id):

    generate_token_user(token_payload)
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


# Deletes a gallery comment. Only the comment owner can delete the comment.
@bp.route('/user/gallery/comment/<comment_id>', methods=['DELETE'])
@require_auth()
def delete_gallery_comments(token_payload, comment_id):

    generate_token_user(token_payload)
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

    generate_token_user(token_payload)
    logged_user = User.query.filter_by(auth_id=token_payload['sub']).first()
    if logged_user is None:
        abort(403, 'Request Blocked. User Token not Valid.')

    if not gallery_id:
        abort(400, 'Gallery id field is empty.')

    target_gallery = Gallery.query.filter_by(id=gallery_id).first()

    if not target_gallery:
        abort(404, 'Gallery not Found.')

    if 'file' not in request.files:  # Search for 'file' in the passed files.
        abort(400, 'No file part')

    file = request.files['file']

    if file.filename == '':
        abort(400, 'No selected file')

    if not file:
        abort(400, 'No proper file object.')

    if not allowed_file(file.filename):  # Check if file type is allowed.
        abort(400, 'File type not allowed.')

    image_id = random_generator()  # A random, 12 character, alpharethmetic image id.

    locations = sm.upload_image(image_id, file)  # Uploads image in two randomly selected storage servers
    # and returns the two storage server id's that the image was uploaded.

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
    generate_token_user(token_payload)
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

    generate_token_user(token_payload)
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

    db.session.delete(target_image)  # Comments also get deleted.
    db.session.commit()

    return jsonify({'message': 'Image successfully deleted.'}), 200

# Add comment to a image.
@bp.route('/user/image/<image_id>/comment', methods=['POST'])
@require_auth()
def post_image_comment(token_payload, image_id):

    generate_token_user(token_payload)
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

    generate_token_user(token_payload)
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

    generate_token_user(token_payload)
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







