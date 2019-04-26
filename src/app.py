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
def generate_user():
    pub_key = auth_pubkey
    payload = check_token(pub_key)
    token = request.args.get('token')
    user_data= requests.get('http://disastergram.nikolaidis.tech:5000/auth/user/'+str(payload['sub'])+str(token)).json()
    if User.query.filter(User.auth_id == user_data['id']).count() != 0:
        return

    dup_user = User(username=user_data['username'], auth_id=user_data['id'])
    db.session.add(dup_user)
    db.session.commit()

    return jsonify({'message': 'User {} added .'})


def require_auth(pub_key="PUBLIC_KEY"):
    #if not callable(pub_key):
    pub_key = auth_pubkey

    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            payload = check_token(pub_key)
            kwargs['token_payload'] = payload
            #generate_user
            return f(*args, **kwargs)

        return wrapped
    return decorator





# TESTING TESTING TESTING TESTING
@bp.route('/test', methods=['GET'])
@require_auth()
def test_pubkey(token_payload):
    return requests.get('http://disastergram.nikolaidis.tech:5000/auth/user/'+str(token_payload['sub'])+'?token=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJhdXRoX3NlcnZlciIsInN1YiI6MiwiZXhwIjoxNTU2MzEwMTkwLCJuYmYiOjE1NTYzMDk1OTB9.DvJ55LZtT4OXxBl_EGrIiOej028rpbhkHjdc4mnKrm-TNepAhEccpcWmX7qsI5JBs_xqWpWWJAIZ6dffpQ5F_I3jGGf4wm0Lg0iEXsL-ATIbiVXBfx9HdCu5EgOumurJUJZ0gCRNTjfnKnz6lsm6gMkEsSWXdXqh6iihoqwyMt4hD8Mj2EWN7JW-8aYJCXgNVQPAFhKgdrYixVd3EJfIfEIaxQmvfgDdZxGlWhnaHSD1CAsSRORrfwIaqSKeCTQ7jMEyy8zmHLlQuNX0Vwc6-5-7NZW9r-Jh2GwZIAz82tjoR5r84wJ-YIu-mkQs4t3XRA4U3t2z-TbSaJkbPAN3nvxZd1JNoaApIdr5W3a0PndH0GOphLGPcc-54XW_yC1slFUBD9Pp2ATv9r49CkiJQhG2pk6O2OXpma8XFWiSFiP-M0SiaK0e3LfQsU50ZaxYSaKOoeg6PRMALPSgiJj04tgXYHVxoV5C4lVhTq0ApxFlOD9_h19H8OVvujSCnOMInAeJ_s7sgml6CMhEcaPrO3bidKslE7EeUrdWT4iTSHHrSTm1JVp_dAmOX5N7nw6stkuUQqujM---zVa3y3K-Ml4DPxTOW32j9FgOPV93VHNFizmWuxRbIvI37xpEyaql9JrPCGeWOlr9nYwyS3IAQS8XSvDnIxVKXUdLOR8vVCc').content



@bp.route('/user', methods=['GET'])
def get_all_users():
    users = User.query.all()

    output = []

    for user in users:
        user_data = {}
        user_data['id'] = user.id
        user_data['username'] = user.username
        user_data['password'] = user.password
        output.append(user_data)
    return jsonify({'users': output})




@bp.route('/user/<user_id>', methods=['GET'])
def get_user():
    return ''

@bp.route('/user', methods=['POST'])
def create_user():
    data = request.get_json()
    new_user = User(username=request.json['username'], password=request.json['password'])
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'New user created!'})


@bp.route('/user/friends/<username>', methods=['POST'])
@require_auth()
def add_friend(username):
    current_user = User.query.filter_by(username='stavros').first() #Temporary way to declare current user...
    user = User.query.filter_by(username=username).first()
    if user is None:
        #TODO : Error Handling.
        return jsonify({'message': 'No user found.'})

    #TODO : Else if to check if user tries to add himself.

    current_user.follow(user)
    db.session.commit()
    return jsonify({'message': 'User {} added to your Friends.'})


@bp.route('/user/friends', methods=['GET'])
def get_friends():
    current_user = User.query.filter_by(username='stavros').first()  # Temporary way to declare current user...
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


@bp.route('/user/gallery', methods=['POST'])
def create_gallery():
    current_user = User.query.filter_by(username='stavros').first()  # Temporary way to declare current user..
    new_gallery = Gallery(galleryname=request.json['name'], author=current_user)
    db.session.add(new_gallery)
    db.session.commit()
    return jsonify({'message': 'Gallery Created.'})


@bp.route('/user/gallery/upload', methods=['POST'])
def upload_image():

    #https://www.youtube.com/watch?time_continue=381&v=TLgVEBuQURA

    return ''

@bp.route('/user/gallery_id/image_id/comment', methods=['POST'])
def post_comment():
    current_user = User.query.filter_by(username='stavros').first()  # Temporary way to declare current user..
    

#@bp.route('/user/<username>', methods=['DELETE'])
#def delete_user(username):
#    return ''



















