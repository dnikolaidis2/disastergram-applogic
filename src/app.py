from flask import request, jsonify, Response, abort, Blueprint
from src.models import User, UserSchema
from src import db
from functools import wraps



bp = Blueprint('app', __name__, url_prefix='/app')

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


#@bp.route('/user/<username>', methods=['DELETE'])
#def delete_user(username):
#    return ''



















