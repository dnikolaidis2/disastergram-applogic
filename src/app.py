from flask import Flask, request, jsonify, Response, abort
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from marshmallow import pprint
from flask_marshmallow import Marshmallow

app = Flask(__name__)

# https://docs.sqlalchemy.org/en/latest/core/engines.html#postgresql
# Instantiates database server.
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg2://postgres:1234@db/postgres'
# TODO: WTF is this?
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

bcrypt = Bcrypt(app)

db = SQLAlchemy(app)    # Creates an object of the database.
ma = Marshmallow(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.Text, unique=True, nullable=False)

    def check_password(self, bc, password):
        return bc.check_password_hash(self.password, password)

    def __init__(self, bc, **kwargs):
        newkargs = kwargs
        newkargs['password'] = bc.generate_password_hash(kwargs['password'].__str__()).decode('utf-8')
        super(User, self).__init__(**newkargs)

    def __repr__(self):
        return '<User %r>' % self.username



# db.drop_all()
db.create_all()   # Creates - Instantiates database tables.

class UserSchema(ma.ModelSchema):
    class Meta:
        model = User


@app.route('/auth/user', methods=['POST', 'GET'])
def user():
    if request.method == 'POST':
        # TODO: could you use marshal.dump to do some input testing?
        if not request.is_json:
            abort(400)

        if User.query.filter(User.username == request.json['username']).count() != 0:
            abort(400)

        newuser = User(bcrypt, username=request.json['username'], password=request.json['password'])
        db.session.add(newuser)
        db.session.commit()
        return Response(status=201)

    if request.method == 'GET':
        user_schema = UserSchema(exclude=['id'])
        # getuser = User.query.get(1)

        # return user_schema.jsonify(getuser)
        # Find if user exists

        reqd_user = request.args.get('username')
        if reqd_user is None:
            # Returns all usernames in a single string
            # ...for debugging reasons
            str = ''
            user_list = User.query.all()
            for user in user_list:
                str = str + user.username + '  '
            return str
        else:
            get_user = User.query.filter(User.username == reqd_user).one()
            return user_schema.jsonify(get_user)

        # Maybe check if they have the required perms?
        # User
        # Return user. Redirecting to its profile page
        # return


@app.route('/auth/login', methods=['POST'])
def login():
    if request.method == 'POST':

        if not request.is_json:
            abort(400)

        if User.query.filter(User.username == request.json['username']).count() != 0:
            abort(400)



if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)

