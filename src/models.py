from src import db
from src import ma
from src import bc


followers = db.Table('followers',
    db.Column('follower_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('followed_id', db.Integer, db.ForeignKey('user.id'))
)


class Gallery(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    galleryname = db.Column(db.String, unique = False, nullable= False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))


    def __repr__(self):
        return '<Gallery %r>' % self.galleryname


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.Text, unique=True, nullable=False)
    galleries = db.relationship('Gallery', backref='author', lazy = 'dynamic')
    followed = db.relationship(
        'User', secondary=followers,
        primaryjoin=(followers.c.follower_id == id),
        secondaryjoin=(followers.c.followed_id == id),
        backref=db.backref('followers', lazy='dynamic'), lazy='dynamic')


    def check_password(self, password):
        return bc.check_password_hash(self.password, password)

    def follow(self, user):
        if not self.is_following(user):
            self.followed.append(user)

    def unfollow(self, user):
        if self.is_following(user):
            self.followed.remove(user)

    def is_following(self, user):
        return self.followed.filter(
            followers.c.followed_id == user.id).count() > 0


    def __init__(self, **kwargs):
        kwargs['password'] = bc.generate_password_hash(kwargs['password'].__str__()).decode('utf-8')
        super(User, self).__init__(**kwargs)

    def __repr__(self):
        return '<User %r>' % self.username


class UserSchema(ma.ModelSchema):
    class Meta:
        model = User




def init_db(app):
    with app.app_context():
        db.create_all()

