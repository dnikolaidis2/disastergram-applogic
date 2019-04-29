from src import db
from src import ma
from src import bc


followers = db.Table('followers',
    db.Column('follower_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('followed_id', db.Integer, db.ForeignKey('user.id'))
)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.String(1024), unique=False, nullable= False)
    image_id = db.Column(db.Integer, db.ForeignKey('image.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __repr__(self):
        return '<Comment %r>' % self.id

class Image(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    gallery_id = db.Column(db.Integer, db.ForeignKey('gallery.id'))
    imageurl = db.Column(db.String(100), unique = True, nullable = False)
    comments = db.relationship('Comment', backref='author', lazy = 'dynamic')

    def __repr__(self):
        return '<Image %r>' % self.imageurl

class Gallery(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    galleryname = db.Column(db.String, unique = False, nullable= False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    images = db.relationship('Image', backref='author', lazy = 'dynamic')

    def __repr__(self):
        return '<Gallery %r>' % self.galleryname


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    auth_id = db.Column(db.Integer, unique=True, nullable=False)
    galleries = db.relationship('Gallery', backref='author', lazy = 'dynamic')
    comments = db.relationship('Comment', backref='author1', lazy = 'dynamic')
    followed = db.relationship(
        'User', secondary=followers,
        primaryjoin=(followers.c.follower_id == id),
        secondaryjoin=(followers.c.followed_id == id),
        backref=db.backref('followers', lazy='dynamic'), lazy='dynamic')



    def follow(self, user):
        if not self.is_following(user):
            self.followed.append(user)

    def unfollow(self, user):
        if self.is_following(user):
            self.followed.remove(user)

    def is_following(self, user):
        return self.followed.filter(
            followers.c.followed_id == user.id).count() > 0

    #def __init__(self, **kwargs):
    #    kwargs['password'] = bc.generate_password_hash(kwargs['password'].__str__()).decode('utf-8')
    #    super(User, self).__init__(**kwargs)

    def __repr__(self):
        return '<User %r>' % self.username


class UserSchema(ma.ModelSchema):
    class Meta:
        model = User




def init_db(app):
    with app.app_context():
        db.create_all()

