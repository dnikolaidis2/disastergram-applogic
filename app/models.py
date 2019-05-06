from app import db
from app import ma
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy import update
import uuid
import string
import random

def random_generator():
    return ''.join([random.choice(string.ascii_letters + string.digits) for n in range(32)])


def user_uuid():
    uid = uuid.uuid4()
    while User.query.get(uid) is not None:
        uid = uuid.uuid4()

    return uid

def gallery_uuid():
    uid = uuid.uuid4()
    while Gallery.query.get(uid) is not None:
        uid = uuid.uuid4()

    return uid

def gallery_comment_uuid():
    uid = uuid.uuid4()
    while GalleryComment.query.get(uid) is not None:
        uid = uuid.uuid4()

    return uid

def comment_uuid():
    uid = uuid.uuid4()
    while Comment.query.get(uid) is not None:
        uid = uuid.uuid4()

    return uid
followers = db.Table('followers',
    db.Column('follower_id', UUID(as_uuid=True), db.ForeignKey('user.id')),
    db.Column('followed_id', UUID(as_uuid=True), db.ForeignKey('user.id'))
)


class Comment(db.Model):
    id = db.Column(UUID(as_uuid=True), default=gallery_comment_uuid, primary_key=True,  unique=True, index=True)
    body = db.Column(db.String(1024), unique=False, nullable= False)
    image_id = db.Column(db.Integer, db.ForeignKey('image.id'))
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey('user.id'))

    def __repr__(self):
        return '<Comment %r>' % self.id


class GalleryComment(db.Model):
    id = db.Column(UUID(as_uuid=True), default=gallery_comment_uuid, primary_key=True,  unique=True, index=True)
    body = db.Column(db.String(1024), unique=False, nullable= False)
    gallery_id = db.Column(UUID(as_uuid=True), db.ForeignKey('gallery.id'))
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey('user.id'))

    def __repr__(self):
        return '<GalleryComment %r>' % self.id


class Image(db.Model):
    id = db.Column(db.String, primary_key=True,  unique=True, index=True)
    gallery_id = db.Column(UUID(as_uuid=True), db.ForeignKey('gallery.id'))
    imageurl = db.Column(db.String(100), unique = True, nullable = False)
    comments = db.relationship('Comment', backref='author', lazy = 'dynamic')

    def update_url(self, url):
        self.imageurl = url

    def __repr__(self):
        return '<Image %r>' % self.imageurl


class Gallery(db.Model):
    id = db.Column(UUID(as_uuid=True), default=gallery_uuid, primary_key=True,  unique=True, index=True)
    galleryname = db.Column(db.String(80), unique = False, nullable= False)
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey('user.id'))
    images = db.relationship('Image', backref='author', lazy='dynamic')
    comments = db.relationship('GalleryComment', backref='gallery_author', lazy='dynamic')

    def __repr__(self):
        return '<Gallery %r>' % self.galleryname


class User(db.Model):
    id = db.Column(UUID(as_uuid=True), default=user_uuid, primary_key=True,  unique=True, index=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    auth_id = db.Column(db.String(120), unique=True, nullable=False)
    galleries = db.relationship('Gallery', backref='author', lazy = 'dynamic')
    comments = db.relationship('Comment', backref='comment_author', lazy='dynamic')
    g_comments = db.relationship('GalleryComment', backref='g_comment_author', lazy='dynamic')
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

    def __repr__(self):
        return '<User %r>' % self.username


class UserSchema(ma.ModelSchema):
    class Meta:
        model = User




def init_db(app):
    with app.app_context():
        db.create_all()

