from index import db

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(256))
    username = db.Column(db.String(256))
    password = db.Column(db.String(256))
    admin = db.Column(db.Boolean)

class Password(db.Model):
    __tablename__ = 'password'
    id = db.Column(db.Integer, primary_key=True)
    website = db.Column(db.String(256))
    password = db.Column(db.String(256))