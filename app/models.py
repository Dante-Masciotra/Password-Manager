from index import db

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    email = db.Column(db.String(256))
    username = db.Column(db.String(256))
    password = db.Column(db.String(256))
    admin = db.Column(db.Boolean)
    