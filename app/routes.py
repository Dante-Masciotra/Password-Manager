from index import app, db
from flask import request, jsonify
from app.models import User, Password
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import uuid
import jwt
import datetime
import re

def require_token(function):
    @wraps(function)
    def decorator(*args, **kwargs):
        token = None 
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message': 'Missing token.'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.filter_by(username=data['username']).first()
        except:
            return jsonify({'message': 'Invalid token.'}), 401
        return function(current_user, *args, **kwargs)
    return decorator

def require_refresh_token(function):
    @wraps(function)
    def decorator(*args, **kwargs):
        token = None 
        if 'x-refresh-token' in request.headers:
            token = request.headers['x-refresh-token']
        if not token:
            return jsonify({'message': 'Missing refresh token.'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.filter_by(username=data['username']).first()
        except:
            return jsonify({'message': 'Invalid refresh token.'}), 401
        return function(current_user, *args, **kwargs)
    return decorator

@app.route('/authenticate')
@require_token
def authenticate(_):
    return jsonify({'message': "Authentication successful."})

@app.route('/user')
@require_token
def get_users(current_user):
    try:
        if not current_user.admin:
            return jsonify({'message': "Insufficient permissions."}), 401
        users = User.query.all()
        if not users:
            return jsonify({'message': 'No users found.'}), 404
        user_list = []
        for user in users:
            data = {}
            data['email'] = user.email
            data['username'] = user.username
            data['password'] = user.password
            data['admin'] = user.admin
            user_list.append(data)
        return jsonify({'users: ': user_list})
    except Exception as e:
        print(e)
        return jsonify({'message': "An error occurred."}), 500

@app.route('/user/<username>')
@require_token
def get_user(current_user, username):
    try:
        if not current_user.admin:
            return jsonify({'message': "Insufficient permissions."}), 401
        user = User.query.filter_by(username=username).first()
        if not user:
            return jsonify({'message': 'User not found.'}), 404
        data = {}
        data['username'] = user.username 
        data['password'] = user.password 
        data['admin'] = user.admin 
        return jsonify(data)
    except Exception as e:
        print(e)
        return jsonify({'message': "An error occurred."}), 500
    
@app.route('/me')
@require_token
def get_current_user(current_user):
    data = {}
    data['id'] = current_user.id 
    data['username'] = current_user.username 
    return jsonify(data) 

@app.route('/user', methods=['POST'])
@require_token
def create_user(current_user):
    try:
        if not current_user.admin:
            return jsonify({'message': "Insufficient permissions."}), 401
        data = request.get_json()
        hashed_pw = generate_password_hash(data['password'], method='sha256')
        user = User( username=data['username'], password=hashed_pw, admin=data['admin'])
        db.session.add(user)
        db.session.commit()
        return jsonify({'message': 'User created.'})
    except Exception as e:
        print(e)
        return jsonify({'message': "An error occurred."}), 500

@app.route('/user/<username>', methods=['DELETE'])
@require_token
def delete_user(current_user, username):
    try:
        if not current_user.admin:
            return jsonify({'message': "Insufficient permissions."}), 401
        user = User.query.filter_by(username=username).first()
        if not user:
            return jsonify({'message': 'User not found.'}), 404
        db.session.delete(user)
        db.session.commit()
        return jsonify({'message': 'User deleted.'})
    except Exception as e:
        print(e)
        return jsonify({'message': "An error occurred."}), 500

@app.route('/login',  methods=['POST'])
def login():
    try:
        data = request.get_json()
        if not data or not data['username'] or not data['password']:
            return jsonify({'message': 'Invalid or missing credentials.'}), 401
        user = User.query.filter_by(username=data['username']).first()
        if not user:
            return jsonify({'message': 'User not found.'}), 404
        if check_password_hash(user.password, data['password']):
            token = jwt.encode({'username': user.username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=15)}, app.config['SECRET_KEY'], algorithm='HS256')
            refresh = jwt.encode({'username': user.username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(days=15)}, app.config['SECRET_KEY'], algorithm='HS256')
            return jsonify({'token': token, 'refresh': refresh})
    except Exception as e:
        print(e)
        return jsonify({'message': "An error occurred."}), 500
    return jsonify({'message': 'Invalid or missing credentials.'}), 401

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        if not re.search(r".+@.+\..+", data['email']) or re.search(r"[%\\\?\"\'~/\$\*\{\}\s]", data['email']) or len(data['email']) > 128 or not data['email'].isascii():
            return jsonify({'message': 'Invalid email. Check for any special characters that may be present, and ensure that the entered email address is formatted correctly.'}), 401
        if not data['username'] or re.search(r"[%\\\?\"\'~/\$\*\{\}\s]", data['username']) or len(data['username']) > 32 or len(data['username']) < 1 or not data['username'].isascii():
            return jsonify({'message': 'Invalid username. Check for any special characters that may be present, and that your username is less than 32 characters in length. Usernames cannot be blank'}), 401
        if not data['password'] or re.search(r"[%\\\?\"\'~/\$\*\{\}\s]", data['password']) or len(data["password"]) < 8 or len(data['password']) > 256 or not data['password'].isascii():
            return jsonify({'message': 'Invalid password. Check for any special characters that may be present, and ensure that your password is not too short (at least 8 characters).'}), 401
        if User.query.filter_by(email=data['email']).first():
            return jsonify({'message': "An account with the given email address is already registered."}), 401
        if User.query.filter_by(username=data['username']).first():
            return jsonify({'message': "Username is taken."}), 401
        hashed_pw = generate_password_hash(data['password'], method='sha256')
        user = User( username=data['username'], email=data['email'], password=hashed_pw, admin=False)
        db.session.add(user)
    except Exception as e:
        print(e)
        return jsonify({'message': "An error occurred."}), 500
    try:
        db.session.commit()
    except:
        return jsonify({'message': 'Failed to commit changes to database.'}), 500
    return jsonify({'message': 'User created.'})

@app.route('/refresh')
@require_refresh_token
def refresh_token(current_user):
    try:
        refresh_token = request.headers['x-refresh-token']
        if not refresh_token:
            return jsonify({'message': 'Missing refresh token.'}), 401
        try:
            jwt.decode(refresh_token, app.config['SECRET_KEY'], algorithms=['HS256'])
        except:
            return jsonify({'message': 'Invalid refresh token.'}), 401
        if not current_user:
            return jsonify({'message': 'User not found.'}), 404
        return jsonify({'token': jwt.encode({'username': current_user.username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=15)}, app.config['SECRET_KEY'], algorithm='HS256'), 'refresh': jwt.encode({'username': current_user.username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(days=15)}, app.config['SECRET_KEY'], algorithm='HS256')})
    except Exception as e:
        print(e)
        return jsonify({'message': "An error occurred."}), 500
    

@app.route('/AddPassword', methods=['POST'])
def AddPassword():
    try:
        data = request.get_json()
        if not data or not data['website']:
            return jsonify({'message': 'Missing Website.'}), 401
        if not data or not data['password']:
            return jsonify({'message': 'Missing Password.'}), 401
        
        hashed_pw = generate_password_hash(data['password'], method='sha256')
        password = Password( user=data['user'], website=data['website'], password=hashed_pw)
        db.session.add(password)
    except Exception as e:
        print(e)
        return jsonify({'message': "An error occurred."}), 500
    try:
        db.session.commit()
    except:
        return jsonify({'message': 'Failed to commit changes to database.'}), 500
    return jsonify({'message': 'Password Added.'})
