from flask import Flask
from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
import os

load_dotenv(".env")
app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.abspath((os.getcwd())) + r'\app\db\pw.db'

db = SQLAlchemy(app)
from app import routes

if __name__ == '__main__':
    with app.app_context():
        app.run(debug=True)
        