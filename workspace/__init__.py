from flask import  Flask
from flask_cors import CORS
from workspace.controllers import UsersController
import json
import configparser
from flask_jwt_extended import JWTManager
from workspace.db_connect import create_session


app = Flask(__name__, static_folder='view/', static_url_path="/")
conf = configparser.ConfigParser()
conf.read('.\\config.ini')
app.config['SECRET_KEY'] = conf.get('JWT','secret_key')
jwt = JWTManager(app)
CORS(app)
#CORS(app, supports_credentials=True, resources=r'/api/*')


@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    user = None
    session = create_session()
    user = UsersController.get_current_user(session, None, identity)
    session.close()
    return user

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    return app.send_static_file("index.html")
    
import workspace.routes.api


