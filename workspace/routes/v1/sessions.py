from workspace import app 
from flask import request
import json
import base64
from flask_jwt_extended import jwt_required
from flask_cors import cross_origin
from workspace.db_connect import create_session
from workspace.controllers import SessionsController, general


#Получить список уникальных сессий
@app.route('/api/v1/Sessions',methods=['GET', 'POST'])
@jwt_required()
def get_sessions():
    session = create_session()
    resp_data = SessionsController.get_sessions(session, request.json['data']['workspace'], request.json['data']['data'])
    session.close()
    return resp_data


#Получить данные сессии
@app.route('/api/v1/Sessions/Data',methods=['GET', 'POST'])
@jwt_required()
def get_session_data():
    session = create_session()
    resp_data = SessionsController.get_session_data(session, request.json['data']['workspace'], request.json['data']['session'])
    session.close()
    return resp_data


#Получить данные сессии
@app.route('/api/v1/Sessions/Events',methods=['GET', 'POST'])
@jwt_required()
def get_session_events():
    session = create_session()
    resp_data = SessionsController.get_session_events(session, request.json['data']['workspace'], request.json['data']['session'])
    session.close()
    return resp_data