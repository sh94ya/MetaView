from workspace import app 
from flask import request
import json
import base64
from flask_jwt_extended import jwt_required, current_user
from flask_cors import cross_origin
from workspace.db_connect import create_session
from workspace.controllers import CredsController, general


#Получить заметки(notes) для выбранного workspace
@app.route('/api/v1/Creds',methods=['GET', 'POST'])
# @jwt_required()
def get_creds_data():
    session = create_session()
    resp_data = CredsController.getData(session, request.json['data']['workspace'], request.json['data']['data'])
    session.close()
    return resp_data


#Добавить учетки(creds) для выбранного workspace
@app.route('/api/v1/Creds/addItem', methods=['POST'])
@jwt_required()
def add_creds():
    data = request.json['data']
    session = create_session()
    item = general.JSON_deserialize(data['data'])
    resp_data = CredsController.add_creds(session, int(data['workspace']), item, current_user, item['CredType'])
    session.close()
    return resp_data


#Удалить учетки(creds) для выбранного workspace
@app.route('/api/v1/Creds/delItem',methods=['POST'])
@jwt_required()
def del_creds():
    data = request.json['data']
    if(str(type(data['data'])) == "<class 'list'>"):
        data_temp = list(data['data'])
        for item in data:
            session = create_session()
            resp = CredsController.del_creds(session, int(data['workspace']), int(item))
            session.close()
            if(resp["status"] == 200):
                data_temp.remove(item)
        if (len(data_temp) != 0 and data_temp != data):
            return {'status': 210, 'message':'Не все записи удалены', "data": data_temp}
        else:
            return {'status' :200, 'message': ''}
    elif(str(type(data['data']))  == "<class 'dict'>"):
            session = create_session()
            resp_data = CredsController.del_creds(session, int(data['workspace']), data['data'])
            session.close()
            return resp_data


#Удалить учетки(creds) для выбранного workspace
@app.route('/api/v1/Creds/editItem',methods=['POST'])
@jwt_required()
def edit_creds():
    data = request.json['data']
    session = create_session()
    item = general.JSON_deserialize(data['data'])
    resp_data = CredsController.edit_creds(session, int(data['workspace']), item, current_user, item['CredType'])
    session.close()
    return resp_data
