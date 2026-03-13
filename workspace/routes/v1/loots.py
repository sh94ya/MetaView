from workspace import app 
from flask import request
import json
import base64
from flask_jwt_extended import jwt_required
from flask_cors import cross_origin
from workspace.db_connect import create_session
from workspace.controllers import LootsController, general


#Получить loots для выбранного workspace
@app.route('/api/v1/Loots',methods=['GET', 'POST'])
@jwt_required()
def get_loots():
    session = create_session()
    resp_data = LootsController.getData(session, request.json['data']['workspace'], request.json['data']['data'])
    session.close()
    return resp_data


#Получить уникальные наименования ltype
@app.route('/api/v1/Loots/UnicType',methods=['GET'])
@jwt_required()
def get_unic_ltype():
    session = create_session()
    resp_data = None
    resp_data = LootsController.getUnicLtype(session)
    session.close()
    return resp_data


#Добавить запись
@app.route('/api/v1/Loots/addItem',methods=['POST'])
@jwt_required()
def add_loots():
    data = request.json['data']
    session = create_session()
    resp_data = LootsController.add_loots(session, int(data['workspace']), general.JSON_deserialize(data['data']))
    session.close()
    return resp_data


#Редактирование записи
@app.route('/api/v1/Loots/editItem',methods=['GET', 'POST'])
@jwt_required()
def edit_loots():
    data = request.json['data']
    session = create_session()
    resp_data = LootsController.edit_loots(session, int(data['workspace']), general.JSON_deserialize(data['data']))
    session.close()
    return resp_data


#Удалить запись
@app.route('/api/v1/Loots/delItem',methods=['POST'])
@jwt_required()
def del_loots():
    data = request.json['data']
    if(str(type(data)) == "<class 'list'>"):
        data_temp = list(data['data'])
        for item in data:
            session = create_session()
            resp = LootsController.del_loots(session, int(data['workspace']), int(item))
            session.close()
            if(resp["status"] == 200):
                data_temp.remove(item)
        if (len(data_temp) != 0 and data_temp != data):
            return {'status': 210, 'message':'Не все записи удалены', "data": data_temp}
        else:
            return {'status' :200, 'message': ''}
    elif(str(type(data)) == "<class 'dict'>"):
            session = create_session()
            resp_data = LootsController.del_loots(session, int(data['workspace']), int(data['data']))
            session.close()
            return resp_data
