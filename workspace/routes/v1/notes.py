from workspace import app 
from flask import request
import json
import base64
from flask_jwt_extended import jwt_required
from flask_cors import cross_origin
from workspace.db_connect import create_session
from workspace.controllers import NotesController, general


#Получить заметки(notes) для выбранного workspace
@app.route('/api/v1/Notes',methods=['GET', 'POST'])
@jwt_required()
def get_notes():
    session = create_session()
    resp_data = NotesController.getDataNotes(session, request.json['data']['workspace'], request.json['data']['data'])
    session.close()
    return resp_data


#Получить уникальные наименования ntype
@app.route('/api/v1/Notes/UnicType',methods=['GET'])
@jwt_required()
def get_unic_ntype():
    session = create_session()
    resp_data = None
    resp_data = NotesController.getUnicNtype(session)
    session.close()
    return resp_data


#Добавить заметки(notes) для выбранного workspace
@app.route('/api/v1/Notes/addItem',methods=['POST'])
@jwt_required()
def add_notes():
    data = request.json['data']
    session = create_session()
    resp_data = NotesController.add_notes(session, int(data['workspace']), general.JSON_deserialize(data['data']))
    session.close()
    return resp_data


#Добавить заметки(notes) для выбранного workspace
@app.route('/api/v1/Notes/editItem',methods=['POST'])
@jwt_required()
def edit_notes():
    data = request.json['data']
    session = create_session()
    resp_data = NotesController.edit_notes(session, int(data['workspace']), general.JSON_deserialize(data['data']))
    session.close()
    return resp_data


#Del
@app.route('/api/v1/Notes/delItem',methods=['POST'])
@jwt_required()
def del_notes():
    data = request.json['data']
    if(str(type(data)) == "<class 'list'>"):
        data_temp = list(data['data'])
        for item in data:
            session = create_session()
            resp = NotesController.del_Note_by_id(session, int(data['workspace']), int(item))
            session.close()
            if(resp["status"] == 200):
                data_temp.remove(item)
        if (len(data_temp) != 0 and data_temp != data):
            return {'status': 210, 'message':'Не все записи удалены', "data": data_temp}
        else:
            return {'status' :200, 'message': ''}
    elif(str(type(data)) == "<class 'dict'>"):
            session = create_session()
            resp_data = NotesController.del_Note_by_id(session, int(data['workspace']), int(data['data']))
            session.close()
            return resp_data
