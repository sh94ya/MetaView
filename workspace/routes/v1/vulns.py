from workspace import app 
from flask import request
import json
import base64
from flask_jwt_extended import jwt_required, current_user
from flask_cors import cross_origin
from workspace.db_connect import create_session
from workspace.controllers import VulnsController, general

#Получить уязвимости(vulns) для выбранного workspace
@app.route('/api/v1/Vulns',methods=['GET', 'POST'])
@jwt_required()
def get_vulns():
    session = create_session()
    resp_data = VulnsController.getData(session, request.json['data']['workspace'], request.json['data']['data'])
    session.close()
    return resp_data


#Получить имена уязвимости
@app.route('/api/v1/Vulns/UnicName',methods=['GET', 'POST'])
@jwt_required()
def get_name_unic_vulns():
    session = create_session()
    resp_data = None
    resp_data = VulnsController.getUniName(session)
    session.close()
    return resp_data


#Получить уникальные ссылки на уязвимости
@app.route('/api/v1/Vulns/UnicRefs',methods=['GET', 'POST'])
@jwt_required()
def get_unic_refs():
    session = create_session()
    resp_data = None
    resp_data = VulnsController.getUniRefs(session)
    session.close()
    return resp_data


#Добавить запись
@app.route('/api/v1/Vulns/addRef',methods=['POST'])
@jwt_required()
def add_ref():
    session = create_session()
    resp_data = VulnsController.add_ref(session, str(request.json['data']['data']))
    session.close()
    return resp_data


#Добавить уязвимость(vulns) для выбранного workspace
@app.route('/api/v1/Vulns/addItem',methods=['POST'])
@jwt_required()
def add_vulns():
    data = request.json['data']
    session = create_session()
    resp_data = VulnsController.add_vulns(session, int(data['workspace']), general.JSON_deserialize(data['data']), current_user)
    session.close()
    return resp_data


#Удалить запись из таблицы(vulns) для выбранного workspace
@app.route('/api/v1/Vulns/delItem',methods=['POST'])
@jwt_required()
def del_vulns():
    data = request.json['data']
    if(str(type(data)) == "<class 'list'>"):
        data_temp = list(data['data'])
        for item in data:
            session = create_session()
            resp = VulnsController.del_vulns(session, int(data['workspace']), int(item))
            session.close()
            if(resp["status"] == 200):
                data_temp.remove(item)
        if (len(data_temp) != 0 and data_temp != data):
            return {'status': 210, 'message':'Не все записи удалены', "data": data_temp}
        else:
            return {'status' :200, 'message': ''}
    elif(str(type(data)) == "<class 'dict'>"):
            session = create_session()
            resp_data = VulnsController.del_vulns(session, int(data['workspace']), int(data['data']))
            session.close()
            return resp_data


#Редактировать запись из таблицы(vulns) для выбранного workspace
@app.route('/api/v1/Vulns/editItem',methods=['POST'])
@jwt_required()
def edit_vulns():
    data = request.json['data']
    session = create_session()
    resp_data = VulnsController.edit_vulns(session, int(data['workspace']), general.JSON_deserialize(data['data']), current_user)
    session.close()
    return resp_data




#Получить id ссылок для текущего элемента
@app.route('/get_id_refs',methods=['GET', 'POST'])
@jwt_required()
def get_id_refs():
    vuln_id = request.args.get('vuln_id')
    resp_data = VulnsController.get_id_refs(vuln_id)
    return resp_data
