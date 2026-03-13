from workspace import app 
from flask import request
import json
import base64
from flask_jwt_extended import jwt_required
from flask_cors import cross_origin
from workspace.db_connect import create_session
from workspace.controllers import ServicesController, general


#Получить список уникальных сервисов
@app.route('/api/v1/Services/UnicServicesName',methods=['GET', 'POST'])
@jwt_required()
def get_unicservice():
    session = create_session()
    resp_data = ServicesController.getUnicNameService(session)
    session.close()
    return resp_data


#Получить список уникальных имен/портов сервисов для IP
# @app.route('/get_unic_portname_serv',methods=['GET', 'POST'])
# @jwt_required()
# def get_unic_portname_serv():
#     address = request.args.get('address')
#     workspace = request.args.get('workspace')
#     resp_data = services.get_unic_portname_serv(workspace,address)
#     return json.dumps(resp_data)


#Получить сервисы для выбранного workspace
@app.route('/api/v1/Services',methods=['GET', 'POST'])
@jwt_required()
def get_services():
    session = create_session()
    resp_data = ServicesController.getDataServices(session, request.json['data']['workspace'], request.json['data']['data'])
    session.close()
    return resp_data


#Редактирование таблицы с сервисами
@app.route('/api/v1/Services/editItem',methods=['GET', 'POST'])
@jwt_required()
def edit_services():
    data = request.json['data']
    session = create_session()
    resp_data = ServicesController.edit_services(session, int(data['workspace']), general.JSON_deserialize(data['data']))
    session.close()
    return resp_data


#Редактирование таблицы с сервисами (несколько столбцов)
@app.route('/api/edit_services_value',methods=['POST'])
@jwt_required()
def edit_services_value():
    workspace = request.json['workspace']
    data = general.JSON_deserialize(request.json['data'])
    session = create_session()
    arr_id = []
    for id_host in data['id']:
        data_tmp = {}
        for d in data['data']:
            data_tmp[d['column']] = d['value']
        data_tmp['id'] = id_host
        resp_data = ServicesController.edit_services(session, int(workspace), data_tmp)
        arr_id.append(id_host)
    if(len(arr_id) > 0):
        resp_data = {'rsp_k':200, 'message':'Записи отредактированы!', 'id': arr_id}
    else:
        resp_data = {'rsp_k':410, 'message':'Не удалось отредактировать записи!', 'id': arr_id}
    session.close()
    return json.dumps(resp_data)


#Edit
@app.route('/api/v1/Services/addItem',methods=['POST'])
@jwt_required()
def add_services():
    data = request.json['data']
    session = create_session()
    resp_data = ServicesController.add_services(session, int(data['workspace']), general.JSON_deserialize(data['data']))
    session.close()
    return resp_data


#Del
@app.route('/api/v1/Services/delItem',methods=['POST'])
@jwt_required()
def del_services():
    data = request.json['data']
    if(str(type(data)) == "<class 'list'>"):
        data_temp = list(data['data'])
        for item in data:
            session = create_session()
            resp = ServicesController.del_service(session, int(data['workspace']), int(item))
            session.close()
            if(resp["status"] == 200):
                data_temp.remove(item)
        if (len(data_temp) != 0 and data_temp != data):
            return {'status': 210, 'message':'Не все записи удалены', "data": data_temp}
        else:
            return {'status' :200, 'message': ''}
    elif(str(type(data)) == "<class 'dict'>"):
            session = create_session()
            resp_data = ServicesController.del_service(session, int(data['workspace']), int(data['data']))
            session.close()
            return resp_data
