from workspace import app 
from flask import request
import json
import base64
from flask_jwt_extended import jwt_required
from flask_cors import cross_origin
from workspace.db_connect import create_session
from workspace.controllers import  general, HostsController

#Получить хосты для выбранного workspace по тегам
@app.route('/get_tree_tags',methods=['GET', 'POST'])
@jwt_required()
def get_tree_tags():
    workspace_id = request.args.get('workspace')
    tag_id = request.args.get('tag_id')
    session = create_session()
    host = HostsController.get_tree_tags(session, workspace_id, tag_id)
    session.close()
    return  json.dumps(host,indent=4, sort_keys=True, default=str)


#Получить список уникальных имен ОС для выбранного семейства ОС
@app.route('/api/v1/Hosts/getNameOS',methods=['GET'])
@jwt_required()
def getNameOS():
    session = create_session()
    resp_data = HostsController.getNameOS(session,  request.args)
    session.close()
    return json.dumps(resp_data)


#Получить список уникальных имен ОС для выбранного семейства ОС
@app.route('/api/v1/Hosts/UnicIP',methods=['GET'])
@jwt_required()
def getUnicIP():
    session = create_session()
    resp_data = HostsController.getUnicIP(session,  request.args)
    session.close()
    return resp_data


#Получить теги узлов
@app.route('/api/get_tags',methods=['GET', 'POST'])
@jwt_required()
def get_tags():
    workspace = request.args.get('workspace')
    session = create_session()
    resp_data = HostsController.get_tags(session, workspace)
    session.close()
    return json.dumps(resp_data)


#Добавление нового тега
@app.route('/api/add_new_tag',methods=['POST'])
@jwt_required()
def add_new_tag():
    data = request.json['data']
    session = create_session()
    resp_data = HostsController.add_new_tag(session, data)
    session.close()
    return json.dumps(resp_data)


#Добавление выбранных тегов для хостов
@app.route('/api/add_tags_on_hosts',methods=['POST'])
@jwt_required()
def add_tags_on_hosts():
    data = request.json['data']
    session = create_session()
    resp_data = HostsController.add_tags_on_hosts(session, data)
    session.close()
    return json.dumps(resp_data)


#Получить хосты(creds) для выбранного workspace
@app.route('/api/v1/Hosts',methods=['GET', 'POST'])
# @jwt_required()
def get_hosts():
    session = create_session()
    resp_data = HostsController.getDataHosts(session, request.json['data']['workspace'], request.json['data']['data'])
    session.close()
    return resp_data


#Редактирование таблицы с хостами (несколько столбцов)
@app.route('/api/edit_hosts_value',methods=['POST'])
@jwt_required()
def edit_hosts_value():
    workspace = request.json['workspace']
    data = general.JSON_deserialize(request.json['data'])
    session = create_session()
    arr_id = []
    for id_host in data['id']:
        data_tmp = {}
        for d in data['data']:
            data_tmp[d['column']] = d['value']
        data_tmp['id'] = id_host
        resp_data = HostsController.edit_hosts(session, int(workspace), data_tmp)
        arr_id.append(id_host)
    if(len(arr_id) > 0):
        resp_data = {'rsp_k':200, 'message':'Записи отредактированы!', 'id': arr_id}
    else:
        resp_data = {'rsp_k':410, 'message':'Не удалось отредактировать записи!', 'id': arr_id}
    session.close()
    return json.dumps(resp_data)


#Добавление хоста
@app.route('/api/v1/Hosts/addItem',methods=['POST'])
@jwt_required()
def add_hosts():
    data = request.json['data']
    session = create_session()
    resp_data = HostsController.add_hosts(session, int(data['workspace']), general.JSON_deserialize(data['data']))
    session.close()
    return resp_data


#Редактирование таблицы с хостами
@app.route('/api/v1/Hosts/editItem',methods=['POST'])
@jwt_required()
def edit_hosts():
    data = request.json['data']
    session = create_session()
    resp_data = HostsController.edit_hosts(session, int(data['workspace']), general.JSON_deserialize(data['data']))
    session.close()
    return resp_data


#Удалить хост
@app.route('/api/v1/Hosts/delItem', methods=['POST'])
@jwt_required()
def del_hosts():
    data = request.json['data']
    if(str(type(data)) == "<class 'list'>"):
        data_temp = list(data['data'])
        for item in data:
            session = create_session()
            resp = HostsController.del_hosts(session, int(data['workspace']), int(item))
            session.close()
            if(resp["status"] == 200):
                data_temp.remove(item)
        if (len(data_temp) != 0 and data_temp != data):
            return {'status': 210, 'message':'Не все записи удалены', "data": data_temp}
        else:
            return {'status' :200, 'message': ''}
    elif(str(type(data)) == "<class 'dict'>"):
            session = create_session()
            resp_data = HostsController.del_hosts(session, int(data['workspace']), int(data['data']))
            session.close()
            return resp_data
