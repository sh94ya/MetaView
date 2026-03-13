from workspace import app 
from flask import request
import json
import base64
from flask_jwt_extended import jwt_required
from flask_cors import cross_origin
from workspace.db_connect import create_session
from workspace.controllers import CredsController, HostsController, LootsController, NotesController, ServicesController, VulnsController, SessionsController, WebController, general

#Получить top_services
@app.route('/get_top_service',methods=['GET', 'POST'])
@jwt_required()
def get_top_service():
    workspace_id = request.args.get('workspace')
    session = create_session()
    resp_data = ServicesController.get_top_service(session, workspace_id)
    session.close()
    return json.dumps(resp_data, indent=4, sort_keys=True, default=str)


#Получить top_vulns
@app.route('/get_top_vuln',methods=['GET', 'POST'])
@jwt_required()
def get_top_vuln():
    workspace_id = request.args.get('workspace')
    session = create_session()
    resp_data = VulnsController.get_top_vuln(session, workspace_id)
    session.close()
    return json.dumps(resp_data, indent=4, sort_keys=True, default=str)


#Получить количество узявимых/неуязвимых хостов 
@app.route('/get_vulns_hosts',methods=['GET', 'POST'])
@jwt_required()
def get_vulns_hosts():
    workspace_id = request.args.get('workspace')
    session = create_session()
    resp_data = VulnsController.get_vulns_hosts(session, workspace_id)
    session.close()
    return json.dumps(resp_data, indent=4, sort_keys=True, default=str)


#Получить top_os_name
@app.route('/get_distinct_os_name',methods=['GET', 'POST'])
@jwt_required()
def get_distinct_os_name():
    workspace_id = request.args.get('workspace')
    session = create_session()
    resp_data = HostsController.get_distinct_os_name(session, workspace_id)
    session.close()
    return json.dumps(resp_data, indent=4, sort_keys=True, default=str)


#Получить top_creds
@app.route('/get_top_creds',methods=['GET', 'POST'])
@jwt_required()
def get_top_creds():
    workspace_id = request.args.get('workspace')
    session = create_session()
    resp_data = CredsController.get_top_creds(session, workspace_id)
    session.close()
    return json.dumps(resp_data, indent=4, sort_keys=True, default=str)


#Получить purpose_hosts
@app.route('/get_distinct_purpose',methods=['GET', 'POST'])
@jwt_required()
def get_distinct_purpose():
    workspace_id = request.args.get('workspace')
    session = create_session()
    resp_data = HostsController.get_distinct_purpose(session, workspace_id)
    session.close()
    return json.dumps(resp_data, indent=4, sort_keys=True, default=str)


#Получить purpose_os_name
@app.route('/get_distinct_os',methods=['GET', 'POST'])
@jwt_required()
def get_distinct_os():
    workspace_id = request.args.get('workspace')
    session = create_session()
    resp_data = HostsController.get_distinct_os(session, workspace_id)
    session.close()
    return json.dumps(resp_data, indent=4, sort_keys=True, default=str)


#Учетные записи с различными правами
@app.route('/get_distinct_creds_type',methods=['GET', 'POST'])
@jwt_required()
def get_distinct_creds_type():
    workspace_id = request.args.get('workspace')
    session = create_session()
    resp_data = CredsController.get_distinct_creds_type(session, workspace_id)
    session.close()
    return json.dumps(resp_data, indent=4, sort_keys=True, default=str)


#Получить количество hosts,services,notes,creds,vulns,loots
@app.route('/api/v1/CountInformation',methods=['GET', 'POST'])
@jwt_required()
def get_count_info():
    dd = {'hosts':0,'services':0,'notes':0,'creds':0,'vulns':0,'loots':0}
    session = create_session()
    dd['loots'] = LootsController.get_count(session, int(request.json['data']['workspace']), request.json['data']['data'])
    dd['hosts'] = HostsController.get_count(session, int(request.json['data']['workspace']), request.json['data']['data'])
    dd['services'] = ServicesController.get_count(session, int(request.json['data']['workspace']), request.json['data']['data'])
    dd['notes'] = NotesController.get_count(session, int(request.json['data']['workspace']), request.json['data']['data'])
    dd['vulns'] = VulnsController.get_count(session, int(request.json['data']['workspace']), request.json['data']['data'])
    dd['creds'] = CredsController.get_count(session, int(request.json['data']['workspace']), request.json['data']['data'])
    dd['web'] = WebController.get_count(session, int(request.json['data']['workspace']), request.json['data']['data'])
    dd['sessions'] = SessionsController.get_count(session, int(request.json['data']['workspace']), request.json['data']['data'])
    session.close()
    return  json.dumps(dd)