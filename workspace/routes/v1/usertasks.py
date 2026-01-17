from workspace import app 
from flask import request
import json
import base64
from flask_jwt_extended import jwt_required
from flask_cors import cross_origin
from workspace.db_connect import create_session
from workspace.controllers import UserTasksController, general


#GetItem
@app.route('/api/v1/UserTasks',methods=['GET'])
@jwt_required()
def get_users_tasks():
    workspace_id = request.args.get('workspace')
    session = create_session()
    resp_data = UserTasksController.get_full_info_about_all_tasks(session, workspace_id)
    session.close()
    return json.dumps(resp_data, indent=4, sort_keys=True, default=str)


#Add Item
@app.route('/api/v1/UserTasks/addItem',methods=['POST'])
@jwt_required()
def add_task():
    data = request.json['data']
    session = create_session()
    resp_data = UserTasksController.add_task(session, int(data['workspace']), general.JSON_deserialize(data['data']))
    session.close()
    return json.dumps(resp_data)


#Remove Item
@app.route('/api/v1/UserTasks/delItem',methods=['POST'])
@jwt_required()
def del_task():
    data = request.json['data']
    session = create_session()
    resp_data = UserTasksController.del_tasks(session, int(data['workspace']), [int(data['data'])])
    session.close()
    return json.dumps(resp_data)


#Edit Item
@app.route('/api/v1/UserTasks/editItem',methods=['POST'])
@jwt_required()
def edit_task():
    data = request.json['data']
    session = create_session()
    resp_data = UserTasksController.edit_task(session, int(data['workspace']), general.JSON_deserialize(data['data']))
    session.close()
    return json.dumps(resp_data)
