from workspace import app 
from flask import request
import json
import base64
from flask_jwt_extended import jwt_required
from flask_cors import cross_origin
from workspace.db_connect import create_session
from workspace.controllers import WorkspacesController, general


#Получить name workspaces
@app.route('/get_name_workspace',methods=['GET'])
@jwt_required()
def get_name_projects():
    workspace_id = request.args.get('workspace')
    workspace = WorkspacesController.get_name_workspace(workspace_id)
    return  workspace


#Получить доступные workspaces
@app.route('/api/v1/Workspaces',methods=['GET'])
@jwt_required()
def get_projects():
    session = create_session()
    resp_data = WorkspacesController.getWorkspaces(session)
    session.close()
    return  resp_data


#Добавление проекта
@app.route('/api/v1/Workspaces/addItem',methods=['POST'])
@jwt_required()
def add_project():
    data = request.json['data']
    session = create_session()
    resp_data = WorkspacesController.add_workspace(session, general.JSON_deserialize(data))
    session.close()
    return  resp_data


#Удаление проекта
@app.route('/api/v1/Workspaces/delItem',methods=['POST'])
@jwt_required()
def del_project():
    data = request.json['data']
    session = create_session()
    resp_data = WorkspacesController.del_workspace(session, int(data))
    session.close()
    return  resp_data


#Редактирование проекта
@app.route('/api/v1/Workspaces/editItem',methods=['POST'])
@jwt_required()
def edit_project():
    data = request.json['data']
    session = create_session()
    resp_data = WorkspacesController.edit_workspace(session, general.JSON_deserialize(data))
    session.close()
    return  resp_data
