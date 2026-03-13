from workspace import app 
from flask import request
import json
import base64
from flask_jwt_extended import jwt_required
from flask_cors import cross_origin
from workspace.db_connect import create_session
from workspace.controllers import WebController, general


#Получить заметки(notes) для выбранного workspace
@app.route('/api/v1/Web/Sites',methods=['GET', 'POST'])
@jwt_required()
def get_web_sites():
    session = create_session()
    resp_data = WebController.getDataSites(session, request.json['data']['workspace'], request.json['data']['data'])
    session.close()
    return resp_data


#Получить структуру сайта
@app.route('/api/v1/Web/Sites/Struct',methods=['GET', 'POST'])
# @jwt_required()
def get_web_sites_struct():
    session = create_session()
    workspace_id = 20
    site_id = 768
    resp_data = WebController.getDataSiteStruct(session, request.json['data']['workspace'], request.json['data']['site_id'])
    session.close()
    return resp_data


#Получить pages 
@app.route('/api/v1/Web/Sites/Page/Info',methods=['GET', 'POST'])
# @jwt_required()
def get_web_sites_pages():
    session = create_session()
    resp_data = WebController.getDataSitePages(session, request.json['data']['workspace'], request.json['data']['page_id'])
    session.close()
    return resp_data


#Получить forms 
@app.route('/api/v1/Web/Sites/Form/Info',methods=['GET', 'POST'])
# @jwt_required()
def get_web_sites_forms():
    session = create_session()
    resp_data = WebController.getDataSiteForms(session, request.json['data']['workspace'], request.json['data']['page_id'])
    session.close()
    return resp_data


#Получить vulns 
@app.route('/api/v1/Web/Sites/Vuln/Info',methods=['GET', 'POST'])
# @jwt_required()
def get_web_sites_vulns():
    session = create_session()
    resp_data = WebController.getDataSiteVulns(session, request.json['data']['workspace'], request.json['data']['page_id'])
    session.close()
    return resp_data


#Получить pages, forms, vulns  
@app.route('/api/v1/Web/Sites/PathInfo',methods=['GET', 'POST'])
# @jwt_required()
def get_web_sites_path_info():
    data = request.json['data']
    session = create_session()
    resp_data = WebController.getDataSitePath(session, data['workspace'], data['site_id'], data['fullpath'], data['type'])
    session.close()
    return resp_data


#Del Path  
@app.route('/api/v1/Web/Sites/delPath',methods=['GET', 'POST'])
# @jwt_required()
def del_sites_path():
    data = request.json['data']
    session = create_session()
    resp_data = WebController.deletePath(session, data['workspace'], data['site_id'], data['path'])
    session.close()
    return resp_data


#Получить count pages, forms, vulns 
@app.route('/api/v1/Web/Sites/CountInfo',methods=['GET', 'POST'])
# @jwt_required()
def get_web_sites_count_info():
    session = create_session()
    resp_data = WebController.getDataSiteCountInfo(session, request.json['data']['workspace'], request.json['data']['site_id'], request.json['data']['fullpath'])
    session.close()
    return resp_data


#Добавить pages, forms, vulns 
@app.route('/api/v1/Web/Sites/addInfo',methods=['POST'])
@jwt_required()
def add_card_info():
    data = request.json['data']
    session = create_session()
    resp_data = WebController.add_card_info(session, int(data['site_id']), data['type'], general.JSON_deserialize(data['data']))
    session.close()
    return resp_data


#Add comment 
@app.route('/api/v1/Web/Sites/addComment',methods=['POST'])
@jwt_required()
def add_site_comment():
    data = request.json['data']
    session = create_session()
    resp_data = WebController.addSiteComment(session, int(data['site_id']), general.JSON_deserialize(data['data']))
    session.close()
    return resp_data


#Edit Page
@app.route('/api/v1/Web/Sites/Page/editItem',methods=['POST'])
@jwt_required()
def edit_site_page():
    data = request.json['data']
    session = create_session()
    resp_data = WebController.editPage(session, int(data['workspace']), general.JSON_deserialize(data['data']))
    session.close()
    return resp_data


#Edit Form
@app.route('/api/v1/Web/Sites/Form/editItem',methods=['POST'])
@jwt_required()
def edit_site_form():
    data = request.json['data']
    session = create_session()
    resp_data = WebController.editForm(session, int(data['workspace']), general.JSON_deserialize(data['data']))
    session.close()
    return resp_data


#Edit Vuln
@app.route('/api/v1/Web/Sites/Vuln/editItem',methods=['POST'])
@jwt_required()
def edit_site_vuln():
    data = request.json['data']
    session = create_session()
    resp_data = WebController.editVuln(session, int(data['workspace']), general.JSON_deserialize(data['data']))
    session.close()
    return resp_data


#Del Page
@app.route('/api/v1/Web/Sites/Page/delItem',methods=['POST'])
@jwt_required()
def del_site_page():
    data = request.json['data']
    session = create_session()
    resp_data = WebController.delPage(session, int(data['workspace']), int(data['page_id']))
    session.close()
    return resp_data


#Del Form
@app.route('/api/v1/Web/Sites/Form/delItem',methods=['POST'])
@jwt_required()
def del_site_form():
    data = request.json['data']
    session = create_session()
    resp_data = WebController.delForm(session, int(data['workspace']), int(data['form_id']))
    session.close()
    return resp_data


#Del Vuln
@app.route('/api/v1/Web/Sites/Vuln/delItem',methods=['POST'])
@jwt_required()
def del_site_vuln():
    data = request.json['data']
    session = create_session()
    resp_data = WebController.delVuln(session, int(data['workspace']), int(data['vuln_id']))
    session.close()
    return resp_data


# #Получить уникальные наименования ntype
# @app.route('/api/v1/Notes/UnicType',methods=['GET'])
# @jwt_required()
# def get_unic_ntype():
#     session = create_session()
#     resp_data = None
#     resp_data = NotesController.getUnicNtype(session)
#     session.close()
#     return resp_data


#Add Site
@app.route('/api/v1/Web/Sites/addItem',methods=['POST'])
@jwt_required()
def add_site():
    data = request.json['data']
    session = create_session()
    resp_data = WebController.addSite(session, int(data['workspace']), general.JSON_deserialize(data['data']))
    session.close()
    return resp_data

#Edit Site
@app.route('/api/v1/Web/Sites/editItem',methods=['POST'])
@jwt_required()
def edit_site():
    data = request.json['data']
    session = create_session()
    resp_data = WebController.editSite(session, int(data['workspace']), general.JSON_deserialize(data['data']))
    session.close()
    return resp_data


# #Добавить заметки(notes) для выбранного workspace
# @app.route('/api/v1/Notes/editItem',methods=['POST'])
# @jwt_required()
# def edit_notes():
#     data = request.json['data']
#     session = create_session()
#     resp_data = NotesController.edit_notes(session, int(data['workspace']), general.JSON_deserialize(data['data']))
#     session.close()
#     return resp_data


# #Del
# @app.route('/api/v1/Notes/delItem',methods=['POST'])
# @jwt_required()
# def del_notes():
#     data = request.json['data']
#     if(str(type(data)) == "<class 'list'>"):
#         data_temp = list(data['data'])
#         for item in data:
#             session = create_session()
#             resp = NotesController.del_Note_by_id(session, int(data['workspace']), int(item))
#             session.close()
#             if(resp["status"] == 200):
#                 data_temp.remove(item)
#         if (len(data_temp) != 0 and data_temp != data):
#             return {'status': 210, 'message':'Не все записи удалены', "data": data_temp}
#         else:
#             return {'status' :200, 'message': ''}
#     elif(str(type(data)) == "<class 'dict'>"):
#             session = create_session()
#             resp_data = NotesController.del_Note_by_id(session, int(data['workspace']), int(data['data']))
#             session.close()
#             return resp_data
