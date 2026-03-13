from workspace import app 
from flask import request
import json
import base64
from datetime import timedelta
from flask_jwt_extended import jwt_required, create_access_token, current_user
from flask_cors import cross_origin
from workspace.db_connect import create_session
from workspace.controllers import UsersController, general


#Создание учетной записи администратора
@app.before_first_request
def create_admin():
    session = create_session()
    UsersController.create_admin(session)
    session.close()


#Логин
@app.route("/login", methods=['GET', 'POST'])
def login():
    username = request.json['data']['username']
    password = request.json['data']['password']
    session = create_session()
    validation = UsersController.validation(session, username, password)
    session.close()
    if (validation):
        user = validation[1]
        del user["crypted_password"]
        del user["password_salt"]
        del user["persistence_token"]
        user["token"] = create_access_token(identity=username, expires_delta=timedelta(48))
        return {'status':200, 'user': user}
    else:
         return {'status':503,'message':'Не правильный логин или пароль'}


#Получить всех пользователей
@app.route("/api/get_users", methods=['GET', 'POST'])
@jwt_required()
def get_users():
    if(current_user[0]['admin']== True):
        session = create_session()
        resp_data = UsersController.get_users(session)
        session.close()
        return json.dumps(resp_data, indent=4, sort_keys=True, default=str)
    else:
        return json.dumps({'rsp_k':420,'message':'Нехватает прав для совершения операции!'})


@app.route("/api/v1/Users", methods=['GET'])
@jwt_required()
def get_users_info():
    session = create_session()
    fulldata = request.args.get('fulldata')
    resp_data = UsersController.get_all_users(session, request.args)
    session.close()
    return  json.dumps(resp_data, indent=4, sort_keys=True, default=str)


#Добавить пользователя
@app.route("/api/v1/Users/addItem", methods=['POST'])
@jwt_required()
def add_users():
    data = request.json['data']
    if(current_user.admin == True):
        session = create_session()
        resp_data = UsersController.add_user(session, general.JSON_deserialize(data['data']))
        session.close()
        return  resp_data
    else:
        return {'status':420,'message':'Нехватает прав для совершения операции!'}


#Редактировать пользователя
@app.route("/api/v1/Users/editItem", methods=['POST'])
@jwt_required()
def edit_user():
    data = request.json['data']
    if(current_user.admin== True):
        session = create_session()
        resp_data = UsersController.edit_user(session, general.JSON_deserialize(data['data']))
        session.close()
        return  resp_data
    else:
        return {'status':420,'message':'Нехватает прав для совершения операции!'}


#Удалить пользователя
@app.route("/api/v1/Users/delItem", methods=['POST'])
@jwt_required()
def del_users():
    data = request.json['data']
    if(current_user.admin== True):
        if(str(type(data['data'])) == "<class 'list'>"):
            data_temp = list(data['data'])
            for item in data:
                session = create_session()
                resp = UsersController.del_user(session, int(item))
                session.close()
                if(resp["status"] == 200):
                    data_temp.remove(item)
            if (len(data_temp) != 0 and data_temp != data):
                return {'status': 210, 'message':'Не все записи удалены', "data": data_temp}
            else:
                return {'status' :200, 'message': ''}
        elif(str(type(data['data'])) == "<class 'int'>"):
                session = create_session()
                resp_data = UsersController.del_user(session, int(data['data']))
                session.close()
                return resp_data
        # session = create_session()
        # resp_data = UsersController.del_user(session, general.JSON_deserialize(data['data']))
        # session.close()
        return  resp_data
    else:
        return {'status':420,'message':'Нехватает прав для совершения операции!'}


#Сменить пароль пользователя
@app.route("/api/v1/User/changePassword", methods=['POST'])
@jwt_required()
def change_password():
    username = request.json['data']['username']
    password = request.json['data']['password']
    session = create_session()
    if(current_user.admin == True):
        resp_data = UsersController.change_password(session, username, password)
    else:
        if(current_user.username == username):
            resp_data = UsersController.change_password(session, username, password)
        else:
            return json.dumps({'status':420,'message':'Нехватает прав для совершения операции!'})
    session.close()
    return  resp_data
