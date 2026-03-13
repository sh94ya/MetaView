from datetime import datetime
from sqlalchemy.orm import Session
from workspace.models.migration import Users, WorkspaceMembers, Workspaces, MetasploitCredentialOriginManuals, UserTasksPerformers
import bcrypt
import workspace.logger as logging

log = logging.getLogger()


#Получить инфо по по всем пользователям
def get_all_users(db_session: Session, args) -> list:
    users = []

    for user_object in db_session.query(Users):
        if(args.get('fulldata') == None):
            user_dict = {"id": user_object.id,
                        "username": user_object.username,
                        "label": user_object.username,
                        "fullname": user_object.fullname}
        else:
            user_dict = user_object.to_dict()
            del user_dict['crypted_password']
            del user_dict['password_salt']
        
        users.append(user_dict)

    return users


#Получить инфо по выбранному пользователю
def get_current_user(db_session: Session, user_id: int, name_user: str):
    try:
        user = None
        if(user_id != None):
            user = db_session.query(Users).filter_by(id = int(user_id)).first()
        if(name_user != None):
            user = db_session.query(Users).filter_by(username = str(name_user)).first()
        return user
    except Exception as e:
        log.error("Error in controllers `UsersController` function  `get_current_user`. Details - {0}".format(str(e)))
        return None


#Валидация
def validation(db_session: Session, username: str, password: str):
    try:
        user = get_current_user(db_session, None, username)
        if(user):
            if(bcrypt.checkpw(password.encode('utf8'),user.crypted_password.encode('utf8'))):
                return True, user.to_dict()
            else:
                return False
    except Exception as e:
        log.error("Error in controllers `UsersController` function  `validation`. Details - {0}".format(str(e)))
        return False


#Создать пользователя admin
def create_admin(db_session: Session):
        data = {
            'username':'admin',
            'password': "admin",
            'fullname': "Administrator",
            'phone': "",
            'email': "", 
            'company': "",
            'admin': True
        }
        add_user(db_session, data)


#Создать пользователя
def add_user(db_session: Session, data: dict):
    try:
        user = db_session.query(Users).filter_by(username = data['username']).first()
        if(user == None):
            salt = bcrypt.gensalt()
            passwd = bcrypt.hashpw(data['password'].encode('utf8'), salt)
            user = Users(data['username'],
                        str(passwd.decode('utf8')),
                        str(salt.decode('utf8')),
                        data['fullname'],
                        data['email'],
                        data['phone'],
                        data['company'],
                        data['admin'])
            db_session.add(user)
            db_session.flush()
            db_session.commit()
            return {'status':200, 'id':user.id}
        else:
            return {'status':410,'message':'Такой пользователь уже существует!'}
    except Exception as e:
        log.error("Error in controllers `UsersController` function  `add_user`. Details - {0}".format(str(e)))
        return {"status": 500, "message": str(e) }


#Редактировать пользователя
def edit_user(db_session: Session, data: dict):
    try:
        user = db_session.query(Users).filter_by(id = data['id']).first()
        if(user):
            user.update_state(data)
            db_session.flush()
            db_session.commit()
            return {'status':200 }
        else:
            return {'status':410,'message':'Такого пользователя не существует!'}
    except Exception as e:
        log.error("Error in controllers `UsersController` function  `edit_user`. Details - {0}".format(str(e)))
        return {"status": 500, "message": str(e) }


#Получить данные р всех пользователях
def get_users(db_session: Session):
    dd = []
    try:
        select_statement = "SELECT id, username, fullname, email, phone, company, admin, prefs FROM users"
        result_set = db_session.execute(select_statement)
        dd = [dict(r) for r in result_set]
        return dd
    except Exception as e:
        log.error("Error function get_users-Users. Message: {0}".format(str(e)))


#Изменить пароль для пользователя
def change_password(db_session: Session, username: str, password: str):
    try:
        if(password!=None or password!=''):
            salt = bcrypt.gensalt()
            passwd = bcrypt.hashpw(password.encode('utf8'), salt)
            db_session.query(Users).filter_by(username = username).update(
                                                        {'crypted_password': str(passwd.decode('utf8')),
                                                        'password_salt': str(salt.decode('utf8')),
                                                        'updated_at': datetime.now()})
            db_session.flush()
            db_session.commit()
            return {'status':200,'message':'Пароль успешно изменен'}
        else:
            return {'status':410,'message':'Пароль не должен быть пустым!'}
    except Exception as e:
        log.error("Error in controllers `UsersController` function  `change_password`. Details - {0}".format(str(e)))
        return {"status": 500, "message": str(e) }


#Удалить пользователя
def del_user(db_session: Session, id: int):
    try:
        user = db_session.query(Users).filter_by(id = id).first()
        if(user.admin != True):
            db_session.query(Users).filter_by(id = id).delete()
            db_session.flush()

            db_session.query(WorkspaceMembers).filter_by(user_id = id).delete()
            db_session.flush()

            db_session.query(Workspaces).filter_by(owner_id = id).update({"owner_id": None})
            db_session.flush()

            db_session.query(MetasploitCredentialOriginManuals).filter_by(user_id = id).update({"user_id": None})
            db_session.flush()

            db_session.query(UserTasksPerformers).filter_by(user_id = id).delete()
            db_session.flush()

            db_session.commit()
            return {'status':200, 'message':'Пользователь удален!'}
        else:
           return {'status':410,'message':'Ползователя admin нельзя удалить!'}
    except Exception as e:
        log.error("Error in controllers `UsersController` function  `del_user`. Details - {0}".format(str(e)))
        db_session.rollback()
        return {"status": 500, "message": str(e) }