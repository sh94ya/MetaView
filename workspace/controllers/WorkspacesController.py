import json
from sqlalchemy import inspect
from sqlalchemy.orm import Session
from datetime import datetime
from workspace import routes, db_connect
from workspace.controllers import HostsController, UserTasksController
from workspace.models.migration import Workspaces, Hosts, UserTasks, Users, WorkspaceMembers
from flask import jsonify

from sqlalchemy import Table, and_, or_, func, distinct, select, exists

import workspace.logger as logging

log = logging.getLogger()


#Добавить workspace
def add_workspace(db_session: Session, data: dict):
    try:
        workspace_id = None 
        for item in db_session.query(Workspaces).filter_by(name = data["name"]).limit(1):
            workspace_id = item.id
        if(workspace_id == None):
            workspace = Workspaces(data["name"])
            db_session.add(workspace)
            workspace.update_state(data)
            db_session.flush()

            if(data["members"] != None and data["name"] != []):
                for member_id in data["members"]:
                    member = WorkspaceMembers(workspace.id, member_id)
                    db_session.add(member)
                    db_session.flush()

            db_session.commit()
            return {'status':200,'id': workspace.id, 'created_at': workspace.created_at.strftime("%d.%m.%Y"), 'updated_at': workspace.updated_at.strftime("%d.%m.%Y")}
        else:
           return {'status':410,'message':'Запись с таким именем уже существует!'}
    except Exception as e:
        db_session.rollback()
        log.error("Error in controllers `WorkspacesController` function  `editItem`. Details - {0}".format( e._message))
        return {"status": 500, "message": e._message}


#Удалить workspace
def del_workspace(db_session: Session, data: dict):
    res = {'rsp_k':410,'message':'Не удалось удалить запись!'}
    try:
        db_session.query(Workspaces).filter_by(id = data).delete()
        db_session.flush()
        #Получаем все узлы для Workspace и удаляем их
        hosts_dict = []
        for item in db_session.query(Hosts).filter_by(workspace_id = data):
            hosts_dict.append(item.id)
        for item in hosts_dict:
            HostsController.del_hosts(db_session, data, item)

        #Получаем все задачи для Workspace
        users_tasks_dict = []
        for item in db_session.query(UserTasks).filter_by(workspace_id = data):
            users_tasks_dict.append(item.id)
        for item in hosts_dict:
            UserTasksController.del_tasks(db_session, data, item)

        db_session.commit()
        res = {'rsp_k':200}
    except Exception as e:
        log.error("Ошибка при удалении записи в таблице Workspaces (id - {0}).".format(''))
        db_session.rollback()
    return res


#Редактировать workspace
def edit_workspace(db_session: Session,  data: dict) -> dict:
    try:
        workspace = db_session.query(Workspaces).filter_by(id = data['id']).first()
        workspace.update_state(data)
        
        db_session.query(WorkspaceMembers).filter_by(workspace_id = workspace.id).delete()
        db_session.flush()
        if(data["members"] != None and data["name"] != []):
            for member_id in data["members"]:
                member = WorkspaceMembers(workspace.id, member_id)
                db_session.add(member)
                db_session.flush()

        db_session.commit()
        return {"status": 200, "id": workspace.id, "updated_at": workspace.updated_at.strftime("%d.%m.%Y")}
    except Exception as e:
        db_session.rollback()
        log.error("Error in controllers `WorkspacesController` function  `editItem`. Details - {0}".format( e._message))
        return {"status": 500, "message": e._message}


#Получить доступные workspaces
def getWorkspaces(db_session: Session):
    try:
        select_statement = '''SELECT
                                workspaces.*,
                                (SELECT json_build_object('id', u.id, 'username', u.username)
                                FROM users u
                                WHERE u.id = workspaces.owner_id) as owner,
                                (SELECT json_agg(json_build_object('id', u.id, 'username', u.username))
                                FROM users u
                                JOIN workspace_members wm ON wm.user_id = u.id
                                WHERE wm.workspace_id = workspaces.id) as members
                                FROM workspaces ORDER BY workspaces.id  DESC '''
        result_set = db_session.execute(select_statement)
        return jsonify([dict(r) for r in result_set]), 200 
    except Exception as e:
        log.error("Error in controllers `WorkspacesController` function  `getWorkspaces`. Details - {0}".format(str(e)))
        return {"status": 500, "message": str(e) }


#Получить name workspaces
def get_name_workspace(workspace_id):
    workspace_table = Table('workspaces',db_connect.meta,autoload=True)
    conn = db_connect.db.connect()
    select_statement  = select([workspace_table.c.name]).where(workspace_table.c.id == workspace_id)
    result_set = conn.execute(select_statement)
    dd =  [dict(r) for r in result_set]
    return(json.dumps(dd,indent=4, sort_keys=True, default=str))