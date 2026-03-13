import ipaddress
from sqlalchemy.orm import Session
from datetime import datetime
from workspace.controllers import HostsController, ServicesController
from workspace.models.migration import Hosts, Events, Tags, HostsTags, Services, Notes, Loots, MetasploitCredentialCores, MetasploitCredentialLogins, MetasploitCredentialRealms, MetasploitCredentialPublics, MetasploitCredentialPrivates, MetasploitCredentialOriginCrackedPasswords, MetasploitCredentialOriginSessions, MetasploitCredentialOriginServices, Sessions, Vulns, VulnDetails, VulnAttempts, VulnsRefs, Refs
import workspace.logger as logging
from flask import jsonify

from sqlalchemy import and_, func, distinct
from sqlalchemy.orm import aliased
from sqlalchemy.dialects import postgresql
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.sql import label

from workspace.controllers.Parsers import apply_dynamic_filters


log = logging.getLogger()



def getData (db_session: Session, workspace_id: int, arg) -> dict:
    try:
        host_json = (
            func.jsonb_build_object('id', Hosts.id, 'address', Hosts.address, 'purpose', Hosts.purpose, 'os_family', Hosts.os_family)
        ).label('host')
        service_json = (
            func.jsonb_build_object('id', Services.id, 'port', Services.port, 'proto', Services.proto, 'name', Services.name)
        ).label('service')
        q = (
                db_session.query(
                Loots.id,
                host_json,
                service_json,
                Loots.ltype,
                Loots.path,
                Loots.name,
                Loots.info,
                Loots.content_type,
                Loots.data
            )
            .outerjoin(Hosts, Loots.host_id == Hosts.id)
            .outerjoin(HostsTags, HostsTags.host_id == Hosts.id)
            .outerjoin(Tags, Tags.id == HostsTags.tag_id)
            .outerjoin(Services, Services.id == Loots.service_id)
            .outerjoin(Notes, Notes.host_id == Hosts.id)
            .outerjoin(MetasploitCredentialLogins, MetasploitCredentialLogins.service_id == Services.id)
            .outerjoin(MetasploitCredentialCores, MetasploitCredentialCores.id == MetasploitCredentialLogins.core_id)
            .outerjoin(MetasploitCredentialRealms, MetasploitCredentialRealms.id == MetasploitCredentialCores.realm_id)
            .outerjoin(MetasploitCredentialPrivates, MetasploitCredentialPrivates.id == MetasploitCredentialCores.private_id)
            .outerjoin(MetasploitCredentialPublics, MetasploitCredentialPublics.id == MetasploitCredentialCores.public_id)
            .outerjoin(MetasploitCredentialOriginCrackedPasswords, MetasploitCredentialOriginCrackedPasswords.metasploit_credential_core_id == MetasploitCredentialCores.public_id)
            .outerjoin(MetasploitCredentialOriginServices, MetasploitCredentialOriginServices.service_id == Services.id)
            .outerjoin(Sessions, Sessions.host_id == Hosts.id)
            .outerjoin(MetasploitCredentialOriginSessions, MetasploitCredentialOriginSessions.session_id == Sessions.id)
            .outerjoin(Vulns, Vulns.host_id == Hosts.id)
            .outerjoin(VulnDetails, VulnDetails.vuln_id == Vulns.id)
            .outerjoin(VulnAttempts, VulnAttempts.vuln_id == Vulns.id)
            .outerjoin(VulnsRefs, VulnsRefs.vuln_id == Vulns.id)
            .outerjoin(Refs, Refs.id == VulnsRefs.ref_id)
            .filter(Loots.workspace_id == workspace_id)
            .group_by(Hosts.id)
            .group_by(Services.id)
            .group_by(Loots.id)
            .order_by(Hosts.address)
        )

        q = apply_dynamic_filters(q, arg)
        return jsonify([dict(r) for r in q.all()]), 200  
    except Exception as e:
        log.error("Error in controllers `LootsController` function  `getData`. Details - {0}".format(str(e)))
        return {"status": 500, "message": str(e) }


#Получить уникальные наименования ltype
def getUnicLtype(db_session: Session) -> dict:
    dd = []
    select_statement = ''
    try:
        select_statement = '''SELECT DISTINCT ltype FROM loots ORDER BY ltype ASC'''
        result_set = db_session.execute(select_statement)
        return jsonify([dict(r) for r in result_set]), 200 
    except Exception as e:
        log.error("Error in controllers `LootsController` function  `getUnicLtype`. Details - {0}".format(str(e)))
        return {"status": 500, "message": str(e) }


#Добавить запись
def add_loots(db_session: Session, workspace_id: int, data: dict):
    try:
        host = None
        host_id = None
        service_id = []
        loots = []
        #Get host id
        if(str(type(data['host'])) == "<class 'dict'>"):
           host_id = data['host']['id']
        else:
            host_id = HostsController.get_host_id(db_session, workspace_id, data['host'])
        
        if(str(type(host_id)) == "<class 'int'>"):
            host = db_session.query(func.jsonb_build_object('id', Hosts.id, 'address', Hosts.address, 'purpose', Hosts.purpose, 'os_family', Hosts.os_family)).filter_by(workspace_id = int(workspace_id), id = host_id).first()
            host= dict(host[0])
        
        data['host_id'] = host_id

        #Get services id
        if(str(type(data['service'])) == "<class 'list'>"):
            for service in data['service']:
               service_id.append(service['id']) 

       #Option 1: length service_id - 0
        if(len(service_id) == 0):
            data['service_id'] = None
            loot = Loots(workspace_id)
            db_session.add(loot)
            loot.update_state(data)
            db_session.flush()
            loots = {"id": loot.id, "service": None, "host": host, "created_at": loot.created_at.strftime("%d.%m.%Y"), "updated_at": loot.updated_at.strftime("%d.%m.%Y")}
       #Option 2: length service_id > 0 
        if(len(service_id) > 0 and host_id != None): 
            for service in service_id:
                loot = Loots(workspace_id)
                db_session.add(loot)
                data['service_id'] = service
                loot.update_state(data)
                db_session.flush()
                loots.append({"id":loot.id, "service": service, "host": host, "created_at": loot.created_at.strftime("%d.%m.%Y"), "updated_at": loot.updated_at.strftime("%d.%m.%Y")})
        
        db_session.commit()
        return {'status':200, 'loot': loots}
    except Exception as e:
        log.error("Error in controllers `LootsController` function  `add_loots`. Details - {0}".format(str(e)))
        return {"status": 500, "message": str(e) }


#Функция редактирования записи
def edit_loots(db_session: Session, workspace_id: int, data: dict):
    try:
        host = None
        host_id = None
        service_id = None
        #Get host id
        if(str(type(data['host'])) == "<class 'dict'>"):
           host_id = data['host']['id']
        else:
            host_id = HostsController.get_host_id(db_session, workspace_id, data['host'])

        if(str(type(host_id)) == "<class 'int'>"):
            host = db_session.query(func.jsonb_build_object('id', Hosts.id, 'address', Hosts.address, 'purpose', Hosts.purpose, 'os_family', Hosts.os_family)).filter_by(workspace_id = int(workspace_id), id = host_id).first()
            host= dict(host[0])

        #Get service id
        if(str(type(data['service'])) == "<class 'dict'>"):
           service_id = data['service']['id']
        else:
            if(data['service'] != None):
                service_id = ServicesController.get_service_id(workspace_id, data['service']['proto'], data['service']['name'], data['service']['port'], host['address'])
        
        data['host_id'] = host_id
        data['service_id'] = service_id
        loot = db_session.query(Loots).filter_by(id = data['id']).first()
        loot.update_state(data)
        db_session.flush()
        db_session.commit()
        return {'status':200, 'id': loot.id, 'updated_at': loot.updated_at.strftime("%d.%m.%Y"), 'host': host  }
    except Exception as e:
        log.error("Error in controllers `LootsController` function  `edit_loots`. Details - {0}".format(str(e)))
        return {"status": 501, "message": str(e)}


#Удаление записи из таблицы loots. Входные данные - id
def del_loots(db_session: Session, workspace_id: int, id: int):
    try:
        db_session.query(Loots).filter_by(id = id).delete()
        db_session.flush()
        db_session.commit()
        return {"status": 200, "message": ''}
    except Exception as e:
        log.error("Error in controllers `LootsController` function  `del_loots`. Details - {0}".format(str(e)))
        return {"status": 500, "message": str(e)}


#Удаление записи из таблицы loots. Входные данные - host_id
def del_loots_by_HostID(db_session: Session, host_id: int):
    res = {'rsp_k':410,'message':'Не удалось удалить запись!'}
    try:
        db_session.query(Loots).filter_by(host_id = host_id).delete()
        db_session.flush()
        db_session.commit()
        res = {'rsp_k':200}
    except Exception as e:
        log.error("Ошибка при удалении записи в таблице loots (workspace_id - {0}).".format(''))
        db_session.rollback()
    return res


#Удаление записи из таблицы loots. Входные данные - service_id
def del_loots_by_ServiceID(db_session: Session, service_id: int):
    res = {'rsp_k':410,'message':'Не удалось удалить запись!'}
    try:
        db_session.query(Loots).filter_by(service_id = service_id).delete()
        db_session.flush()
        db_session.commit()
        res = {'rsp_k':200}
    except Exception as e:
        log.error("Ошибка при удалении записи в таблице loots (workspace_id - {0}).".format(''))
        db_session.rollback()
    return res


#Количество loots
def get_count(db_session: Session, workspace_id: int, arg) -> int:
    try:
        q = (
                db_session.query(
                func.count(distinct(Loots.id)).label('loots')
            )
            .outerjoin(Hosts, Loots.host_id == Hosts.id)
            .outerjoin(HostsTags, HostsTags.host_id == Hosts.id)
            .outerjoin(Tags, Tags.id == HostsTags.tag_id)
            .outerjoin(Services, Services.id == Loots.service_id)
            .outerjoin(Notes, Notes.host_id == Hosts.id)
            .outerjoin(MetasploitCredentialLogins, MetasploitCredentialLogins.service_id == Services.id)
            .outerjoin(MetasploitCredentialCores, MetasploitCredentialCores.id == MetasploitCredentialLogins.core_id)
            .outerjoin(MetasploitCredentialRealms, MetasploitCredentialRealms.id == MetasploitCredentialCores.realm_id)
            .outerjoin(MetasploitCredentialPrivates, MetasploitCredentialPrivates.id == MetasploitCredentialCores.private_id)
            .outerjoin(MetasploitCredentialPublics, MetasploitCredentialPublics.id == MetasploitCredentialCores.public_id)
            .outerjoin(MetasploitCredentialOriginCrackedPasswords, MetasploitCredentialOriginCrackedPasswords.metasploit_credential_core_id == MetasploitCredentialCores.public_id)
            .outerjoin(MetasploitCredentialOriginServices, MetasploitCredentialOriginServices.service_id == Services.id)
            .outerjoin(Sessions, Sessions.host_id == Hosts.id)
            .outerjoin(MetasploitCredentialOriginSessions, MetasploitCredentialOriginSessions.session_id == Sessions.id)
            .outerjoin(Vulns, Vulns.host_id == Hosts.id)
            .outerjoin(VulnDetails, VulnDetails.vuln_id == Vulns.id)
            .outerjoin(VulnAttempts, VulnAttempts.vuln_id == Vulns.id)
            .outerjoin(VulnsRefs, VulnsRefs.vuln_id == Vulns.id)
            .outerjoin(Refs, Refs.id == VulnsRefs.ref_id)
            .filter(Loots.workspace_id == workspace_id)
            .group_by(Hosts.id)
            .group_by(Services.id)
            .group_by(Loots.id)
            .order_by(Hosts.address)
        )

        q = apply_dynamic_filters(q, arg)
        return len([dict(r) for r in q.all()]) 
    except Exception as e:
        log.error("Error in controllers `LootsController` function  `get_count`. Details - {0}".format(str(e)))
        return None