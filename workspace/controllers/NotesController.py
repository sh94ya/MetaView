import ipaddress
import json
from sqlalchemy.orm import Session
from datetime import datetime
from workspace.controllers import CredsController, LootsController, NotesController, ServicesController, HostsController, VulnsController
from workspace.models.migration import Hosts, Events, Tags, HostsTags, Services, Notes, Loots, MetasploitCredentialCores, MetasploitCredentialLogins, MetasploitCredentialRealms, MetasploitCredentialPublics, MetasploitCredentialPrivates, MetasploitCredentialOriginCrackedPasswords, MetasploitCredentialOriginSessions, MetasploitCredentialOriginServices, Sessions, Vulns, VulnDetails, VulnAttempts, VulnsRefs, Refs
import workspace.logger as logging
from flask import jsonify

from sqlalchemy import and_, func, distinct
from sqlalchemy.orm import aliased
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.sql import label

from workspace.controllers.Parsers import apply_dynamic_filters

log = logging.getLogger()



def getDataNotes (db_session: Session, workspace_id: int, arg) -> dict:
    dd = []
    try:
        host_json = (
            func.jsonb_build_object('id', Hosts.id, 'address', Hosts.address, 'purpose', Hosts.purpose, 'os_family', Hosts.os_family)
        ).label('host')
        service_json = (
            func.jsonb_build_object('id', Services.id, 'port', Services.port, 'proto', Services.proto, 'name', Services.name)
        ).label('service')
        q = (
                db_session.query(
                Notes.id,
                host_json,
                service_json,
                Notes.ntype,
                Notes.data
            )
            .outerjoin(Hosts, Notes.host_id == Hosts.id)
            .outerjoin(HostsTags, HostsTags.host_id == Hosts.id)
            .outerjoin(Tags, Tags.id == HostsTags.tag_id)
            .outerjoin(Services, Services.id == Notes.service_id)
            .outerjoin(Loots, Loots.host_id == Hosts.id)
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
            .filter(Notes.workspace_id == workspace_id)
            .group_by(Hosts.id)
            .group_by(Services.id)
            .group_by(Notes.id)
            .order_by(Hosts.address)
        )

        q = apply_dynamic_filters(q, arg)
        return jsonify([dict(r) for r in q.all()]), 200  
    except Exception as e:
        log.error("Error in controllers `NotesController` function  `getDataNotes`. Details - {0}".format(str(e)))
        return {"status": 500, "message": str(e) }


#Получить уникальные наименования ntype
def getUnicNtype(db_session: Session) -> dict:
    try:
        select_statement = "SELECT DISTINCT ntype FROM notes WHERE ntype != '' OR ntype != NULL ORDER BY ntype ASC"
        result_set = db_session.execute(select_statement)
        return jsonify([dict(r) for r in result_set]), 200 
    except Exception as e:
        log.error("Error in controllers `NotesController` function  `getUnicNtype`. Details - {0}".format(str(e)))
        return {"status": 500, "message": str(e) }


#Получить заметки по адресу, сервису, типу записи
def get_Notes_by_HostID(db_session: Session, workspace_id: int, host_id: int, service_id: int, data: dict):
    res = None
    try:
        for note in db_session.query(Notes).filter_by(host_id = host_id, service_id = service_id, ntype = data["ntype"]).limit(1):
            res = note.id
    except Exception as e:
        log.error("Ошибка при формировании подзапроса для функцииget_Notes_by_HostID таблицы notes (workspace_id - {0}, host_id - {1}, service_id - {2},).".format(workspace_id, host_id, service_id))
    return res


#Добавить запись
def add_notes(db_session: Session, workspace_id: int, data: dict):
    try:
        host = None
        host_id = None
        service_id = []
        notes = []
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
        
        if(str(type(data['service'])) == "<class 'dict'>"):
            service_id.append( data['service']['id']) 

       #Option 1: length service_id - 0
        if(len(service_id) == 0):
            data['service_id'] = None
            note = Notes(workspace_id)
            db_session.add(note)
            note.update_state(data)
            db_session.flush()
            notes = {"id": note.id, "service": None, "host": host, "created_at": note.created_at.strftime("%d.%m.%Y"), "updated_at": note.updated_at.strftime("%d.%m.%Y")}
       #Option 2: length service_id > 0 
        if(len(service_id) > 0 and host_id != None): 
            for service in service_id:
                note = Notes(workspace_id)
                db_session.add(note)
                data['service_id'] = service
                note.update_state(data)
                db_session.flush()
                notes.append({"id":note.id, "service": service, "host": host, "created_at": note.created_at.strftime("%d.%m.%Y"), "updated_at": note.updated_at.strftime("%d.%m.%Y")})
        
        db_session.commit()
        return {'status':200, 'note': notes }
    except Exception as e:
        log.error("Error in controllers `NotesController` function  `add_notes`. Details - {0}".format(str(e)))
        return {"status": 501, "message": str(e)}


#Редактировать заметки(notes)
def edit_notes(db_session: Session, workspace_id: int, data: dict):
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
        note = db_session.query(Notes).filter_by(id = data['id']).first()
        note.update_state(data)
        db_session.flush()
        db_session.commit()
        return {'status':200, 'id': note.id, 'updated_at': note.updated_at.strftime("%d.%m.%Y"), 'host': host  }
    except Exception as e:
        log.error("Error in controllers `NotesController` function  `edit_notes`. Details - {0}".format(str(e)))
        return {"status": 501, "message": str(e)}



#Удаление заметок(notes). Входные данные - id записи 
def del_Note_by_id(db_session: Session, workspace_id: int, data: int):
    try:
        db_session.query(Notes).filter_by(id = data).delete()
        db_session.flush()
        db_session.commit()
        return {"status": 200, "message": ''}
    except Exception as e:
        log.error("Error in controllers `NotesController` function  `del_Note_by_id`. Details - {0}".format(str(e)))
        return {"status": 500, "message": str(e)}


#Удаление заметок(notes). Входные данные - список 
def del_Notes_by_List(db_session: Session, data: list):
    dd = data
    for item in data:
        res = del_Note_by_id(db_session, item)
        if(res["rsp_k"]) == 200:
            dd.remove(item)
    return dd


#Удаление заметок(notes). Входные данные - service_id 
def del_Notes_by_ServiceID(db_session: Session, service_id: int):
    res = {'rsp_k':410,'message':'Не удалось удалить запись!'}
    try:
        db_session.query(Notes).filter_by(service_id = service_id).delete()
        db_session.flush()
        db_session.commit()
        res = {'rsp_k':200}
    except Exception as e:
        log.error("Ошибка при удалении записи в таблицу notes (workspace_id - {0}).".format(''))
    return res


#Удаление заметок(notes). Входные данные - host_id 
def del_Notes_by_HostID(db_session: Session, host_id: int):
    res = {'rsp_k':410,'message':'Не удалось удалить запись!'}
    try:
        db_session.query(Notes).filter_by(host_id = host_id).delete()
        db_session.flush()
        db_session.commit()
        res = {'rsp_k':200}
    except Exception as e:
        log.error("Ошибка при удалении записи в таблицу notes (workspace_id - {0}).".format(''))
    return res


#Количество заметок(notes)
def get_count(db_session: Session, workspace_id: int, arg) -> int:
    try:
        q = (
                db_session.query(
                func.count(distinct(Notes.id)).label('notes')
            )
            .outerjoin(Hosts, Notes.host_id == Hosts.id)
            .outerjoin(HostsTags, HostsTags.host_id == Hosts.id)
            .outerjoin(Tags, Tags.id == HostsTags.tag_id)
            .outerjoin(Services, Services.id == Notes.service_id)
            .outerjoin(Loots, Loots.host_id == Hosts.id)
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
            .filter(Notes.workspace_id == workspace_id)
            .group_by(Hosts.id)
            .group_by(Services.id)
            .group_by(Notes.id)
            .order_by(Hosts.address)
        )

        q = apply_dynamic_filters(q, arg)
        return len([dict(r) for r in q.all()]) 
    except Exception as e:
        log.error("Error in controllers `NotesController` function  `get_count`. Details - {0}".format(str(e)))
        return None