import ipaddress
import json
from sqlalchemy.orm import Session
from datetime import datetime
from workspace.controllers import CredsController, HostsController, LootsController, NotesController, VulnsController
from workspace.models.migration import Hosts, Events, Tags, HostsTags, Services, Notes, Loots, MetasploitCredentialCores, MetasploitCredentialLogins, MetasploitCredentialRealms, MetasploitCredentialPublics, MetasploitCredentialPrivates, MetasploitCredentialOriginCrackedPasswords, MetasploitCredentialOriginSessions, MetasploitCredentialOriginServices, Sessions, Vulns, VulnDetails, VulnAttempts, VulnsRefs, Refs
import workspace.logger as logging
from flask import jsonify

from sqlalchemy import and_, func, distinct
from sqlalchemy.orm import aliased
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.sql import label
from workspace.db_connect import create_session

from workspace.controllers.Parsers import apply_dynamic_filters

log = logging.getLogger()


# Возвращает топ 5 служб
def get_top_service(db_session: Session, workspace_id : int) -> dict:
    dd = []
    select_statement = ''
    try:
        select_statement = '''SELECT services.port, services.proto, services.name, COUNT(services.port) AS count FROM services 
                                    INNER JOIN hosts ON hosts.id = services.host_id
                                    WHERE hosts.workspace_id = {0} AND  services.port != 0 
                                    GROUP BY services.port, services.proto, services.name
                                    ORDER BY COUNT(*) DESC LIMIT 5'''.format(str(int(workspace_id)))
        
        result_set = db_session.execute(select_statement)
        dd = [dict(r) for r in result_set]
        return dd
    except Exception as e:
        log.error("Error function get_top_service-Services (workspace_id - {0}).".format(workspace_id))


#Вспомогательная функция для get_services для 
def sub_query(sign1: str, node: dict, sign2: str, service_id: int) -> str:
    query = ''
    query_host = ''
    query_service = ''
    try:
        if(sign1 == "auto" and node['type'] != 'root'):
            if(node['type'] == 'subnet'):
                sign1 = "<<"
            else:
                sign1 = "="
        if(node['label'] != None and node['type'] == 'subnet'):
            query_host = " AND hosts.address {0} inet('".format(sign1)+str(ipaddress.ip_network(node['label'], strict=False))+"') "
        elif (node['type'] == 'host'):
            if 'host_id' in node:
                query_host = " AND hosts.id {0} {1} ".format(sign1, str(node['host_id']))
            else:
                query_host = " AND hosts.address {0} inet('{1}') ".format(sign1, str(ipaddress.ip_network(node["label"], strict=False)))

        if(service_id != None and sign2 != None):
            query_service = " AND service_id {0} {1} ".format(sign2,str(service_id))
        elif(service_id != None and sign2 == None):
            query_service = " AND service_id = {0} ".format(str(service_id))
        query = query_host + query_service
    except Exception as e:
        log.error("Error function sub_query-Services (node- {1} service_id - {2}).".format(node, service_id, e._message))
    return query


# Получить id сервиса по полям proto, service_name, port
def get_service_id(workspace_id: int, proto: str, service: str, port: int, address: str):
    res = None
    dd = []
    session = create_session()
    try:
        select_statement = '''SELECT services.id FROM services 
                                    INNER JOIN hosts ON hosts.id = services.host_id
                                    WHERE hosts.workspace_id = {0} AND hosts.id = {1} AND services.port = {2} AND services.proto = '{3}'
                                    LIMIT 1'''.format(str(int(workspace_id)), str(HostsController.get_host_id(session, workspace_id, address)), str(int(port)), str(proto))
        
        result_set = session.execute(select_statement)
        dd = [dict(r) for r in result_set]
        session.close()
        return dd[0]['id']
    except Exception as e:
        session.close()
        log.error("Error function get_service_id-Services (workspace_id - {0}, proto - {1}, service - {2}, port - {3}, address - {4}).".format(workspace_id, proto, service, port, address))
    return res


def getDataServices (db_session: Session, workspace_id: int, arg) -> dict:
    dd = []
    try:
        TagAlias = aliased(Tags)
        host_json = (
            func.jsonb_build_object('id', Hosts.id, 'address', Hosts.address, 'purpose', Hosts.purpose, 'os_family', Hosts.os_family)
        ).label('host')

        q = (
                db_session.query(
                Services.id,
                host_json,
                Services.port,
                Services.proto,
                Services.state,
                Services.name,
                Services.info
            )
            .select_from(Services)
            .outerjoin(Hosts, Hosts.id == Services.host_id)
            .outerjoin(HostsTags, HostsTags.host_id == Hosts.id)
            .outerjoin(Tags, Tags.id == HostsTags.tag_id)
            .outerjoin(Notes, Notes.host_id == Hosts.id)
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
            .outerjoin(Vulns, Vulns.service_id == Services.id)
            .outerjoin(VulnDetails, VulnDetails.vuln_id == Vulns.id)
            .outerjoin(VulnAttempts, VulnAttempts.vuln_id == Vulns.id)
            .outerjoin(VulnsRefs, VulnsRefs.vuln_id == Vulns.id)
            .outerjoin(Refs, Refs.id == VulnsRefs.ref_id)
            .filter(Hosts.workspace_id == workspace_id)
            .group_by(Services.id)
            .order_by(Hosts.address)
        )

        q = apply_dynamic_filters(q, arg)
        q.group_by(Services.id)
        return jsonify([dict(r) for r in q.all()]), 200  
    except Exception as e:
        log.error("Error in controllers `ServicesController` function  `getDataServices`. Details - {0}".format(str(e)))
        return {"status": 500, "message": str(e) }
    

#Добавить сервис
def add_services(db_session: Session, workspace_id: int, data: dict):
    try:
        if(str(type(data['host'])) == "<class 'dict'>"):
           host_id = data['host']['id']
        else:
            host_id = HostsController.get_host_id(db_session, workspace_id, data['host'])
        host = db_session.query(func.jsonb_build_object('id', Hosts.id, 'address', Hosts.address, 'purpose', Hosts.purpose, 'os_family', Hosts.os_family)).filter_by(workspace_id = int(workspace_id), id = host_id).first()
        host= dict(host[0])

        service = Services(host_id)
        db_session.add(service)
        service.update_state(data)
        db_session.flush()
        db_session.commit()
        return {'status':200, 'id': service.id, 'created_at': service.created_at.strftime("%d.%m.%Y"), 'updated_at': service.updated_at.strftime("%d.%m.%Y"), 'host': host }
    except Exception as e:
        log.error("Error in controllers `ServicesController` function  `add_services`. Details - {0}".format(str(e)))
        return {"status": 501, "message": str(e)}


#Редактировать сервисы
def edit_services(db_session: Session, workspace_id: int, data: dict):
    try:
        if(str(type(data['host'])) == "<class 'dict'>"):
           host_id = data['host']['id']
        else:
            host_id = HostsController.get_host_id(db_session, workspace_id, data['host'])
        host = db_session.query(func.jsonb_build_object('id', Hosts.id, 'address', Hosts.address, 'purpose', Hosts.purpose, 'os_family', Hosts.os_family)).filter_by(workspace_id = int(workspace_id), id = host_id).first()
        host= dict(host[0])
    
        service = db_session.query(Services).filter_by(id = data['id']).first()
        service.update_state(data)
        db_session.flush()
        db_session.commit()

        return {'status':200, 'id': service.id, 'updated_at': service.updated_at.strftime("%d.%m.%Y"), 'host': host }
    except Exception as e:
        log.error("Error in controllers `ServicesController` function  `edit_services`. Details - {0}".format(str(e)))
        return {"status": 501, "message": str(e)}


#Удалить сервис
def del_service(db_session: Session, workspace_id: int, id: int):
    try:     
        #Creds
        CredsController.del_creds_by_ServiceID(db_session, workspace_id, id)
        #Notes
        NotesController.del_Notes_by_ServiceID(db_session, id)
        #Vulns
        VulnsController.del_vulns_by_ServiceID(db_session, id)
        #Loots
        LootsController.del_loots_by_ServiceID(db_session, id)
        #Services
        db_session.query(Services).filter_by(id = id).delete()
        db_session.flush()
        db_session.commit()
        return {"status": 200, "message": ''}
    except Exception as e:
        log.error("Error in controllers `ServicesController` function  `del_service`. Details - {0}".format(str(e)))
        return {"status": 500, "message": str(e)}


#Удаление сервисов(services). Входные данные - host_id 
def del_Service_by_HostID(host_id: int):
    res = False
    try:
        session = create_session()
        session.query(Services).filter_by(id = host_id).delete()
        session.commit()
        session.close()
        res = True
    except Exception as e:
         log.error("Error function del_Service_by_HostID-Services (host_id - {0}).".format(str(host_id)))
    return res


#Получить уникальные имена сервисов
def getUnicNameService(db_session: Session) -> dict:
    try:
        select_statement = "SELECT distinct name FROM services WHERE name != '' OR name != NULL ORDER BY name ASC"
        result_set = db_session.execute(select_statement)
        return jsonify([dict(r) for r in result_set]), 200 
    except Exception as e:
        log.error("Error in controllers `ServicesController` function  `getDataServices`. Details - {0}".format(str(e)))
        return {"status": 500, "message": str(e) }



#Количество services
def get_count(db_session: Session, workspace_id: int, arg) -> int:
    try:
        q = (
                db_session.query(
                func.count(distinct(Services.id)).label('services')
            )
            .select_from(Services)
            .outerjoin(Hosts, Hosts.id == Services.host_id)
            .outerjoin(HostsTags, HostsTags.host_id == Hosts.id)
            .outerjoin(Tags, Tags.id == HostsTags.tag_id)
            .outerjoin(Notes, Notes.host_id == Hosts.id)
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
            .outerjoin(Vulns, Vulns.service_id == Services.id)
            .outerjoin(VulnDetails, VulnDetails.vuln_id == Vulns.id)
            .outerjoin(VulnAttempts, VulnAttempts.vuln_id == Vulns.id)
            .outerjoin(VulnsRefs, VulnsRefs.vuln_id == Vulns.id)
            .outerjoin(Refs, Refs.id == VulnsRefs.ref_id)
            .filter(Hosts.workspace_id == workspace_id)
            .group_by(Services.id)
            .order_by(Hosts.address)
        )

        q = apply_dynamic_filters(q, arg)
        return len([dict(r) for r in q.all()]) 
    except Exception as e:
        log.error("Error in controllers `ServicesController` function  `get_count`. Details - {0}".format(str(e)))
        return None