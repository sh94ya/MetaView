import ipaddress
from sqlalchemy.orm import Session
from datetime import datetime
from workspace.controllers import HostsController, ServicesController
from workspace.models.migration import (
    Hosts, Events, Tags, HostsTags, Services, Notes, Loots, 
    MetasploitCredentialCores, MetasploitCredentialLogins, MetasploitCredentialRealms, MetasploitCredentialPublics, MetasploitCredentialPrivates,
    MetasploitCredentialOriginCrackedPasswords, MetasploitCredentialOriginSessions, MetasploitCredentialOriginServices,
    MetasploitCredentialOriginImports, MetasploitCredentialOriginManuals,
    Sessions as MetasploitSessions, Vulns, VulnDetails, VulnAttempts, VulnsRefs, Refs, Users,
    MetasploitCredentialCoreComments, MetasploitCredentialLoginComments, Comments as MetasploitComments)
import workspace.logger as logging
from flask import jsonify

from sqlalchemy import and_, or_, func, distinct, union_all, select
from sqlalchemy.orm import aliased
from sqlalchemy.dialects import postgresql
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.sql import label

from workspace.controllers.Parsers import apply_dynamic_filters

log = logging.getLogger()


def getData (db_session: Session, workspace_id: int, arg) -> dict:
    try:
        # SELECT: origin_type = 'Metasploit::Credential::Origin::Service'
        origin_service_json = (
            func.jsonb_build_object(
                'id', Hosts.id,
                'address', Hosts.address,
                'purpose', Hosts.purpose,
                'os_family', Hosts.os_family,
                'origin_type', MetasploitCredentialCores.origin_type
            )
        ).label('origin')
        s1 = (
            select(
                origin_service_json,
                MetasploitCredentialCores.origin_id.label("origin_id"),
                MetasploitCredentialCores.origin_type.label("origin_type")
            )
            .select_from(MetasploitCredentialCores)
            .join(MetasploitCredentialOriginServices, MetasploitCredentialOriginServices.id == MetasploitCredentialCores.origin_id)
            .join(Services, Services.id == MetasploitCredentialOriginServices.service_id)
            .join(Hosts, Hosts.id == Services.host_id)
            .where(
                MetasploitCredentialCores.origin_type == "Metasploit::Credential::Origin::Service",
                MetasploitCredentialCores.workspace_id == workspace_id
            )
        )

        # SELECT: origin_type = 'Metasploit::Credential::Origin::Session'
        origin_session_json = (
            func.jsonb_build_object(
                'id', Hosts.id,
                'address', Hosts.address,
                'purpose', Hosts.purpose,
                'os_family', Hosts.os_family,
                'origin_type', MetasploitCredentialCores.origin_type,
                'session_id', MetasploitSessions.id,
                'post_reference_name', MetasploitCredentialOriginSessions.post_reference_name
            )
        ).label('origin')
        s2 = (
            select(
                origin_session_json,
                MetasploitCredentialCores.origin_id.label("origin_id"),
                MetasploitCredentialCores.origin_type.label("origin_type")
            )
            .select_from(MetasploitCredentialCores)
            .join(MetasploitCredentialOriginSessions, MetasploitCredentialOriginSessions.id == MetasploitCredentialCores.origin_id)
            .join(MetasploitSessions, MetasploitSessions.id == MetasploitCredentialOriginSessions.session_id)
            .join(Hosts, Hosts.id == MetasploitSessions.host_id)
            .where(
                MetasploitCredentialCores.origin_type == "Metasploit::Credential::Origin::Session",
                MetasploitCredentialCores.workspace_id == workspace_id
            )
        )

        # SELECT: origin_type = 'Metasploit::Credential::Origin::Import'
        origin_import_json = (
            func.jsonb_build_object(
                'id', MetasploitCredentialOriginImports.id,
                'filename', MetasploitCredentialOriginImports.filename,
                'origin_type', MetasploitCredentialCores.origin_type
            )
        ).label('origin')
        s3 = (
            select(
                origin_import_json,
                MetasploitCredentialCores.origin_id.label("origin_id"),
                MetasploitCredentialCores.origin_type.label("origin_type")
            )
            .select_from(MetasploitCredentialCores)
            .join(MetasploitCredentialOriginImports, MetasploitCredentialOriginImports.id == MetasploitCredentialCores.origin_id)
            .where(
                MetasploitCredentialCores.origin_type == "Metasploit::Credential::Origin::Import",
                MetasploitCredentialCores.workspace_id == workspace_id
            )
        )

        # SELECT: origin_type = 'Metasploit::Credential::Origin::Manual'
        origin_manual_json = (
            func.jsonb_build_object(
                'id', MetasploitCredentialOriginManuals.id,
                'username', Users.username,
                'origin_type', MetasploitCredentialCores.origin_type
            )
        ).label('origin')
        s4 = (
            select(
                origin_manual_json,
                MetasploitCredentialCores.origin_id.label("origin_id"),
                MetasploitCredentialCores.origin_type.label("origin_type")
            )
            .select_from(MetasploitCredentialCores)
            .join(MetasploitCredentialOriginManuals, MetasploitCredentialOriginManuals.id == MetasploitCredentialCores.origin_id)
            .join(Users, Users.id == MetasploitCredentialOriginManuals.user_id)
            .where(
                MetasploitCredentialCores.origin_type == "Metasploit::Credential::Origin::Manual",
                MetasploitCredentialCores.workspace_id == workspace_id
            )
        )

        # SELECT: origin_type = 'Metasploit::Credential::Origin::CrackedPassword'
        origin_crackedpassword_json = (
            func.jsonb_build_object(
                'core_id', MetasploitCredentialOriginCrackedPasswords.metasploit_credential_core_id,
                'origin_type', MetasploitCredentialCores.origin_type
            )
        ).label('origin')
        s5 = (
            select(
                origin_crackedpassword_json,
                MetasploitCredentialCores.origin_id.label("origin_id"),
                MetasploitCredentialCores.origin_type.label("origin_type")
            )
            .select_from(MetasploitCredentialCores)
            .join(MetasploitCredentialOriginCrackedPasswords, MetasploitCredentialOriginCrackedPasswords.id == MetasploitCredentialCores.origin_id)
            .where(
                MetasploitCredentialCores.origin_type == "Metasploit::Credential::Origin::CrackedPassword",
                MetasploitCredentialCores.workspace_id == workspace_id
            )
        )

        # Subquery (UNION) Origin::Service, Origin::Session, Origin::Import, Origin::Manual, Origin::CrackedPassword
        subquery = union_all(s1, s2, s3, s4, s5).subquery()

        # MAIN Query
        host_json = (
            func.jsonb_build_object('id', Hosts.id, 'address', Hosts.address, 'purpose', Hosts.purpose, 'os_family', Hosts.os_family)
        ).label('host')
        service_json = (
            func.jsonb_build_object('id', Services.id, 'port', Services.port, 'proto', Services.proto, 'name', Services.name)
        ).label('service')

        q = (
            db_session.query(
                MetasploitCredentialCores.id,
                MetasploitCredentialLogins.id.label('logins_id'),
                host_json,
                service_json,
                subquery.c.origin,
                MetasploitCredentialPublics.username,
                MetasploitCredentialPrivates.data.label('password'),
                MetasploitCredentialPrivates.type.label('type'),
                MetasploitCredentialPrivates.jtr_format.label('jtr_format'),
                MetasploitCredentialRealms.value.label('realm'),
                MetasploitCredentialRealms.key.label('realm_type'),
                MetasploitCredentialLogins.access_level,
                MetasploitComments.comment
            )
            .select_from(MetasploitCredentialCores)
            .outerjoin(subquery, subquery.c.origin_id == MetasploitCredentialCores.origin_id)
            .outerjoin(MetasploitCredentialPublics, MetasploitCredentialPublics.id == MetasploitCredentialCores.public_id)
            .outerjoin(MetasploitCredentialPrivates, MetasploitCredentialPrivates.id == MetasploitCredentialCores.private_id)
            .outerjoin(MetasploitCredentialRealms, MetasploitCredentialRealms.id == MetasploitCredentialCores.realm_id)
            .outerjoin(MetasploitCredentialOriginCrackedPasswords, and_(MetasploitCredentialOriginCrackedPasswords.metasploit_credential_core_id == MetasploitCredentialCores.id, MetasploitCredentialCores.origin_type == 'Metasploit::Credential::Origin::CrackedPassword'))
            .outerjoin(MetasploitCredentialLogins, MetasploitCredentialLogins.core_id == MetasploitCredentialCores.id)
            .outerjoin(MetasploitCredentialOriginImports, and_(MetasploitCredentialOriginImports.id == MetasploitCredentialCores.origin_id, MetasploitCredentialCores.origin_type == 'Metasploit::Credential::Origin::Import'))
            .outerjoin(Services, Services.id == MetasploitCredentialLogins.service_id)
            .outerjoin(MetasploitCredentialOriginServices, and_(MetasploitCredentialOriginServices.service_id == Services.id, MetasploitCredentialCores.origin_type == 'Metasploit::Credential::Origin::Service'))
            .outerjoin(Hosts, Hosts.id == Services.host_id)
            .outerjoin(HostsTags, HostsTags.host_id == Hosts.id)
            .outerjoin(Tags, Tags.id == HostsTags.tag_id)
            .outerjoin(Notes, Notes.host_id == Hosts.id)
            .outerjoin(MetasploitSessions, MetasploitSessions.host_id == Hosts.id)
            .outerjoin(MetasploitCredentialOriginSessions, and_(MetasploitCredentialOriginSessions.session_id == MetasploitSessions.id, MetasploitCredentialCores.origin_type == 'Metasploit::Credential::Origin::Session'))
            .outerjoin(Vulns, Vulns.host_id == Hosts.id)
            .outerjoin(VulnDetails, VulnDetails.vuln_id == Vulns.id)
            .outerjoin(VulnAttempts, VulnAttempts.vuln_id == Vulns.id)
            .outerjoin(VulnsRefs, VulnsRefs.vuln_id == Vulns.id)
            .outerjoin(Refs, Refs.id == VulnsRefs.ref_id)
            .outerjoin(MetasploitCredentialCoreComments, MetasploitCredentialCoreComments.core_id == MetasploitCredentialCores.id)
            .outerjoin(MetasploitCredentialLoginComments, MetasploitCredentialLoginComments.login_id == MetasploitCredentialLogins.id)
            .outerjoin(MetasploitComments, or_(MetasploitComments.id == MetasploitCredentialCoreComments.comment_id, MetasploitComments.id == MetasploitCredentialLoginComments.comment_id))
            .filter(MetasploitCredentialCores.workspace_id == workspace_id)
            .group_by(MetasploitCredentialCores.id)
            .group_by(subquery.c.origin)
            .group_by(MetasploitCredentialPublics.username)
            .group_by(MetasploitCredentialOriginCrackedPasswords.id)
            .group_by(MetasploitCredentialOriginImports.id)
            .group_by(MetasploitCredentialOriginServices.id)
            .group_by(MetasploitCredentialOriginSessions.id)
            .group_by(MetasploitCredentialLogins.id)
            .group_by(MetasploitCredentialPrivates.data)
            .group_by(MetasploitCredentialPrivates.type)
            .group_by(MetasploitCredentialPrivates.jtr_format)
            .group_by(MetasploitCredentialRealms.value)
            .group_by(MetasploitCredentialRealms.key)
            .group_by(MetasploitCredentialLogins.access_level)
            .group_by(Hosts.id)
            .group_by(Services.id)
            .group_by(Vulns.id)
            .group_by(MetasploitComments.id)
            .group_by(MetasploitCredentialCoreComments.id)
            .group_by(MetasploitCredentialLoginComments.id)
            .order_by(Hosts.address)
        )

        q = apply_dynamic_filters(q, arg)
        # return [dict(r) for r in db_session.execute(q.statement.compile().string)]
        return jsonify([dict(r) for r in q.all()]), 200  
    except Exception as e:
        log.error("Error in controllers `CredsController` function  `getData`. Details - {0}".format(str(e)))
        return {"status": 500, "message": str(e) }
    

# Возвращает топ 5 password
def get_top_creds(db_session: Session, workspace_id : int) -> dict:
    try:
        select_statement = '''SELECT  metasploit_credential_privates.data AS passwords, COUNT(metasploit_credential_privates.data) FROM metasploit_credential_cores 
                                    LEFT OUTER JOIN metasploit_credential_publics ON  metasploit_credential_publics.id = metasploit_credential_cores.public_id 
                                    LEFT OUTER JOIN metasploit_credential_privates ON metasploit_credential_privates.id = metasploit_credential_cores.private_id
                                    LEFT OUTER JOIN metasploit_credential_realms  ON metasploit_credential_realms.id  = metasploit_credential_cores.realm_id 
                                    LEFT OUTER JOIN metasploit_credential_logins  ON metasploit_credential_logins.core_id  = metasploit_credential_cores.id 
                                    LEFT OUTER JOIN services ON services.id  = metasploit_credential_logins.service_id
                                    LEFT OUTER JOIN hosts  ON hosts.id  = services.host_id  
                                    WHERE metasploit_credential_cores.workspace_id  = {0} 
                                    GROUP by  metasploit_credential_privates.data
                                    ORDER BY COUNT(metasploit_credential_privates.data) DESC LIMIT 5'''.format(str(int(workspace_id)))
        
        result_set = db_session.execute(select_statement)
        return [dict(r) for r in result_set]
    except Exception as e:
        log.error("Error in controllers `CredsController` function  `get_top_creds`. Details - {0}".format(str(e)))
        return {"status": 500, "message": str(e) }


# Учетные записи с различными правами
def get_distinct_creds_type(db_session: Session, workspace_id : int) -> dict:
    try:
        select_statement = '''SELECT  metasploit_credential_logins.access_level AS value, COUNT(metasploit_credential_privates.data) FROM metasploit_credential_cores 
                                    LEFT OUTER JOIN metasploit_credential_publics ON  metasploit_credential_publics.id = metasploit_credential_cores.public_id 
                                    LEFT OUTER JOIN metasploit_credential_privates ON metasploit_credential_privates.id = metasploit_credential_cores.private_id
                                    LEFT OUTER JOIN metasploit_credential_realms  ON metasploit_credential_realms.id  = metasploit_credential_cores.realm_id 
                                    LEFT OUTER JOIN metasploit_credential_logins  ON metasploit_credential_logins.core_id  = metasploit_credential_cores.id 
                                    LEFT OUTER JOIN services ON services.id  = metasploit_credential_logins.service_id
                                    LEFT OUTER JOIN hosts  ON hosts.id  = services.host_id  
                                    WHERE metasploit_credential_logins.access_level IS NOT NULL AND metasploit_credential_cores.workspace_id  = {0}
                                    GROUP by  metasploit_credential_logins.access_level
                                    ORDER BY COUNT(metasploit_credential_logins.access_level)'''.format(str(int(workspace_id)))
        result_set = db_session.execute(select_statement)
        return [dict(r) for r in result_set]
    except Exception as e:
        log.error("Error in controllers `CredsController` function  `get_distinct_creds_type`. Details - {0}".format(str(e)))
        return {"status": 500, "message": str(e) }


#Редактирование учетных записей
def edit_creds(db_session: Session, workspace_id: int, data: dict, user_id: int, type_cred="::Service"):
    try:
        result_delete = del_creds(db_session, workspace_id, data)
        if(result_delete["status"] == 200):
            result_add = add_creds(db_session, workspace_id, data, user_id, type_cred)
            if(result_add["status"] != 200):
                db_session.rollback()
                return {'status': 500, 'message':'Ошибка при редактировании'}  
            else:
                result_add["message"] = "Запись отредактирована!"
                return result_add
        else:
            db_session.rollback()
            return {'status': 500, 'message':'Ошибка при редактировании'} 
    except Exception as e:
        log.error("Error in controllers `CredsController` function  `edit_creds`. Details - {0}".format(str(e)))
        db_session.rollback()
        return {"status": 500, "message": str(e) }


#Удаление учетных записей
def del_creds(db_session: Session, workspace_id: int, data: dict):
    try:
        #Get _core row
        core = db_session.query(MetasploitCredentialCores).filter(MetasploitCredentialCores.id == data["id"]).first()
        
        #Delete logins row
        if ("logins_id" in data and data['logins_id'] != None):
            #Check that logins_id belong core's workspace_id
            if(db_session.query(MetasploitCredentialCores).join(MetasploitCredentialLogins, MetasploitCredentialLogins.core_id == MetasploitCredentialCores.id).filter(MetasploitCredentialCores.id == data["id"], MetasploitCredentialCores.workspace_id == workspace_id)):
                #Delete metasploit_credenial_logins rows
                db_session.query(MetasploitCredentialLogins).filter_by(id = data["logins_id"]).delete()
                db_session.flush()
                count_logins_IN_core(db_session, 'decrease', data['id'])
                db_session.query(MetasploitCredentialLoginComments).filter_by(login_id = data['logins_id']).delete()
                data['logins_id'] = None
                db_session.flush()
                # del_creds(db_session, workspace_id, data)
        else:
            count_other_row_with_origin_id= [dict(r) for r in db_session.query(func.count(MetasploitCredentialCores.id).label('count')).filter_by(origin_id = core.origin_id, origin_type = core.origin_type, workspace_id = workspace_id).all()][0]['count']
            if(core.logins_count <= 0):
                db_session.query(MetasploitCredentialCoreComments).filter_by(core_id = core.id).delete()
                if(core.origin_type == 'Metasploit::Credential::Origin::Manual'):
                    db_session.query(MetasploitCredentialCores).filter_by(id = data['id'], workspace_id = workspace_id).delete()
                    if(count_other_row_with_origin_id == 1):
                        db_session.query(MetasploitCredentialOriginManuals).filter_by(id = core.origin_id).delete()
                if(core.origin_type == 'Metasploit::Credential::Origin::Import'):
                    db_session.query(MetasploitCredentialCores).filter_by(id = data['id'], workspace_id = workspace_id).delete()
                    if(count_other_row_with_origin_id == 1):
                        db_session.query(MetasploitCredentialOriginImports).filter_by(id = core.origin_id).delete()
                if(core.origin_type == 'Metasploit::Credential::Origin::CrackedPassword'):   
                    db_session.query(MetasploitCredentialCores).filter_by(id = data['id'], workspace_id = workspace_id).delete()
                    if(count_other_row_with_origin_id == 1):
                        db_session.query(MetasploitCredentialOriginCrackedPasswords).filter_by(id = core.origin_id).delete()
                if(core.origin_type == 'Metasploit::Credential::Origin::Session'):    
                    db_session.query(MetasploitCredentialCores).filter_by(id = data['id'], workspace_id = workspace_id).delete()
                    if(count_other_row_with_origin_id == 1):
                        db_session.query(MetasploitCredentialOriginSessions).filter_by(id = core.origin_id).delete()
                if(core.origin_type == 'Metasploit::Credential::Origin::Service'):    
                    db_session.query(MetasploitCredentialCores).filter_by(id = data['id'], workspace_id = workspace_id).delete()
                    if(count_other_row_with_origin_id == 1):
                        db_session.query(MetasploitCredentialOriginServices).filter_by(id = core.origin_id).delete()
            else:
                return {'status': 503, 'message':'С этой записью связаны другие записи в таблице _logins. Сначала удалите их!'}  
                
        db_session.commit()
        return {'status': 200, 'message':'Запись удалена!'}      
    except Exception as e:
        log.error("Error in controllers `CredsController` function  `del_creds`. Details - {0}".format(str(e)))
        db_session.rollback()
        return {"status": 500, "message": str(e) }


#Удаление учетных записей. Входные данные - host_id
def del_creds_by_HostID(db_session: Session, workspace_id: int, host_id: int):
    try:
        creds_host = getData(db_session, workspace_id, 'hosts.id == {0}'.format(str(int(host_id))))
        for item in creds_host:
            del_creds(db_session, workspace_id, item)
        return {'status': 200,'message': 'Записи удалены!'}     
    except Exception as e:
        log.error("Error in controllers `CredsController` function  `del_creds_by_HostID`. Details - {0}".format(str(e)))
        db_session.rollback()
        return {"status": 500, "message": str(e) }


#Удаление учетных записей. Входные данные - service_id
def del_creds_by_ServiceID(db_session: Session, workspace_id: int, service_id: int):
    try:
        creds_host = getData(db_session, workspace_id, 'services.id == {0}'.format(str(int(service_id))))
        for item in creds_host:
            del_creds(db_session, workspace_id, item)
        return {'status': 200,'message': 'Записи удалены!'}     
    except Exception as e:
        log.error("Error in controllers `CredsController` function  `del_creds_by_ServiceID`. Details - {0}".format(str(e)))
        db_session.rollback()
        return {"status": 500, "message": str(e) }


# Function Add Creds in DB
def add_creds(db_session: Session, workspace_id: int, data: dict, user_id: int, type_cred="::Service"):
    origin_address = ""
    host_id = None
    host = None
    service_id = []
    try:
        #Get host_id
        if(str(type(data['host'])) == "<class 'dict'>"):
           host_id = data['host']['id']
        else:
            host_id = HostsController.get_host_id(db_session, workspace_id, data['host'])
        
        if(str(type(host_id)) == "<class 'int'>"):
            host = db_session.query(func.jsonb_build_object('id', Hosts.id, 'address', Hosts.address, 'purpose', Hosts.purpose, 'os_family', Hosts.os_family)).filter_by(workspace_id = int(workspace_id), id = host_id).first()
            host= dict(host[0])
        
        data['host_id'] = host_id

        #Get services_id
        if(str(type(data['service'])) == "<class 'list'>"):
            for service in data['service']:
               service_id.append(service['id']) 

        #Get private_id, public_id, realm_id
        private_public_realm_id = get_public_private_realm(db_session, data)
        cred_core = db_session.query(MetasploitCredentialCores).filter_by(private_id = private_public_realm_id['private_id'], public_id = private_public_realm_id['public_id'], realm_id = private_public_realm_id['realm_id'], workspace_id = workspace_id).first()

        #1)::Import
        if(type_cred == "::Import"):
            if(cred_core == None):
                #Get Import information
                origin_import = db_session.query(MetasploitCredentialOriginImports).filter_by(filename = 'MetaView').first()
                #If row is not exist then add it
                if(origin_import == None):
                    origin_import = MetasploitCredentialOriginImports('MetaView')
                    db_session.add(origin_import)
                    db_session.flush()
                cred_core = add_IN_cores(db_session, workspace_id, type_cred, origin_import.id, private_public_realm_id)
                if(data['comment'] != None and data['comment'] != ''):
                    comment = db_session.query(MetasploitComments).filter_by(comment = data['comment']).first()
                    if(comment == None):
                        comment = add_IN_comments(db_session, data['comment'])
                        add_IN_core_comments(db_session, cred_core.id, comment.id)
            else:
                return {'status': 502, 'message':'Такая запись уже существует'}

        #2)::Manual
        if(type_cred == "::Manual"):
            if(cred_core == None):
                origin_manuals = MetasploitCredentialOriginManuals(user_id)
                db_session.add(origin_manuals)
                db_session.flush()
                cred_core = add_IN_cores(db_session, workspace_id, type_cred, origin_manuals.id, private_public_realm_id)
                if(data['comment'] != None and data['comment'] != ''):
                    comment = db_session.query(MetasploitComments).filter_by(comment = data['comment']).first()
                    if(comment == None):
                        comment = add_IN_comments(db_session, data['comment'])
                        add_IN_core_comments(db_session, cred_core.id, comment.id)
            else:
                return {'status': 502, 'message':'Такая запись уже существует'}

        #3)::Service
        metasploit_credentials_logins_id = []
        if(host_id != None and type_cred == "::Service"):
            #Если service не указан, то добавляем в таблицу services  службу system
            if(service_id == []):
                try:
                    #Check if 'system port' (0/tcp) already exist
                    sys_service = db_session.query(Services).filter(Services.host_id == host_id, Services.port == 0).first()
                    if(sys_service == None):
                        sys_service = ServicesController.add_services(db_session, workspace_id, {"host": data['host'],  "port": 0, "proto": "", "state": "", "name": "system", "info": ""})
                        if(sys_service["status"] == 200):
                            service_id.append(sys_service["id"])
                        else:
                            return sys_service
                    else:
                        service_id.append(sys_service.id)
                except Exception as e:
                    return {"status": 501, "message": str(e)}
                
            #Если такой записи в этой таблице нет, то добавляем её
            exist_logins_count = 0
            comment = db_session.query(MetasploitComments).filter_by(comment = data['comment']).first()
            for service in service_id:
                if(cred_core == None):
                    origin_service_id = check_IN_original_services(db_session, service)
                    if(origin_service_id == None):
                        origin_service_id = add_IN_origin_services(db_session, service)
                    cred_core = add_IN_cores(db_session, workspace_id, type_cred, origin_service_id, private_public_realm_id)
                    login_id = add_IN_logins(db_session, cred_core.id, service, data)
                    metasploit_credentials_logins_id.append(login_id)
                #Если такой записи нет, то увеличиваем счетчик logins на +1 и добавляем в logins
                else:
                    login_id = check_IN_credential_login(db_session, cred_core.id, service, data)
                    if(login_id == None):
                        login_id = add_IN_logins(db_session, cred_core.id, service, data)
                        metasploit_credentials_logins_id.append(login_id)
                    else:
                        metasploit_credentials_logins_id.append(None)
                
                if(data['comment'] != None and data['comment'] != ''):
                    if(comment == None):
                        comment = add_IN_comments(db_session, data['comment'])
                    login_comments = add_IN_login_comments(db_session, login_id, comment.id)

                

        origin = get_origin(db_session, cred_core.origin_id, type_cred) 
        db_session.commit()
        return {'status':200, 'id': cred_core.id, 'logins_id': metasploit_credentials_logins_id, 'service_id': service_id, 'host': host, 'origin': origin, 'origin_id': cred_core.origin_id, 'created_at': cred_core.created_at.strftime("%d.%m.%Y"), 'updated_at': cred_core.updated_at.strftime("%d.%m.%Y"),}
    except Exception as e:
        log.error("Error in controllers `CredsController` function  `add_creds`. Details - {0}".format(str(e)))
        db_session.rollback()
        return {"status": 501, "message": str(e)}


#Найти адрес Origin
def get_origin(db_session: Session, origin_id: int, type_cred: str):
    result = None
    try:
        # SELECT: origin_type = 'Metasploit::Credential::Origin::Service'
        if(type_cred == "::Service"):
            origin_service_json = (
                func.jsonb_build_object(
                    'id', Hosts.id,
                    'address', Hosts.address,
                    'purpose', Hosts.purpose,
                    'os_family', Hosts.os_family,
                    'origin_type', MetasploitCredentialCores.origin_type
                )
            ).label('origin')
            statement = (
                select(
                    origin_service_json,
                )
                .select_from(MetasploitCredentialCores)
                .join(MetasploitCredentialOriginServices, MetasploitCredentialOriginServices.id == MetasploitCredentialCores.origin_id)
                .join(Services, Services.id == MetasploitCredentialOriginServices.service_id)
                .join(Hosts, Hosts.id == Services.host_id)
                .where(
                    MetasploitCredentialCores.origin_type == "Metasploit::Credential::Origin::Service",
                    MetasploitCredentialCores.origin_id == origin_id
                )
            )

        # SELECT: origin_type = 'Metasploit::Credential::Origin::Session'
        if(type_cred == "::Session"):
            origin_session_json = (
                func.jsonb_build_object(
                    'id', Hosts.id,
                    'address', Hosts.address,
                    'purpose', Hosts.purpose,
                    'os_family', Hosts.os_family,
                    'origin_type', MetasploitCredentialCores.origin_type,
                    'session_id', MetasploitSessions.id,
                    'post_reference_name', MetasploitCredentialOriginSessions.post_reference_name
                )
            ).label('origin')
            statement = (
                select(
                    origin_session_json,
                )
                .select_from(MetasploitCredentialCores)
                .join(MetasploitCredentialOriginSessions, MetasploitCredentialOriginSessions.id == MetasploitCredentialCores.origin_id)
                .join(MetasploitSessions, MetasploitSessions.id == MetasploitCredentialOriginSessions.session_id)
                .join(Hosts, Hosts.id == MetasploitSessions.host_id)
                .where(
                    MetasploitCredentialCores.origin_type == "Metasploit::Credential::Origin::Session",
                    MetasploitCredentialCores.origin_id == origin_id
                )
            )

        # SELECT: origin_type = 'Metasploit::Credential::Origin::Import'
        if(type_cred == "::Import"):
            origin_import_json = (
                func.jsonb_build_object(
                    'id', MetasploitCredentialOriginImports.id,
                    'filename', MetasploitCredentialOriginImports.filename,
                    'origin_type', MetasploitCredentialCores.origin_type
                )
            ).label('origin')
            statement = (
                select(
                    origin_import_json,
                )
                .select_from(MetasploitCredentialCores)
                .join(MetasploitCredentialOriginImports, MetasploitCredentialOriginImports.id == MetasploitCredentialCores.origin_id)
                .where(
                    MetasploitCredentialCores.origin_type == "Metasploit::Credential::Origin::Import",
                    MetasploitCredentialCores.origin_id == origin_id
                )
            )

        # SELECT: origin_type = 'Metasploit::Credential::Origin::Manual'
        if(type_cred == "::Manual"):
            origin_manual_json = (
                func.jsonb_build_object(
                    'id', MetasploitCredentialOriginManuals.id,
                    'username', Users.username,
                    'origin_type', MetasploitCredentialCores.origin_type
                )
            ).label('origin')
            statement = (
                select(
                    origin_manual_json,
                )
                .select_from(MetasploitCredentialCores)
                .join(MetasploitCredentialOriginManuals, MetasploitCredentialOriginManuals.id == MetasploitCredentialCores.origin_id)
                .join(Users, Users.id == MetasploitCredentialOriginManuals.user_id)
                .where(
                    MetasploitCredentialCores.origin_type == "Metasploit::Credential::Origin::Manual",
                    MetasploitCredentialCores.origin_id == origin_id
                )
            )

        # SELECT: origin_type = 'Metasploit::Credential::Origin::CrackedPassword'
        if(type_cred == "::CrackedPassword"):
            origin_crackedpassword_json = (
                func.jsonb_build_object(
                    'core_id', MetasploitCredentialOriginCrackedPasswords.metasploit_credential_core_id,
                    'origin_type', MetasploitCredentialCores.origin_type
                )
            ).label('origin')
            statement = (
                select(
                    origin_crackedpassword_json,
                )
                .select_from(MetasploitCredentialCores)
                .join(MetasploitCredentialOriginCrackedPasswords, MetasploitCredentialOriginCrackedPasswords.id == MetasploitCredentialCores.origin_id)
                .where(
                    MetasploitCredentialCores.origin_type == "Metasploit::Credential::Origin::CrackedPassword",
                    MetasploitCredentialCores.origin_id == origin_id
                )
            )
        
        origin = db_session.query(statement.subquery()).first()
        if(origin != None):
            origin = [dict(r) for r in origin][0]
        
        return origin
        # param = "jsonb_build_object('id', hosts.id, 'address', hosts.address, 'os_family', hosts.os_family, 'purpose', hosts.purpose) AS origin_host"
        # if(type_cred == "::Service"):
        #     select_statement = '''SELECT {0} FROM metasploit_credential_origin_services 
        #     INNER JOIN services ON metasploit_credential_origin_services.service_id = services.id 
        #     INNER JOIN hosts ON services.host_id = hosts.id WHERE metasploit_credential_origin_services.id = {1}'''.format(param, str(int(origin_id))) 
        # if(type_cred == "::Session"):
        #     select_statement = '''SELECT {0} FROM metasploit_credential_origin_sessions
        #     INNER JOIN sessions ON metasploit_credential_origin_sessions.session_id = sessions.id 
        #     INNER JOIN hosts ON sessions.host_id = hosts.id WHERE metasploit_credential_origin_sessions.id = {1}'''.format(param, str(int(origin_id))) 
        # result = [dict(r) for r in db_session.execute(select_statement)]
        # if(len(result) > 0):
        #     result = result[0]['origin_host']
    except Exception as e:
        log.error("Error in controllers `CredsController` function  `get_origin`. Details - {0}".format(str(e)))
    return result


#Проверка на пустой пароль
def get_IDBlankPassword(db_session: Session):
    type_password = "Metasploit::Credential::BlankPassword"
    blank_password = None
    #Если пароль пустой, то ищем в private запись Metasploit::Credential::BlankPassword
    blank_password = db_session.query(MetasploitCredentialPrivates).filter(MetasploitCredentialPrivates.type == type_password).first()
    #Если в таблице нет записи Metasploit::Credential::BlankPassword, то добавляем её
    if(blank_password == None):
        blank_password = add_IN_privates(db_session, {"type": type_password, "password":"", "jtr_format": None})
    else:
        blank_password = blank_password.id
    return blank_password


#Проверка записи в таблице metasploit_credential_cores
def check_IN_credential_cores(db_session: Session, workspace_id: int, private_public_realm_id: dict, ):
    return db_session.query(MetasploitCredentialCores).filter_by(private_id = private_public_realm_id['private_id'], public_id = private_public_realm_id['public_id'], realm_id = private_public_realm_id['realm_id'], workspace_id = workspace_id).first()


#Получить private_id и public_id и realm_id
def get_public_private_realm(db_session: Session, data: dict) -> dict:
    password_id = None
    username_id = None
    realm_id = None
    #1) Если пароль пустой
    if(data['password'] == None or data['password'] == ''):
        password_id = get_IDBlankPassword(db_session)
        private = db_session.query(MetasploitCredentialPrivates).filter_by(id = password_id).first()
    else:
        #Находим id в таблице metasploit_credential_privates
        jtr = None
        if(data['jtr_format'] != None and data['jtr_format'] != ''):
            jtr = (',').join(data['jtr_format'])
        private = db_session.query(MetasploitCredentialPrivates).filter_by(data = data['password'], type = data['type']).first()
    
    if(private == None):
        #Если такого пароля нет в таблице metasploit_credential_privates, то добавляем его
        password_id = add_IN_privates(db_session, data)
    else:
        password_id = private.id

    #2) Если логин пустой
    if(data['username'] == None or data['username'] == ''):
        username_id = None
    else:
        #Находим id в таблице metasploit_credential_publics
        username = db_session.query(MetasploitCredentialPublics).filter_by(username = data['username']).first()
        if(username == None):
            #Если такого username нет в таблице metasploit_credential_publics, то добавляем его
            username_id = add_IN_publics(db_session, data)
        else:
            username_id = username.id


    #3) Если домен пустой
    if(data['realm']  == None or data['realm']  == ''):
        realm_id = None
    else:
        #Находим id в таблице metasploit_credential_publics
        realm =  db_session.query(MetasploitCredentialRealms).filter_by(value = data['realm'] , key = data['realm_type']).first()
        if(realm == None):
            #Если такого realm нет в таблице metasploit_credential_realms, то добавляем его
            realm_id = add_IN_realms(db_session, data)
        else:
            realm_id = realm.id
    return {'private_id': password_id, 'public_id': username_id, 'realm_id': realm_id}


#Добавить пароль в таблицу metasploit_credential_privates
def add_IN_privates(db_session: Session, data: dict):
    jtr = None
    if(data['jtr_format'] != None):
        jtr = ','.join(data['jtr_format'])
        credential_private = MetasploitCredentialPrivates(type = data['type'], data = data['password'], jtr_format = jtr)
    else:
        credential_private = MetasploitCredentialPrivates(type = data['type'], data = data['password'], jtr_format = data['jtr_format'])
    db_session.add(credential_private)
    db_session.flush()
    return credential_private.id


#Добавить пароль в таблицу metasploit_credential_publics
def add_IN_publics(db_session: Session, data: dict):
    credential_public = MetasploitCredentialPublics(data['username'])
    db_session.add(credential_public)
    db_session.flush()
    return credential_public.id


#Добавить realm в таблицу metasploit_credential_realms
def add_IN_realms(db_session: Session, data: dict):
    credential_realm = MetasploitCredentialRealms(data['realm_type'], data['realm'])
    db_session.add(credential_realm)
    db_session.flush()
    return credential_realm.id


#Добавить запись в таблицу metasploit_credential_cores
def add_IN_cores(db_session: Session, workspace_id: int, origin_type: str, origin_id: int, private_public_realm: dict):
    otype = "Metasploit::Credential::Origin{0}".format(str(origin_type))
    core = MetasploitCredentialCores(otype,
                                    origin_id,
                                    private_public_realm["public_id"],
                                    private_public_realm["private_id"],
                                    private_public_realm["realm_id"],
                                    workspace_id
    )
    db_session.add(core)
    db_session.flush()
    return core


#Добавить запись в таблицу metasploit_credential_logins
def add_IN_logins(db_session: Session, core_id: int, service_id: int, data: dict) -> int:
    login = MetasploitCredentialLogins(core_id, service_id, data["access_level"], "Successful")
    db_session.add(login)
    db_session.flush()
    count_logins_IN_core(db_session, 'increase', core_id)
    return login.id


#Добавить запись в таблицу metasploit_credential_core_comments
def add_IN_core_comments(db_session: Session, core_id: int, comment_id: int) -> int:
    core_comment = MetasploitCredentialCoreComments(core_id, comment_id)
    db_session.add(core_comment)
    db_session.flush()
    return core_comment


#Добавить запись в таблицу metasploit_credential_login_comments
def add_IN_login_comments(db_session: Session, login_id: int, comment_id: int) -> int:
    login_comment = MetasploitCredentialLoginComments(login_id, comment_id)
    db_session.add(login_comment)
    db_session.flush()
    return login_comment


#Добавить запись в таблицу comments
def add_IN_comments(db_session: Session,  comment: str) -> int:
    comm = MetasploitComments(comment)
    db_session.add(comm)
    db_session.flush()
    return comm


#Добавить или убавить logins_count в metasploit_credential_cores.
def count_logins_IN_core(db_session: Session, action: str, core_id: int):
    core = db_session.query(MetasploitCredentialCores).filter(MetasploitCredentialCores.id == core_id)
    if(action == 'increase'):
        core = core.first()
        if core:
            core.logins_count +=1

    if(action == 'decrease'):
        core = core.filter(MetasploitCredentialCores.logins_count > 0).first()
        if core:
            core.logins_count -=1
    db_session.flush()


#Добавить в metasploit_credential_origin_services.
def add_IN_origin_services(db_session: Session, service_id: int):
    origin_services = MetasploitCredentialOriginServices(service_id,
                                                        'auxiliary/scanner/login',
                                                        datetime.now(),
                                                        datetime.now())
    db_session.add(origin_services)
    db_session.flush()
    return origin_services.id


#Добавить в sessions.
def add_IN_session(db_session: Session, host_id: int) -> int:
    session = MetasploitSessions(host_id,
                               'shell',
                               'Creds_session',
                               None,
                               None,
                               datetime.now())
    db_session.add(session)
    db_session.flush()
    return session.id


#Добавить  в metasploit_credential_origin_sessions.
def add_IN_origin_sessions(db_session: Session, session_id: int) -> int:
    origin_session = MetasploitCredentialOriginSessions(session_id,
                                                        'Custom',
                                                        datetime.now(),
                                                        datetime.now())
    db_session.add(origin_session)
    db_session.flush()
    return origin_session.id


#Проверить на повторяющуюся запись в metasploit_credential_logins.
def check_IN_credential_login(db_session: Session, core_id: int, service_id: int, data: dict):
    result = db_session.query(MetasploitCredentialLogins).filter_by(service_id = service_id, core_id = core_id, access_level = data["access_level"]).first()
    return result


#Проверить на повторяющуюся запись в metasploit_credential_original_services.
def check_IN_original_services(db_session: Session, service_id: int):
    result = None
    for metasploit_credential_origin_services in db_session.query(MetasploitCredentialOriginServices).filter_by(service_id = service_id).limit(1):
        result = metasploit_credential_origin_services.id
    return result


#Количество creds
def get_count(db_session: Session, workspace_id: int, arg) -> int:
    try:
        q = (
            db_session.query(
                func.count(distinct(Services.id)).label('creds')
            )
            .select_from(MetasploitCredentialCores)
            .outerjoin(MetasploitCredentialPublics, MetasploitCredentialPublics.id == MetasploitCredentialCores.public_id)
            .outerjoin(MetasploitCredentialPrivates, MetasploitCredentialPrivates.id == MetasploitCredentialCores.private_id)
            .outerjoin(MetasploitCredentialRealms, MetasploitCredentialRealms.id == MetasploitCredentialCores.realm_id)
            .outerjoin(MetasploitCredentialOriginCrackedPasswords, and_(MetasploitCredentialOriginCrackedPasswords.metasploit_credential_core_id == MetasploitCredentialCores.id, MetasploitCredentialCores.origin_type == 'Metasploit::Credential::Origin::CrackedPassword'))
            .outerjoin(MetasploitCredentialLogins, MetasploitCredentialLogins.core_id == MetasploitCredentialCores.id)
            .outerjoin(MetasploitCredentialOriginImports, and_(MetasploitCredentialOriginImports.id == MetasploitCredentialCores.origin_id, MetasploitCredentialCores.origin_type == 'Metasploit::Credential::Origin::Import'))
            .outerjoin(Services, Services.id == MetasploitCredentialLogins.service_id)
            .outerjoin(MetasploitCredentialOriginServices, and_(MetasploitCredentialOriginServices.service_id == Services.id, MetasploitCredentialCores.origin_type == 'Metasploit::Credential::Origin::Service'))
            .outerjoin(Hosts, Hosts.id == Services.host_id)
            .outerjoin(HostsTags, HostsTags.host_id == Hosts.id)
            .outerjoin(Tags, Tags.id == HostsTags.tag_id)
            .outerjoin(Notes, Notes.host_id == Hosts.id)
            .outerjoin(MetasploitSessions, MetasploitSessions.host_id == Hosts.id)
            .outerjoin(MetasploitCredentialOriginSessions, and_(MetasploitCredentialOriginSessions.session_id == MetasploitSessions.id, MetasploitCredentialCores.origin_type == 'Metasploit::Credential::Origin::Session'))
            .outerjoin(Vulns, Vulns.host_id == Hosts.id)
            .outerjoin(VulnDetails, VulnDetails.vuln_id == Vulns.id)
            .outerjoin(VulnAttempts, VulnAttempts.vuln_id == Vulns.id)
            .outerjoin(VulnsRefs, VulnsRefs.vuln_id == Vulns.id)
            .outerjoin(Refs, Refs.id == VulnsRefs.ref_id)
            .filter(MetasploitCredentialCores.workspace_id == workspace_id)
            .group_by(MetasploitCredentialCores.id)
            .group_by(MetasploitCredentialPublics.username)
            .group_by(MetasploitCredentialOriginCrackedPasswords.id)
            .group_by(MetasploitCredentialOriginImports.id)
            .group_by(MetasploitCredentialOriginServices.id)
            .group_by(MetasploitCredentialOriginSessions.id)
            .group_by(MetasploitCredentialLogins.id)
            .group_by(MetasploitCredentialPrivates.data)
            .group_by(MetasploitCredentialPrivates.type)
            .group_by(MetasploitCredentialPrivates.jtr_format)
            .group_by(MetasploitCredentialRealms.value)
            .group_by(MetasploitCredentialRealms.key)
            .group_by(MetasploitCredentialLogins.access_level)
            .group_by(Hosts.id)
            .group_by(Services.id)
            .group_by(Vulns.id)
            .order_by(Hosts.address)
        )

        q = apply_dynamic_filters(q, arg)
        return len([dict(r) for r in q.all()])   
    except Exception as e:
        log.error("Error in controllers `CredsController` function  `get_count`. Details - {0}".format(str(e)))
        return None