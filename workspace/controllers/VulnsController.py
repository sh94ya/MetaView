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
        details_arr = func.array_agg(
            distinct(func.jsonb_build_object('id', VulnDetails.id, 'cvss_score', VulnDetails.cvss_score, 'title', VulnDetails.title , 'description', VulnDetails.description, 'solution', VulnDetails.solution)
            )
        ).label('details')
        attempts_arr = func.array_agg(
            distinct(func.jsonb_build_object('id', VulnAttempts.id, 'exploited', VulnAttempts.exploited, 'module', VulnAttempts.module, 'fail_reason', VulnAttempts.fail_reason, 'fail_detail', VulnAttempts.fail_detail, 'session_id', VulnAttempts.session_id)
            )
        ).label('attempts')
        refs_arr = func.array_agg(
            distinct(func.jsonb_build_object('id', Refs.id, 'name', Refs.name)
            )
        ).label('refs')
        q = (
                db_session.query(
                Vulns.id,
                host_json,
                service_json,
                Vulns.name,
                Vulns.info,
                Vulns.name,
                Vulns.info,
                func.max(VulnDetails.cvss_score).label('cvss'),
                details_arr,
                attempts_arr,
                refs_arr
            )
            .outerjoin(Hosts, Vulns.host_id == Hosts.id)
            .outerjoin(HostsTags, HostsTags.host_id == Hosts.id)
            .outerjoin(Tags, Tags.id == HostsTags.tag_id)
            .outerjoin(Services, Services.id == Vulns.service_id)
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
            .outerjoin(VulnDetails, VulnDetails.vuln_id == Vulns.id)
            .outerjoin(VulnAttempts, VulnAttempts.vuln_id == Vulns.id)
            .outerjoin(VulnsRefs, VulnsRefs.vuln_id == Vulns.id)
            .outerjoin(Refs, Refs.id == VulnsRefs.ref_id)
            .filter(Hosts.workspace_id == workspace_id)
            .group_by(Hosts.id)
            .group_by(Services.id)
            .group_by(Vulns.id)
            .order_by(Hosts.address)
        )

        q = apply_dynamic_filters(q, arg)
        return jsonify([dict(r) for r in q.all()]), 200  
    except Exception as e:
        log.error("Error in controllers `VulnsController` function  `getData`. Details - {0}".format(str(e)))
        return {"status": 500, "message": str(e) }


# Возвращает топ 5 уязвимостей
def get_top_vuln(db_session: Session, workspace_id : int) -> dict:
    dd = []
    select_statement = ''
    try:
        select_statement = '''SELECT vulns.name AS value, COUNT(vulns.name) AS count FROM vulns 
        INNER JOIN hosts ON hosts.id = vulns.host_id
        WHERE hosts.workspace_id = {0}
        GROUP BY  vulns.name
        ORDER BY COUNT(*) DESC LIMIT 5'''.format(str(int(workspace_id)))
        result_set = db_session.execute(select_statement)
        dd = [dict(r) for r in result_set]
        return dd
    except Exception as e:
        log.error("Ошибка при обращении к таблице services, func get_top_service() (workspace_id - {0}).".format(workspace_id))


# Возвращает количество уязвимых/не уязвимых хостов
def get_vulns_hosts(db_session: Session, workspace_id : int) -> dict:
    dd = []
    select_statement = ''
    try:
        select_statement = '''SELECT 'Уязвимые хосты' AS value, count(distinct vulns.host_id) AS count  FROM vulns
        INNER JOIN hosts on vulns.host_id = hosts.id 
        WHERE hosts.workspace_id  = {0}
        UNION 
        SELECT 'Хосты без уязвимостей' as value, count (hosts.id) as count  from hosts
        WHERE hosts.id NOT IN (SELECT hosts.id FROM hosts INNER JOIN vulns ON vulns.host_id = hosts.id) AND hosts.workspace_id  = {0}'''.format(str(int(workspace_id)))
        result_set = db_session.execute(select_statement)
        dd = [dict(r) for r in result_set]
        return dd
    except Exception as e:
        log.error("Ошибка при обращении к таблице hosts, func get_vulns_hosts() (workspace_id - {0}).".format(workspace_id))


#Уникальные имена уязвимостей
def getUniName(db_session: Session) -> dict:
    try:
        select_statement = "SELECT DISTINCT name FROM vulns ORDER BY name"
        result_set = db_session.execute(select_statement)
        return jsonify([dict(r) for r in result_set]), 200 
    except Exception as e:
        log.error("Error in controllers `VulnsController` function  `getUniName`. Details - {0}".format(str(e)))
        return {"status": 500, "message": str(e) }


#Ссылки на уязвимости
def getUniRefs(db_session: Session) -> dict:
    try:
        select_statement = "SELECT DISTINCT refs.name, refs.id FROM refs ORDER BY refs.name"
        result_set = db_session.execute(select_statement)
        return jsonify([dict(r) for r in result_set]), 200 
    except Exception as e:
        log.error("Error in controllers `VulnsController` function  `getUniRefs`. Details - {0}".format(str(e)))
        return {"status": 500, "message": str(e) }


#Получить id ссылок для текущего элемента
def get_id_refs(vuln_id: int):
    session = create_session()
    select_statement = "SELECT vulns_refs.ref_id FROM vulns_refs WHERE vulns_refs.vuln_id = {0}".format(str(int(vuln_id)))
    result_set = session.execute(select_statement)
    dd = [dict(r) for r in result_set]
    session.close()
    return(json.dumps(dd))



#Получить Refs, если их нет, добавляем
def get_refs(db_session: Session, refs_list: list):
    refs = []
    if(refs_list != None):
        for ref in refs_list:
            ref_res = add_ref(db_session, ref) 
            if(ref_res["status"] == 200 or ref_res["status"] == 503):
                refs.append(ref_res["id"])
    return refs


#Добавить ссылку
def add_ref(db_session: Session, ref_name: str):
    try:
        ref = db_session.query(Refs).filter_by(name = ref_name).first()
        if(ref == None):
            ref = Refs(ref_name)
            db_session.add(ref)
            db_session.flush()
            db_session.commit()
            return {'status':200, 'id': ref.id, 'created_at': ref.created_at.strftime("%d.%m.%Y"), 'updated_at': ref.updated_at.strftime("%d.%m.%Y")}
        else:

            return {"status": 503, "message": 'Ref already exist!', 'id': ref.id}
    except Exception as e:
        log.error("Error in controllers `VulnsController` function  `add_ref`. Details - {0}".format(str(e)))
        return {"status": 501, "message": str(e)}


#Добавить детали уязвимости
def add_vuln_detail(db_session: Session, data: dict):
    res = {'rsp_k':410,'message':'Не удалось добавить запись!'}
    vuln_detail_id = None
    try:
        
        for item in db_session.query(VulnDetails).filter_by(cvss_score = float(data["cvss"]),
                                                            title = data["name"],
                                                            description = data["info"],
                                                            solution =  data["solution"], 
                                                            vuln_id = data["id"]).limit(1):
            vuln_detail_id = item.id
        if(vuln_detail_id == None):
            item = VulnDetails(data["id"],
                        float(data["cvss"]),
                        data["name"],
                        data["info"],
                        data["solution"],
                        data["vulner_id"])
            db_session.add(item)
            db_session.flush()
            db_session.commit()
        res = {'rsp_k':200,'id':item.id}
    except Exception as e:
        log.error("Ошибка при добавлении записи в таблицу refs ({0}).".format())
        db_session.rollback()
    return res


#Добавить инфо по уязвимости
def add_vulns(db_session: Session, workspace_id: int, data: dict, current_user: list):
    try:
        host = None
        host_id = None
        service_id = None
        #Get host id
        if(str(type(data['host'])) == "<class 'dict'>"):
           host_id = data['host']['id']
        if(str(type(data['host'])) == "<class 'int'>"):
           host_id = data['host']
        if(str(type(data['host'])) == "<class 'str'>"):
            host_id = HostsController.get_host_id(db_session, workspace_id, data['host'])
        
        if(str(type(host_id)) == "<class 'int'>"):
            host = db_session.query(func.jsonb_build_object('id', Hosts.id, 'address', Hosts.address, 'purpose', Hosts.purpose, 'os_family', Hosts.os_family)).filter_by(workspace_id = int(workspace_id), id = host_id).first()
            host= dict(host[0])
        
        if(host_id == None):
            return {"status": 501, "message": "Host doesn't be a NULL"}
        
        data['host_id'] = host_id

        #Get services id
        if(data['service'] != None):
            if(str(type(data['service'])) == "<class 'dict'>"):
                service_id = data['service']['id']
            if(str(type(data['service'])) == "<class 'int'>"):
                service_id = data['service']
        data['service_id'] = service_id

        
        vuln = Vulns(data["name"])
        db_session.add(vuln)
        vuln.update_state(data)
        db_session.flush() 

        #Add to vulns_refs table
        if(data['refs'] != None and len(data['refs']) != 0):
            for ref in data['refs']:
                if(str(type(ref)) == "<class 'dict'>"):
                    vuln_ref = VulnsRefs(ref['id'], vuln.id)
                if(str(type(ref)) == "<class 'int'>"):
                    vuln_ref = VulnsRefs(ref, vuln.id)
                db_session.add(vuln_ref)
                db_session.flush()
        
        #Add to vulns_details table
        vuln_details_id = []
        if(data['details']  != None and len(data['details'] ) != 0):
            for detail in data['details']:
                vuln_detail = VulnDetails(vuln.id)
                db_session.add(vuln_detail)
                vuln_detail.update_state(detail)
                db_session.flush()
                vuln_details_id.append({"id": vuln_detail.id})
            vuln.update_state({"vuln_detail_count": len(data['details']) })
            db_session.flush()

        #Add to vulns_attempts table
        vuln_attempts_id = []
        if(data['attempts']  != None and len(data['attempts'] ) != 0):
            username = 'unknown'
            if(current_user != None):
                username = current_user.username
            for attempt in data['attempts']:
                vuln_attempt = VulnAttempts(vuln.id)
                db_session.add(vuln_attempt)
                attempt['username'] = username
                vuln_attempt.update_state(attempt)
                db_session.flush()
                vuln_attempts_id.append({"id": vuln_attempt.id})
                if(vuln_attempt.exploited == True):
                    vuln.update_state({"exploited_at": vuln_attempt.attempted_at })
                    db_session.flush()
            vuln.update_state({"vuln_attempt_count": len(data['attempts']) })
            db_session.flush()

        db_session.commit()
        return {'status':200, 'id': vuln.id, 'vuln_details': vuln_details_id, 'vuln_attempts': vuln_attempts_id, "created_at": vuln.created_at.strftime("%d.%m.%Y"), "updated_at": vuln.updated_at.strftime("%d.%m.%Y") }
    except Exception as e:
        log.error("Error in controllers `VulnsController` function  `add_vulns`. Details - {0}".format(str(e)))
        return {"status": 501, "message": str(e)}



#Редактировать инфо по уязвимости
def edit_vulns(db_session: Session, workspace_id: int, data: dict, current_user: list):
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
        
        if(host_id == None):
            return {"status": 501, "message": "Host doesn't be a NULL"}
        
        data['host_id'] = host_id

        #Get services id
        if(data['service'] != None):
            service_id = data['service']['id']
        
        data['service_id'] = service_id

        vuln = db_session.query(Vulns).filter_by(id = data['id']).first()
        vuln.update_state(data)
        db_session.flush()

        #Del and Add to vulns_refs table
        db_session.query(VulnsRefs).filter_by(vuln_id = vuln.id).delete()
        if(data['refs'] != None and len(data['refs']) != 0):
            for ref in data['refs']:
                vuln_ref = VulnsRefs(ref['id'], vuln.id)
                db_session.add(vuln_ref)
                db_session.flush()
        
        #Del and Add to vulns_details table
        vuln_details_id = []
        db_session.query(VulnDetails).filter_by(vuln_id = vuln.id).delete()
        if(data['details']  != None and len(data['details'] ) != 0):
            for detail in data['details']:
                vuln_detail = VulnDetails(vuln.id)
                db_session.add(vuln_detail)
                vuln_detail.update_state(detail)
                db_session.flush()
                vuln_details_id.append({"id": vuln_detail.id})
            vuln.update_state({"vuln_detail_count": len(data['details']) })
            db_session.flush()

        #Add to vulns_attempts table
        vuln_attempts_id = []
        db_session.query(VulnAttempts).filter_by(vuln_id = vuln.id).delete()
        if(data['attempts']  != None and len(data['attempts'] ) != 0):
            username = 'unknown'
            if(current_user != None):
                username = current_user.username
            for attempt in data['attempts']:
                vuln_attempt = VulnAttempts(vuln.id)
                db_session.add(vuln_attempt)
                attempt['username'] = username
                vuln_attempt.update_state(attempt)
                db_session.flush()
                vuln_attempts_id.append({"id": vuln_attempt.id})
                if(vuln_attempt.exploited == True):
                    vuln.update_state({"exploited_at": vuln_attempt.attempted_at })
                    db_session.flush()
            vuln.update_state({"vuln_attempt_count": len(data['attempts']) })
            db_session.flush()

        db_session.flush()
        db_session.commit()
        return {'status':200, 'id': vuln.id, 'vuln_details': vuln_details_id, 'vuln_attempts': vuln_attempts_id, "updated_at": vuln.updated_at.strftime("%d.%m.%Y") }
    except Exception as e:
        log.error("Error in controllers `VulnsController` function  `edit_vulns`. Details - {0}".format(str(e)))
        return {"status": 501, "message": str(e)}


#Удаление записи из таблицы vulns. Входные данные - id
def del_vulns(db_session: Session, workspace_id: int, id: int):
    try:
        db_session.query(Vulns).filter_by(id = id).delete()
        db_session.flush()
        db_session.query(VulnsRefs).filter_by(vuln_id = id).delete()
        db_session.flush()
        db_session.query(VulnDetails).filter_by(vuln_id = id).delete()
        db_session.flush()
        db_session.query(VulnAttempts).filter_by(vuln_id = id).delete()
        db_session.flush()
        db_session.commit()
        return {"status": 200, "message": ''}
    except Exception as e:
        log.error("Error in controllers `VulnsController` function  `del_vulns`. Details - {0}".format(str(e)))
        return {"status": 500, "message": str(e)}


#Удаление записи из таблицы vulns. Входные данные - service_id
def del_vulns_by_ServiceID(db_session: Session, service_id: int):
    res = {'rsp_k':410,'message':'Не удалось удалить запись!'}
    try:
        for item in db_session.query(Vulns).filter_by(service_id = service_id):
            db_session.query(VulnsRefs).filter_by(vuln_id = item.id).delete()
            db_session.flush()
            db_session.query(Vulns).filter_by(id = item.id).delete()
            db_session.flush()
            db_session.query(VulnDetails).filter_by(vuln_id = item.id).delete()
            db_session.flush()
        db_session.commit()
        res = {'rsp_k':200}
    except Exception as e:
        log.error("Ошибка при удалении записи в таблице vulns (service_id - {0}).".format(service_id))
        db_session.rollback()
    return res


#Удаление записи из таблицы vulns. Входные данные - host_id
def del_vulns_by_HostID(db_session: Session, host_id: int):
    res = {'rsp_k':410,'message':'Не удалось удалить запись!'}
    try:
        for item in db_session.query(Vulns).filter_by(host_id = host_id):
            db_session.query(VulnsRefs).filter_by(vuln_id = item.id).delete()
            db_session.flush()
            db_session.query(Vulns).filter_by(id = item.id).delete()
            db_session.flush()
            db_session.query(VulnDetails).filter_by(vuln_id = item.id).delete()
            db_session.flush()
        db_session.commit()
        res = {'rsp_k':200}
    except Exception as e:
        log.error("Ошибка при удалении записи в таблице vulns (host_id - {0}).".format(host_id))
        db_session.rollback()
    return res


#Проверка, существует ли данная запись 
def check_IN_vulns(data: dict, host_id: int, service_id: int):
    res = True
    session = create_session()
    select_statement = '''SELECT vulns.id FROM vulns 
    WHERE vulns.host_id = {0} AND vulns.service_id = {1} AND vulns.name = '{2}' AND vulns.info = '{3}' '''.format(str(int(host_id)), str(int(service_id)), str(data['name']), str(data['info']))
    result_set = session.execute(select_statement)
    vulns_id = [dict(r) for r in result_set]
    session.close()
    if(len(vulns_id) == 0):
        res = False
    else:
        res = True
    return res


#Получить заметки по адресу, сервису, типу записи
def get_Vulns_by_HostID(db_session: Session, workspace_id: int, host_id: int, service_id: int, data: dict):
    res = None
    try:
        for vuln in db_session.query(Vulns).filter_by(host_id = host_id, service_id = service_id, name = data["name"]).limit(1):
            res = vuln.id
    except Exception as e:
        log.error("Error function get_Vulns_by_HostID-Vulns (workspace_id - {0}, host_id - {1}, service_id - {2},).".format(workspace_id, host_id, service_id))
    return res


#Количество уязвимостей по хостам
def get_count(db_session: Session, workspace_id: int, arg) -> int:
    try:
        q = (
                db_session.query(
                func.count(distinct(Vulns.id)).label('vulns')
            )
            .outerjoin(Hosts, Vulns.host_id == Hosts.id)
            .outerjoin(HostsTags, HostsTags.host_id == Hosts.id)
            .outerjoin(Tags, Tags.id == HostsTags.tag_id)
            .outerjoin(Services, Services.id == Vulns.service_id)
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
            .outerjoin(VulnDetails, VulnDetails.vuln_id == Vulns.id)
            .outerjoin(VulnAttempts, VulnAttempts.vuln_id == Vulns.id)
            .outerjoin(VulnsRefs, VulnsRefs.vuln_id == Vulns.id)
            .outerjoin(Refs, Refs.id == VulnsRefs.ref_id)
            .filter(Hosts.workspace_id == workspace_id)
            .group_by(Hosts.id)
            .group_by(Services.id)
            .group_by(Vulns.id)
            .order_by(Hosts.address)
        )

        q = apply_dynamic_filters(q, arg)
        return len([dict(r) for r in q.all()]) 
    except Exception as e:
        log.error("Error in controllers `VulnsController` function  `get_count`. Details - {0}".format(str(e)))
        return None