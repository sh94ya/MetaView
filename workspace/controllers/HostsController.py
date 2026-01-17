import ipaddress
import json
from sqlalchemy.orm import Session
from datetime import datetime
from workspace.controllers import CredsController, LootsController, NotesController, ServicesController, VulnsController
from workspace.models.migration import Hosts, Events, Tags, HostsTags, Services, Notes, Loots, MetasploitCredentialCores, MetasploitCredentialLogins, MetasploitCredentialRealms, MetasploitCredentialPublics, MetasploitCredentialPrivates, MetasploitCredentialOriginCrackedPasswords, MetasploitCredentialOriginSessions, MetasploitCredentialOriginServices, Sessions, Vulns, VulnDetails, VulnAttempts, VulnsRefs, Refs
import workspace.logger as logging
from flask import jsonify

from sqlalchemy import and_, func, distinct
from sqlalchemy.orm import aliased
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.sql import label

from workspace.controllers.Parsers import apply_dynamic_filters

log = logging.getLogger()



'''
SELECT hosts.id, array_agg(DISTINCT jsonb_build_object('id',tags.id,'name', tags.name)) as tags, hosts.address, hosts.mac, hosts.name, hosts.state, hosts.os_family, hosts.os_name, hosts.os_flavor, hosts.os_sp, hosts.os_lang, hosts.arch, hosts.purpose, hosts.virtual_host, hosts.info, hosts.comments FROM hosts
                                        LEFT JOIN hosts_tags ON hosts_tags.host_id = hosts.id 
                                        LEFT JOIN tags ON tags.id = hosts_tags.tag_id 
                                        LEFT JOIN services ON services.host_id = hosts.id
                                        LEFT JOIN notes ON notes.host_id = hosts.id
                                        LEFT JOIN loots ON loots.host_id = hosts.id
                                        LEFT JOIN metasploit_credential_logins ON services.id  = metasploit_credential_logins.service_id
										LEFT JOIN metasploit_credential_cores  ON metasploit_credential_logins.core_id  = metasploit_credential_cores.id 
										LEFT JOIN metasploit_credential_realms  ON metasploit_credential_realms.id  = metasploit_credential_cores.realm_id
										LEFT JOIN metasploit_credential_privates ON metasploit_credential_privates.id = metasploit_credential_cores.private_id
										LEFT JOIN metasploit_credential_publics ON  metasploit_credential_publics.id = metasploit_credential_cores.public_id 
										LEFT JOIN metasploit_credential_origin_cracked_passwords ON  metasploit_credential_origin_cracked_passwords.metasploit_credential_core_id = metasploit_credential_cores.id 
										LEFT JOIN metasploit_credential_origin_services ON  metasploit_credential_origin_services.service_id  = services.id 
										LEFT JOIN sessions ON  sessions.host_id  = hosts.id										
										LEFT JOIN metasploit_credential_origin_sessions ON  metasploit_credential_origin_sessions.session_id  = sessions.id 
										LEFT JOIN vulns on vulns.id = vulns.id 
										LEFT JOIN vuln_details on vuln_details.vuln_id = vulns.id 
										LEFT JOIN vuln_attempts on vuln_attempts.vuln_id  = vulns.id 
										LEFT JOIN vulns_refs  on vulns_refs.vuln_id  = vulns.id 
                                        WHERE hosts.workspace_id = 9 GROUP BY hosts.id ORDER BY hosts.address
'''



def getDataHosts (db_session: Session, workspace_id: int, arg) -> dict:
    dd = []
    try:
        TagAlias = aliased(Tags)
        tags_json = func.array_agg(
            distinct(
                func.jsonb_build_object('id', Tags.id, 'name', Tags.name)
            )
        ).label('tags')

        q = (
                db_session.query(
                Hosts.id,
                tags_json,
                Hosts.address,
                Hosts.mac,
                Hosts.name,
                Hosts.state,
                Hosts.os_family,
                Hosts.os_name,
                Hosts.os_flavor,
                Hosts.os_sp,
                Hosts.os_lang,
                Hosts.arch,
                Hosts.purpose,
                Hosts.virtual_host,
                Hosts.info,
                Hosts.comments,
            )
            .select_from(Hosts)
            .outerjoin(HostsTags, HostsTags.host_id == Hosts.id)
            .outerjoin(Tags, Tags.id == HostsTags.tag_id)
            .outerjoin(Services, Services.host_id == Hosts.id)
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
            .outerjoin(Vulns, Vulns.host_id == Hosts.id)
            .outerjoin(VulnDetails, VulnDetails.vuln_id == Vulns.id)
            .outerjoin(VulnAttempts, VulnAttempts.vuln_id == Vulns.id)
            .outerjoin(VulnsRefs, VulnsRefs.vuln_id == Vulns.id)
            .outerjoin(Refs, Refs.id == VulnsRefs.ref_id)
            .filter(Hosts.workspace_id == workspace_id)
            # .group_by(Hosts.id)
            # .order_by(Hosts.address)
        )

        q = apply_dynamic_filters(q, arg)
        return jsonify([dict(r) for r in q.all()]), 200  
    except Exception as e:
        log.error("Error in controllers `Hosts` function  `getDataHosts`. Details - {0}".format(str(e)))
        return {"status": 500, "message": str(e) }


# Возвращает все хосты проекта где есть сервисы
def get_by_service_port(db_session: Session, workspace_id: int, node: dict) -> dict:
    dd = []
    select_statement = ''
    try:
        select_statement = '''SELECT hosts.id, array_agg(DISTINCT jsonb_build_object('id',tags.id,'name', tags.name)) as tags, hosts.address, hosts.mac, hosts.name, hosts.state, hosts.os_family, hosts.os_name, hosts.os_flavor, hosts.os_sp, hosts.os_lang, hosts.arch, hosts.purpose, hosts.virtual_host, hosts.info, hosts.comments FROM hosts 
                                    LEFT JOIN hosts_tags ON hosts_tags.host_id = hosts.id 
                                    LEFT JOIN tags ON tags.id = hosts_tags.tag_id 
                                    INNER JOIN services ON hosts.id = services.host_id 
                                    WHERE workspace_id = {0} AND services.port = {1} AND services.proto = '{2}' GROUP BY hosts.id ORDER BY hosts.address'''.format(str(int(workspace_id)), str(int(node['port'])), str(node['proto']))
        
        result_set = db_session.execute(select_statement)
        dd = [dict(r) for r in result_set]
        return dd
    except Exception as e:
        log.error("Error function get_by_service_name-Hosts (workspace_id - {0}). Message: {1}".format(str(workspace_id), e._message))


# Возвращает все хосты проекта по имени сервиса
def get_by_service_name(db_session: Session, workspace_id: int, node: dict) -> dict:
    dd = []
    select_statement = ''
    try:
        select_statement = '''SELECT hosts.id, array_agg(DISTINCT jsonb_build_object('id',tags.id,'name', tags.name)) as tags, hosts.address, hosts.mac, hosts.name, hosts.state, hosts.os_family, hosts.os_name, hosts.os_flavor, hosts.os_sp, hosts.os_lang, hosts.arch, hosts.purpose, hosts.virtual_host, hosts.info, hosts.comments FROM hosts 
                                    LEFT JOIN hosts_tags ON hosts_tags.host_id = hosts.id 
                                    LEFT JOIN tags ON tags.id = hosts_tags.tag_id 
                                    INNER JOIN services ON hosts.id = services.host_id 
                                    WHERE workspace_id = {0} AND services.name = '{1}' GROUP BY hosts.id ORDER BY hosts.address'''.format(str(int(workspace_id)), str(node['label']))
        
        result_set = db_session.execute(select_statement)
        dd = [dict(r) for r in result_set]
        return dd
    except Exception as e:
        log.error("Error function get_by_service_name-Hosts (workspace_id - {0}). Message: {1}".format(str(workspace_id), e._message))


# Возвращает все хосты проекта где есть сервисы
def get_by_services(db_session: Session, workspace_id: int) -> dict:
    dd = []
    select_statement = ''
    try:
        select_statement = '''SELECT hosts.id, array_agg(DISTINCT jsonb_build_object('id',tags.id,'name', tags.name)) as tags, hosts.address, hosts.mac, hosts.name, hosts.state, hosts.os_family, hosts.os_name, hosts.os_flavor, hosts.os_sp, hosts.os_lang, hosts.arch, hosts.purpose, hosts.virtual_host, hosts.info, hosts.comments FROM hosts 
                                    LEFT JOIN hosts_tags ON hosts_tags.host_id = hosts.id 
                                    LEFT JOIN tags ON tags.id = hosts_tags.tag_id 
                                    WHERE workspace_id = {0}  GROUP BY hosts.id ORDER BY hosts.address'''.format(str(int(workspace_id)))
        
        result_set = db_session.execute(select_statement)
        dd = [dict(r) for r in result_set]
        return dd
    except Exception as e:
        log.error("Error function get_hosts_by_services-Hosts (workspace_id - {0}). Message: {1}".format(str(workspace_id), e._message))


#Получить выборку из таблицы hosts
def get_by_subnet(db_session: Session, workspace_id: int, node: dict) -> dict:
    dd = []
    select_statement = ''
    try:
        if(node['type'] != 'host'):

            if(node['type'] == 'root' or node['type'] == 'dir_subnets'):
                select_statement = '''SELECT hosts.id, array_agg(DISTINCT jsonb_build_object('id',tags.id,'name', tags.name)) as tags, hosts.address, hosts.mac, hosts.name, hosts.state, hosts.os_family, hosts.os_name, hosts.os_flavor, hosts.os_sp, hosts.os_lang, hosts.arch, hosts.purpose, hosts.virtual_host, hosts.info, hosts.comments FROM hosts
                                        LEFT JOIN hosts_tags ON hosts_tags.host_id = hosts.id 
                                        LEFT JOIN tags ON tags.id = hosts_tags.tag_id 
                                        WHERE workspace_id = {0} GROUP BY hosts.id ORDER BY hosts.address '''.format(str(int(workspace_id)))
            
            else:
                select_statement = '''SELECT hosts.id, array_agg(DISTINCT jsonb_build_object('id',tags.id,'name', tags.name)) as tags, hosts.address, hosts.mac, hosts.name, hosts.state, hosts.os_family, hosts.os_name, hosts.os_flavor, hosts.os_sp, hosts.os_lang, hosts.arch, hosts.purpose, hosts.virtual_host, hosts.info, hosts.comments FROM hosts
                                        LEFT JOIN hosts_tags ON hosts_tags.host_id = hosts.id 
                                        LEFT JOIN tags ON tags.id = hosts_tags.tag_id 
                                        WHERE workspace_id = {0} AND hosts.address << inet('{1}') GROUP BY hosts.id ORDER BY hosts.address '''.format(str(int(workspace_id)), str(ipaddress.ip_network(node['label'], strict=False)))                
        
        else:
            select_statement = '''SELECT hosts.id, array_agg(DISTINCT jsonb_build_object('id',tags.id,'name', tags.name)) as tags, hosts.address, hosts.mac, hosts.name, hosts.state, hosts.os_family, hosts.os_name, hosts.os_flavor, hosts.os_sp, hosts.os_lang, hosts.arch, hosts.purpose, hosts.virtual_host, hosts.info, hosts.comments FROM hosts
                                        LEFT JOIN hosts_tags ON hosts_tags.host_id = hosts.id 
                                        LEFT JOIN tags ON tags.id = hosts_tags.tag_id 
                                        WHERE workspace_id = {0} AND hosts.id = {1} GROUP BY hosts.id ORDER BY hosts.address '''.format(str(int(workspace_id)), str(int(node['host_id'])))     
        
        result_set = db_session.execute(select_statement)
        dd = [dict(r) for r in result_set]
        return dd
    except Exception as e:
        log.error("Error function get_by_subnet-Hosts (workspace_id - {0}, node - {1}). Message: {2}".format(str(workspace_id), node, e._message))


#Получить выборку из таблицы hosts по тегам
def get_by_tag(db_session: Session, workspace_id: int, node: dict) -> dict:
    dd = []
    select_statement = ''
    try:
        if(node['type'] == 'dir_tags'):
            select_statement = '''SELECT hosts.id, array_agg(DISTINCT jsonb_build_object('id',tags.id,'name', tags.name)) as tags, hosts.address, hosts.mac, hosts.name, hosts.state, hosts.os_family, hosts.os_name, hosts.os_flavor, hosts.os_sp, hosts.os_lang, hosts.arch, hosts.purpose, hosts.virtual_host, hosts.info, hosts.comments FROM hosts
                                        INNER JOIN hosts_tags ON hosts_tags.host_id = hosts.id 
                                        INNER JOIN tags ON tags.id = hosts_tags.tag_id 
                                        WHERE workspace_id = {0} GROUP BY hosts.id ORDER BY hosts.address '''.format(str(int(workspace_id)))
        
        if(node['type'] == 'tag'):
            select_statement = '''SELECT hosts.id, array_agg(DISTINCT jsonb_build_object('id',tags.id,'name', tags.name)) as tags, hosts.address, hosts.mac, hosts.name, hosts.state, hosts.os_family, hosts.os_name, hosts.os_flavor, hosts.os_sp, hosts.os_lang, hosts.arch, hosts.purpose, hosts.virtual_host, hosts.info, hosts.comments FROM hosts
                                        LEFT JOIN hosts_tags ON hosts_tags.host_id = hosts.id 
                                        LEFT JOIN tags ON tags.id = hosts_tags.tag_id 
                                        WHERE workspace_id = {0} AND tags.id = {1} GROUP BY hosts.id ORDER BY hosts.address '''.format(str(int(workspace_id)), str(int(node['tag_id'])))                    
        
        result_set = db_session.execute(select_statement)
        dd = [dict(r) for r in result_set]
        return dd
    except Exception as e:
        log.error("Error function get_by_tag-Hosts (workspace_id - {0}, node - {1}). Message: {2}".format(str(workspace_id), node, e._message))


#Получить выборку из таблицы hosts по ОС
def get_by_os(db_session: Session, workspace_id: int, node: dict) -> dict:
    dd = []
    select_statement = ''
    try:
        if(node['type'] == 'dir_os'):
            select_statement = '''SELECT hosts.id, array_agg(DISTINCT jsonb_build_object('id',tags.id,'name', tags.name)) as tags, hosts.address, hosts.mac, hosts.name, hosts.state, hosts.os_family, hosts.os_name, hosts.os_flavor, hosts.os_sp, hosts.os_lang, hosts.arch, hosts.purpose, hosts.virtual_host, hosts.info, hosts.comments FROM hosts
                                        LEFT JOIN hosts_tags ON hosts_tags.host_id = hosts.id 
                                        LEFT JOIN tags ON tags.id = hosts_tags.tag_id 
                                        WHERE workspace_id = {0} GROUP BY hosts.id ORDER BY hosts.address '''.format(str(int(workspace_id)))
        
        if(node['type'] == 'dir_os_family'):
            select_statement = '''SELECT hosts.id, array_agg(DISTINCT jsonb_build_object('id',tags.id,'name', tags.name)) as tags, hosts.address, hosts.mac, hosts.name, hosts.state, hosts.os_family, hosts.os_name, hosts.os_flavor, hosts.os_sp, hosts.os_lang, hosts.arch, hosts.purpose, hosts.virtual_host, hosts.info, hosts.comments FROM hosts
                                        LEFT JOIN hosts_tags ON hosts_tags.host_id = hosts.id 
                                        LEFT JOIN tags ON tags.id = hosts_tags.tag_id 
                                        WHERE workspace_id = {0} AND hosts.os_family = '{1}' GROUP BY hosts.id ORDER BY hosts.address '''.format(str(int(workspace_id)), str(node['value']))                    
        
        if(node['type'] == 'dir_os_name'):
            select_statement = '''SELECT hosts.id, array_agg(DISTINCT jsonb_build_object('id',tags.id,'name', tags.name)) as tags, hosts.address, hosts.mac, hosts.name, hosts.state, hosts.os_family, hosts.os_name, hosts.os_flavor, hosts.os_sp, hosts.os_lang, hosts.arch, hosts.purpose, hosts.virtual_host, hosts.info, hosts.comments FROM hosts
                                        LEFT JOIN hosts_tags ON hosts_tags.host_id = hosts.id 
                                        LEFT JOIN tags ON tags.id = hosts_tags.tag_id 
                                        WHERE workspace_id = {0} AND hosts.os_family = '{1}' AND hosts.os_name = '{2}' GROUP BY hosts.id ORDER BY hosts.address '''.format(str(int(workspace_id)), str(node['os_family']),str(node['value']))   

        result_set = db_session.execute(select_statement)
        dd = [dict(r) for r in result_set]
        return dd
    except Exception as e:
        log.error("Error function get_by_os-Hosts (workspace_id - {0}, node - {1}). Message: {2}".format(str(workspace_id), node, e._message))


#Получить выборку из таблицы hosts
def get_by_purpose(db_session: Session, workspace_id: int, node: dict) -> dict:
    dd = []
    select_statement = ''
    try:
        if(node['type'] == 'dir_types'):
            select_statement = '''SELECT hosts.id, array_agg(DISTINCT jsonb_build_object('id',tags.id,'name', tags.name)) as tags, hosts.address, hosts.mac, hosts.name, hosts.state, hosts.os_family, hosts.os_name, hosts.os_flavor, hosts.os_sp, hosts.os_lang, hosts.arch, hosts.purpose, hosts.virtual_host, hosts.info, hosts.comments FROM hosts
                                        LEFT JOIN hosts_tags ON hosts_tags.host_id = hosts.id 
                                        LEFT JOIN tags ON tags.id = hosts_tags.tag_id 
                                        WHERE workspace_id = {0} GROUP BY hosts.id ORDER BY hosts.address '''.format(str(int(workspace_id)))
       
        if(node['type'] == 'purpose'):
            select_statement = '''SELECT hosts.id, array_agg(DISTINCT jsonb_build_object('id',tags.id,'name', tags.name)) as tags, hosts.address, hosts.mac, hosts.name, hosts.state, hosts.os_family, hosts.os_name, hosts.os_flavor, hosts.os_sp, hosts.os_lang, hosts.arch, hosts.purpose, hosts.virtual_host, hosts.info, hosts.comments FROM hosts
                                        LEFT JOIN hosts_tags ON hosts_tags.host_id = hosts.id 
                                        LEFT JOIN tags ON tags.id = hosts_tags.tag_id 
                                        WHERE workspace_id = {0} AND hosts.purpose = '{1}' GROUP BY hosts.id ORDER BY hosts.address '''.format(str(int(workspace_id)), str(node['label']))                   
        
        result_set = db_session.execute(select_statement)
        dd = [dict(r) for r in result_set]
        return dd
    except Exception as e:
        log.error("Error function get_by_purpose-Hosts (workspace_id - {0}, node - {1}). Message: {2}".format(str(workspace_id), node, e._message))


# Возвращает топ 5 os_name
def get_distinct_os_name(db_session: Session, workspace_id: int) -> dict:
    dd = []
    select_statement = ''
    try:
        select_statement = '''SELECT hosts.os_name AS value, COUNT(hosts.os_name) AS count FROM hosts 
                                    WHERE  hosts.workspace_id = {0} 
                                    GROUP BY hosts.os_name
                                    ORDER BY COUNT(*) DESC '''.format(str(int(workspace_id)))    
        result_set = db_session.execute(select_statement)
        dd = [dict(r) for r in result_set]
        return dd
    except Exception as e:
        log.error("Ошибка при обращении к таблице services, func get_top_service() (workspace_id - {0}).".format(workspace_id))


# Возвращает количество purpose
def get_distinct_purpose(db_session: Session, workspace_id: int) -> dict:
    dd = []
    select_statement = ''
    try:
        select_statement = '''SELECT  hosts.purpose AS value, count(hosts.purpose) FROM hosts 
                                    WHERE hosts.workspace_id = {0} 
                                    GROUP BY hosts.purpose
                                    ORDER  BY COUNT(*) DESC'''.format(str(int(workspace_id)))    
        result_set = db_session.execute(select_statement)
        dd = [dict(r) for r in result_set]
        return dd
    except Exception as e:
        log.error("Ошибка при обращении к таблице hosts, func get_top_service() (workspace_id - {0}).".format(workspace_id))


# Возвращает теги узлов
def get_tags(db_session: Session, workspace_id : int) -> dict:
    dd = []
    select_statement = ''
    try:
        if(workspace_id == None):
            select_statement = "SELECT tags.id, tags.name, tags.desc FROM tags ORDER BY tags.name DESC"
        else:
            select_statement = '''SELECT tags.id, tags.name, tags.desc FROM tags 
                                        INNER JOIN hosts_tags ON tags.id = hosts_tags.tag_id
                                        INNER JOIN hosts ON hosts_tags.host_id = hosts.id 
                                        WHERE hosts.workspace_id = {0} 
                                        GROUP BY tags.id
                                        ORDER  BY tags.name ASC'''.format(str(int(workspace_id)))    
        result_set = db_session.execute(select_statement)
        dd = [dict(r) for r in result_set]
        return dd
    except Exception as e:
        log.error("Ошибка при обращении к таблице tags, func get_tags() (workspace_id - {0}).".format(workspace_id))


#Функция добавления записи в таблицу tags
def add_new_tag(db_session: Session, data: dict):
    res = {'rsp_k':410,'message':'Не удалось добавить запись!'}
    try:
        tag = Tags(data["name"],
                   data["desc"],
                   datetime.now(),
                   datetime.now())
        db_session.add(tag)
        db_session.commit()
        res = {'rsp_k':200,'id':tag.id}
    except Exception as e:
        log.error("Ошибка при добавлении записи в таблицу tags")
        res = {'rsp_k':410,'message':'Не удалось добавить запись!'}
    return res


#Функция добавления записей в таблицу hosts_tags
def add_tags_on_hosts(db_session: Session, data: dict):
    res = {'rsp_k':410,'message':'Не удалось добавить запись!'}
    try:
        for host_id in data["host_id"]:
            for tag_id in data["tag_id"]:
                if(check_dublicate_host_tags(db_session, host_id, tag_id) == False):
                    host_tag = HostsTags(host_id, tag_id)
                    db_session.add(host_tag)
                    db_session.commit()
        res = {'rsp_k':200}
    except Exception as e:
        log.error("Ошибка при добавлении записи в таблицу hosts_tags")
        res = {'rsp_k':410,'message':'Не удалось добавить запись!'}
    return res


#Функция удаления записей из таблицы hosts_tags для определенных хостов
def remove_tags_on_hosts(db_session: Session, host_id: int):
    res = {'rsp_k':410,'message':'Не удалось завершить операция!'}
    try:
        db_session.query(HostsTags).filter_by(host_id = host_id).delete()
        db_session.commit()
        res = {'rsp_k':200}
    except Exception as e:
        log.error("Ошибка при совершении операции. Функция remove_tags_on_hosts. Exception: {0}").format(e.message)
    return res


#Функция проверки дубликатов в таблице hosts_tags
def check_dublicate_host_tags(db_session: Session, host_id: int, tag_id: int):
    res = False
    try:
        for item in db_session.query(HostsTags).filter_by(host_id = host_id, 
                                                          tag_id = tag_id).limit(1):
            return  True
    except Exception as e:
        log.error("Ошибка в функции check_dublicate_host_tags() (host_id - {0}, tag_id - {1}). Exception: {2}".format(host_id, tag_id, e.message)) 
    return res
  

#Получить id  по его адресу
def get_host_id(db_session: Session, workspace_id: int, address_: str):
    res = None
    try:
        if(address_ != None and address_ != ''):
            for item in db_session.query(Hosts).filter_by(workspace_id = workspace_id, 
                                                          address = address_).limit(1):
                res = item.id
    except Exception as e:
        log.error("Ошибка при обращении к таблице hosts, func get_host_id() (workspace_id - {0}).".format(workspace_id)) 
    return res


#Получить address по его host_id
def get_host_address(db_session: Session, workspace_id: int, host_id: int):
    res = None
    try:
        for item in db_session.query(Hosts).filter_by(id = host_id).limit(1):
            res = item.address
    except Exception as e:
        log.error("Ошибка при определении host address (workspace_id - {0}, host_id - {1}).".format(str(workspace_id), str(host_id)) )  
    return res


#Функция добавления запись в таблицу hosts
def add_hosts(db_session: Session, workspace_id: int, data: dict):
    try:
        res = db_session.query(Hosts).filter_by(workspace_id = int(workspace_id), address = str(ipaddress.ip_address(data['address']))).first()
        if(res):
            return {"status": 503, "message": 'This address already exist', "id": res.id}
        else:
            host = Hosts(workspace_id, data['address'])
            db_session.add(host)
            host.update_state(data)
            db_session.flush()
            if 'tags' not in data:
                log.error("Нет элемента tags во входных данных")
            else:
                tags = {"host_id": [host.id], "tag_id": list(map(lambda x: x['id'], data["tags"]))}
                add_tags_on_hosts(db_session, tags)
            db_session.commit()
            return  {'status':200, 'id': host.id, 'created_at': host.created_at.strftime("%d.%m.%Y"), 'updated_at': host.created_at.strftime("%d.%m.%Y") }
    except Exception as e:
        log.error("Error in controllers `Hosts` function  `add_hosts`. Details - {0}".format(str(e)))
        return {"status": 501, "message": str(e)}


#Функция прибавления/убавления количества services, notes, creds, vulns
def inc_dec_serv_note_cred(db_session: Session, column: str, action: str, host_id: int) -> int:
    res = False
    try:
        if(action == 'increase'):
            db_session.query(Hosts).filter_by(id = host_id).update({"{0}".format(column): + 1})
        if(action == 'decrease'):
            db_session.query(Hosts).filter_by(id = host_id).update({"{0}".format(column): - 1})
        db_session.flush()
        res = True
    except Exception as e:
        log.error("Ошибка при прибавления/убавления количества services, notes, creds, vulns таблицы hosts (action - {0}, column - {1}, host_id - {2}).".format(action, column, host_id))
    return res


#Функция редактирования записи в таблицу hosts
def edit_hosts(db_session: Session, workspace_id: int, data: dict):
    try:
        host = db_session.query(Hosts).filter_by(workspace_id = int(workspace_id), id = data['id']).first()
        if(host):
            host.update_state(data)
            db_session.flush()
            if 'tags' not in data:
                log.error("Нет элемента tags во входных данных")
            else:
                tags = {"host_id": [data['id']], "tag_id": list(map(lambda x: x['id'], data["tags"]))}
                remove_tags_on_hosts(db_session, data['id'])
                add_tags_on_hosts(db_session, tags)
            db_session.commit()
            return  {'status':200, 'id': host.id, 'updated_at': host.updated_at.strftime("%d.%m.%Y") }
        else:
            return {"status": 501, "message": 'Такого узла не существует'}
    except Exception as e:
        log.error("Error in controllers `Hosts` function  `edit_hosts`. Details - {0}".format(str(e)))
        return {"status": 501, "message": str(e)}



#Удалить hosts. Сделать рефакторинг
def del_hosts(db_session: Session, workspace_id: int, host_id: int):
    try:
        #Delete Creds
        CredsController.del_creds_by_HostID(db_session, workspace_id, host_id)
        #Notes
        NotesController.del_Notes_by_HostID(db_session, host_id)
        #Vulns
        VulnsController.del_vulns_by_HostID(db_session, host_id)
        #Events
        db_session.query(Events).filter_by(host_id = host_id).delete()
        #Loots
        LootsController.del_loots_by_HostID(db_session, host_id)
        #Services
        ServicesController.del_Service_by_HostID(host_id)
        #Hosts
        db_session.query(Hosts).filter_by(id = host_id).delete()
        db_session.query(HostsTags).filter_by(host_id = host_id).delete()

        db_session.flush()
        db_session.commit()
        return {"status": 200, "message": ''}
    except Exception as e:
        log.error("Error in controllers `Hosts` function  `del_hosts`. Details - {0}".format(str(e)))
        return {"status": 500, "message": str(e)}


#Получить уникальные имена ОС
def getUnicIP(db_session: Session, args: dict) -> dict:
    try:
        select_statement = "SELECT distinct jsonb_build_object('id',hosts.id, 'address', hosts.address, 'purpose', hosts.purpose, 'os_family', hosts.os_family ) AS host  FROM hosts WHERE workspace_id = {0}  ORDER BY host ASC".format(str(int(args['workspace_id'])))
        result_set = db_session.execute(select_statement)
        return jsonify([dict(r) for r in result_set]), 200 
    except Exception as e:
        log.error("Error in controllers `HostsController` function  `getUnicIP`. Details - {0}".format(e.message))  
        return {"status": 500, "message": e.message}


#Получить уникальные имена ОС
def getNameOS(db_session: Session, args: dict) -> dict:
    dd = []
    select_statement = ''
    try:
        param = ''
        if(len(args) != 0):
            param = 'WHERE '
            index = 0
            for key, value in args.items():
                if(index != 0):
                    param += 'AND '
                if(key == 'os_family'):
                    param += "hosts.os_family = '{0}'".format(str(value))
                if(key == 'workspace'):
                    param += 'hosts.workspace_id = {0}'.format(str(int(value)))
                if(key == 'purpose'):
                    param += "hosts.purpose = '{0}'".format(str(value))
                if(key == 'cred_count'):
                    param += 'hosts.cred_count {0}'.format(str(value))
                if(key == 'vuln_count'):
                    param += 'hosts.vuln_count {0}'.format(str(value))
                if(key == 'service_count'):
                    param += 'hosts.service_count {0}'.format(str(value))
                if(key == 'service_count'):
                    param += 'hosts.service_count {0}'.format(str(value))
                index += 1
    
        select_statement = '''SELECT DISTINCT os_name FROM hosts {0} ORDER BY hosts.os_name'''.format(param)
        result_set = db_session.execute(select_statement)
        dd = [dict(r) for r in result_set]
        return {"status": 200, "data": dd}
    except Exception as e:
        log.error("Error in controllers `Hosts` function  `getNameOS`. Details - {0}".format(e.message))  
        return {"status": 500, "message": e.message}


#Количество hosts
def get_count(db_session: Session, workspace_id: int, arg) -> int:
    try:
        q = (
                db_session.query(
                func.count(distinct(Hosts.id)).label('hosts')
            )
            .outerjoin(HostsTags, HostsTags.host_id == Hosts.id)
            .outerjoin(Tags, Tags.id == HostsTags.tag_id)
            .outerjoin(Services, Services.host_id == Hosts.id)
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
            .outerjoin(Vulns, Vulns.host_id == Hosts.id)
            .outerjoin(VulnDetails, VulnDetails.vuln_id == Vulns.id)
            .outerjoin(VulnAttempts, VulnAttempts.vuln_id == Vulns.id)
            .outerjoin(VulnsRefs, VulnsRefs.vuln_id == Vulns.id)
            .outerjoin(Refs, Refs.id == VulnsRefs.ref_id)
            .filter(Hosts.workspace_id == workspace_id)
        )

        q = apply_dynamic_filters(q, arg)
        return len([dict(r) for r in q.all()]) 
    except Exception as e:
        log.error("Error in controllers `HostsController` function  `get_count`. Details - {0}".format(str(e)))
        return None
