import ipaddress
from sqlalchemy.orm import Session
import workspace.logger as logging

log = logging.getLogger()


#TreeView Subnets
def getTreeSubnets(db_session: Session, workspace_id: int ,node: dict):
    try:
        if(node['type'] != 'host'):

            if(node['purpose'] == 'hosts.subnets'):
                select_statement =  '''SELECT DISTINCT n1.label, ((row_number() over ())) as subnet_id, 'hosts.subnet' as purpose, true AS lazy, false AS ticked, 'directory' AS type 
                                            FROM hosts, (SELECT DISTINCT NETWORK(set_masklen(hosts.address, {0})) AS label FROM hosts WHERE hosts.workspace_id = {1}) n1 
                                            WHERE hosts.workspace_id = {1} GROUP BY n1.label ORDER BY subnet_id ASC'''.format(str(int(node['mask'])), str(int(workspace_id)))
            
            else:
                select_creds = '''(SELECT hosts.address AS address, COUNT(metasploit_credential_cores.id) AS creds FROM metasploit_credential_cores 
                                            LEFT OUTER JOIN metasploit_credential_publics ON  metasploit_credential_publics.id = metasploit_credential_cores.public_id 
                                            LEFT OUTER JOIN metasploit_credential_privates ON metasploit_credential_privates.id = metasploit_credential_cores.private_id
                                            LEFT OUTER JOIN metasploit_credential_realms  ON metasploit_credential_realms.id  = metasploit_credential_cores.realm_id 
                                            LEFT OUTER JOIN metasploit_credential_logins  ON metasploit_credential_logins.core_id  = metasploit_credential_cores.id 
                                            LEFT OUTER JOIN services ON services.id  = metasploit_credential_logins.service_id
                                            LEFT OUTER JOIN hosts  ON hosts.id  = services.host_id  
                                            WHERE metasploit_credential_cores.workspace_id  = {0} AND hosts.address << inet('{1}') GROUP BY hosts.address) n2'''.format(str(int(workspace_id)), str(ipaddress.ip_network(node['label'], strict=False)))
                select_vulns = '''(SELECT hosts.address, COUNT(vulns.id) AS vulns FROM vulns INNER JOIN hosts ON vulns.host_id = hosts.id 
                                            WHERE workspace_id = {0} AND address << inet('{1}') 
                                            GROUP BY hosts.address) n3'''.format(str(int(workspace_id)), str(ipaddress.ip_network(node['label'],strict=False)))
                select_statement = '''SELECT 'host' as type, hosts.address AS label,hosts.id as host_id, hosts.os_family, hosts.os_name, hosts.state, hosts.purpose, false AS ticked,hosts.virtual_host, n2.creds, n3.vulns FROM hosts 
                                            LEFT OUTER JOIN {0} ON n2.address = hosts.address 
                                            LEFT OUTER JOIN {1} ON n3.address = hosts.address 
                                            WHERE workspace_id = {2} AND hosts.address << inet('{3}') ORDER BY label'''.format(select_creds, select_vulns, str(int(workspace_id)), str(ipaddress.ip_network(node['label'], strict=False)))
        else:
            select_statement = '''SELECT address as label, id as host_id, state, purpose, false AS ticked,virtual_host FROM hosts 
                                            WHERE workspace_id = {0} AND address = inet('{1}') ORDER BY label'''.format(str(int(workspace_id)), str(ipaddress.ip_network(node['label'], strict=False)))
        
        result_set = db_session.execute(select_statement)
        return  {'status':200, 'data': [dict(r) for r in result_set]}
    except Exception as e:
        log.error("Error in controllers `TreeController` function  `getTreeSubnets`. Details - {0}".format(str(e)))
        return {"status": 500, "message": str(e) }


#TreeView Purpose
def getTreePurpose(db_session: Session, workspace_id: int ,node: dict):
    try:
        if(node['purpose'] == 'hosts.purposes'):
            select_statement =  '''SELECT DISTINCT n1.label, ((row_number() over ())) as purpose_id, 'directory' as type, true AS lazy, false AS ticked, 'hosts.purpose' AS purpose 
                                        FROM hosts, (SELECT DISTINCT purpose AS label FROM hosts WHERE hosts.workspace_id = {0}) n1 
                                        WHERE hosts.workspace_id = {0} GROUP BY n1.label ORDER BY purpose_id ASC'''.format(str(int(workspace_id)))
       
        else:
            select_creds = '''(SELECT hosts.address AS address, COUNT(metasploit_credential_cores.id) AS creds FROM metasploit_credential_cores 
                                        LEFT OUTER JOIN metasploit_credential_publics ON  metasploit_credential_publics.id = metasploit_credential_cores.public_id 
                                        LEFT OUTER JOIN metasploit_credential_privates ON metasploit_credential_privates.id = metasploit_credential_cores.private_id
                                        LEFT OUTER JOIN metasploit_credential_realms  ON metasploit_credential_realms.id  = metasploit_credential_cores.realm_id 
                                        LEFT OUTER JOIN metasploit_credential_logins  ON metasploit_credential_logins.core_id  = metasploit_credential_cores.id 
                                        LEFT OUTER JOIN services ON services.id  = metasploit_credential_logins.service_id
                                        LEFT OUTER JOIN hosts  ON hosts.id  = services.host_id  
                                        WHERE metasploit_credential_cores.workspace_id  = {0} AND hosts.purpose = '{1}' GROUP BY hosts.address) n2'''.format(str(int(workspace_id)), str(node['label']))
            select_vulns = '''(SELECT hosts.address, COUNT(vulns.id) AS vulns FROM vulns INNER JOIN hosts ON vulns.host_id = hosts.id 
                                        WHERE workspace_id = {0} AND hosts.purpose = '{1}' 
                                        GROUP BY hosts.address) n3'''.format(str(int(workspace_id)), str(node['label']))
            select_statement = '''SELECT 'host' as type, hosts.address AS label,hosts.id as host_id, hosts.os_family, hosts.os_name, hosts.state, hosts.purpose, false AS ticked,hosts.virtual_host, n2.creds, n3.vulns FROM hosts 
                                        LEFT OUTER JOIN {0} ON n2.address = hosts.address 
                                        LEFT OUTER JOIN {1} ON n3.address = hosts.address 
                                        WHERE workspace_id = {2} AND hosts.purpose = '{3}' ORDER BY label'''.format(select_creds, select_vulns, str(int(workspace_id)), str(node['label']))

        result_set = db_session.execute(select_statement)
        return  {'status':200, 'data': [dict(r) for r in result_set]}
    except Exception as e:
        log.error("Error in controllers `TreeController` function  `getTreePurpose`. Details - {0}".format(str(e)))
        return {"status": 500, "message": str(e) }


#TreeView OS
def getTreeOS(db_session: Session, workspace_id: int, node: dict):
    try:
        if(node['purpose'] == 'hosts.os'):
            select_statement =  '''SELECT DISTINCT n1.label AS label, n1.label AS value, 'directory' AS type, true AS lazy, false AS ticked, 'hosts.os_family' AS purpose 
                                        FROM hosts, (SELECT DISTINCT os_family AS label FROM hosts WHERE hosts.workspace_id = {0}) n1 
                                        WHERE hosts.workspace_id = {0} GROUP BY n1.label '''.format(str(int(workspace_id)))
        
        if(node['purpose'] == 'hosts.os_family'):
            select_statement =  '''SELECT DISTINCT n1.label AS label, n1.label AS value, 'directory' AS type, true AS lazy, false AS ticked, '{1}' AS os_family, 'hosts.os_name' AS purpose 
                                        FROM hosts, (SELECT DISTINCT os_name AS label FROM hosts WHERE hosts.workspace_id = {0} AND os_family = '{1}') n1 
                                        WHERE hosts.workspace_id = {0} GROUP BY n1.label '''.format(str(int(workspace_id)), str(node['value']))
            
        if(node['purpose'] == 'hosts.os_name'):
            select_creds = '''(SELECT hosts.address AS address, COUNT(metasploit_credential_cores.id) AS creds FROM metasploit_credential_cores 
                                        LEFT OUTER JOIN metasploit_credential_publics ON  metasploit_credential_publics.id = metasploit_credential_cores.public_id 
                                        LEFT OUTER JOIN metasploit_credential_privates ON metasploit_credential_privates.id = metasploit_credential_cores.private_id
                                        LEFT OUTER JOIN metasploit_credential_realms  ON metasploit_credential_realms.id  = metasploit_credential_cores.realm_id 
                                        LEFT OUTER JOIN metasploit_credential_logins  ON metasploit_credential_logins.core_id  = metasploit_credential_cores.id 
                                        LEFT OUTER JOIN services ON services.id  = metasploit_credential_logins.service_id
                                        LEFT OUTER JOIN hosts  ON hosts.id  = services.host_id  
                                        WHERE metasploit_credential_cores.workspace_id  = {0} AND hosts.os_name = '{1}' GROUP BY hosts.address) n2'''.format(str(int(workspace_id)), str(node['value']))
            select_vulns = '''(SELECT hosts.address, COUNT(vulns.id) AS vulns FROM vulns INNER JOIN hosts ON vulns.host_id = hosts.id 
                                        WHERE workspace_id = {0} AND hosts.os_name = '{1}' 
                                        GROUP BY hosts.address) n3'''.format(str(int(workspace_id)), str(node['value']))
            select_statement = '''SELECT 'host' as type, hosts.address AS label,hosts.id as host_id, hosts.os_family, hosts.os_name, hosts.state, hosts.purpose, false AS ticked,hosts.virtual_host, n2.creds, n3.vulns FROM hosts 
                                        LEFT OUTER JOIN {0} ON n2.address = hosts.address 
                                        LEFT OUTER JOIN {1} ON n3.address = hosts.address 
                                        WHERE workspace_id = {2} AND hosts.os_name = '{3}' ORDER BY label'''.format(select_creds, select_vulns, str(int(workspace_id)), str(node['value']))

        result_set = db_session.execute(select_statement)
        return  {'status':200, 'data': [dict(r) for r in result_set]}
    except Exception as e:
        log.error("Error in controllers `TreeController` function  `getTreeOS`. Details - {0}".format(str(e)))
        return {"status": 500, "message": str(e) }

 
#TreeView Tags
def getTreeTags(db_session: Session, workspace_id: int, node: dict):
    try:
        if(node['purpose'] == 'hosts.tags'):
            select_statement = '''SELECT  tags.id AS tag_id, 'directory' as type, 'hosts.tag' as purpose, tags.name AS label, true AS lazy, false AS ticked, tags.desc AS description FROM tags 
                                    INNER JOIN hosts_tags ON tags.id = hosts_tags.tag_id
                                    INNER JOIN hosts ON hosts_tags.host_id = hosts.id 
                                    WHERE hosts.workspace_id = {0} 
                                    GROUP BY tags.id
                                    ORDER  BY tags.name ASC'''.format(str(int(workspace_id)))
        
        if(node['purpose'] == 'hosts.tag'):
            select_creds = '''(SELECT hosts.address AS address, COUNT(metasploit_credential_cores.id) AS creds FROM metasploit_credential_cores 
                                    LEFT OUTER JOIN metasploit_credential_publics ON  metasploit_credential_publics.id = metasploit_credential_cores.public_id 
                                    LEFT OUTER JOIN metasploit_credential_privates ON metasploit_credential_privates.id = metasploit_credential_cores.private_id
                                    LEFT OUTER JOIN metasploit_credential_realms  ON metasploit_credential_realms.id  = metasploit_credential_cores.realm_id 
                                    LEFT OUTER JOIN metasploit_credential_logins  ON metasploit_credential_logins.core_id  = metasploit_credential_cores.id 
                                    LEFT OUTER JOIN services ON services.id  = metasploit_credential_logins.service_id
                                    LEFT OUTER JOIN hosts ON hosts.id  = services.host_id 
                                    LEFT OUTER JOIN hosts_tags ON hosts.id = hosts_tags.host_id
                                    LEFT OUTER JOIN tags ON hosts_tags.tag_id = tags.id  
                                WHERE metasploit_credential_cores.workspace_id  = {0} AND tags.id = {1} GROUP BY hosts.address) n2'''.format(str(int(workspace_id)), int(node['tag_id']))
            select_vulns = '''(SELECT hosts.address, COUNT(vulns.id) AS vulns FROM vulns 
                                    INNER JOIN hosts ON vulns.host_id = hosts.id 
                                    INNER JOIN hosts_tags ON hosts.id = hosts_tags.host_id
                                    INNER JOIN tags ON hosts_tags.tag_id = tags.id  
                                    WHERE workspace_id = {0} AND tags.id = {1} GROUP BY hosts.address) n3'''.format(str(int(workspace_id)), int(node['tag_id']))
            select_statement = '''SELECT 'host' as type, hosts.address AS label, (hosts.id) AS host_id, hosts.id AS host_id, hosts.os_family, hosts.os_name, hosts.state, hosts.purpose, false AS ticked,hosts.virtual_host, n2.creds, n3.vulns FROM hosts 
                                    LEFT OUTER JOIN {0} ON n2.address = hosts.address 
                                    LEFT OUTER JOIN {1} ON n3.address = hosts.address 
                                    LEFT OUTER JOIN hosts_tags ON hosts.id = hosts_tags.host_id
                                    LEFT OUTER JOIN tags ON hosts_tags.tag_id = tags.id  
                                    WHERE workspace_id = {2} AND tags.id = {3} ORDER BY label'''.format(select_creds, select_vulns, str(int(workspace_id)), int(node['tag_id']))

        result_set = db_session.execute(select_statement)
        return  {'status':200, 'data': [dict(r) for r in result_set]}
    except Exception as e:
        log.error("Error in controllers `TreeController` function  `getTreeTags`. Details - {0}".format(str(e)))
        return {"status": 500, "message": str(e) }


#Получить список хостов по подсетям для дерева TreeView
def getTreeServices(db_session: Session, workspace_id: int ,node: dict):
    dd = []
    try:
        if(node['type'] != 'host'):
            
            if(node['purpose'] == 'services.ports'):
                select_statement =  '''SELECT  DISTINCT  CONCAT (services.port::text, '/(',services.proto,')') AS label, services.port, services.proto, 'directory' AS type, true AS lazy, false AS ticked, 'services.port' AS purpose FROM services 
                                            INNER JOIN hosts ON hosts.id = services.host_id 
                                            WHERE hosts.workspace_id = {0}
                                            ORDER BY services.port'''.format(str(int(workspace_id)))
            
            if(node['purpose'] == 'services.names'):    
                select_statement = '''SELECT DISTINCT services."name" as label, 'directory' AS type, true AS lazy, false AS ticked, 'services.name' AS purpose FROM services 
                                            INNER JOIN hosts ON hosts.id = services.host_id 
                                            WHERE hosts.workspace_id = {0} ORDER BY label'''.format(str(int(workspace_id)))
            
            if(node['purpose'] == 'services.name'):    
                select_creds = '''(SELECT hosts.address AS address, COUNT(metasploit_credential_cores.id) AS creds FROM metasploit_credential_cores 
                                        LEFT OUTER JOIN metasploit_credential_publics ON  metasploit_credential_publics.id = metasploit_credential_cores.public_id 
                                        LEFT OUTER JOIN metasploit_credential_privates ON metasploit_credential_privates.id = metasploit_credential_cores.private_id
                                        LEFT OUTER JOIN metasploit_credential_realms  ON metasploit_credential_realms.id  = metasploit_credential_cores.realm_id 
                                        LEFT OUTER JOIN metasploit_credential_logins  ON metasploit_credential_logins.core_id  = metasploit_credential_cores.id 
                                        LEFT OUTER JOIN services ON services.id  = metasploit_credential_logins.service_id
                                        LEFT OUTER JOIN hosts  ON hosts.id  = services.host_id  
                                        WHERE metasploit_credential_cores.workspace_id  = {0} AND services.name = '{1}' GROUP BY hosts.address) n2'''.format(str(int(workspace_id)), str(node['label']))
                select_vulns = '''(SELECT hosts.address, COUNT(vulns.id) AS vulns FROM vulns INNER JOIN hosts ON vulns.host_id = hosts.id 
                                        LEFT OUTER JOIN services ON services.host_id  = hosts.id
                                        WHERE workspace_id = {0} AND services.name = '{1}'
                                        GROUP BY hosts.address) n3'''.format(str(int(workspace_id)), str(node['label']))
                select_statement = '''SELECT DISTINCT hosts.address AS label,'host' as type, hosts.id as host_id, hosts.os_family, hosts.os_name, hosts.state, hosts.purpose, false AS ticked,hosts.virtual_host, n2.creds, n3.vulns FROM hosts 
                                        LEFT OUTER JOIN {0} ON n2.address = hosts.address 
                                        LEFT OUTER JOIN {1} ON n3.address = hosts.address 
                                        INNER JOIN services ON services.host_id  = hosts.id
                                        WHERE workspace_id = {2} AND services.name = '{3}' ORDER BY label'''.format(select_creds, select_vulns, str(int(workspace_id)), str(node['label']))
            
            if(node['purpose'] == 'services.port'):    
                select_creds = '''(SELECT hosts.address AS address, COUNT(metasploit_credential_cores.id) AS creds FROM metasploit_credential_cores 
                                        LEFT OUTER JOIN metasploit_credential_publics ON  metasploit_credential_publics.id = metasploit_credential_cores.public_id 
                                        LEFT OUTER JOIN metasploit_credential_privates ON metasploit_credential_privates.id = metasploit_credential_cores.private_id
                                        LEFT OUTER JOIN metasploit_credential_realms  ON metasploit_credential_realms.id  = metasploit_credential_cores.realm_id 
                                        LEFT OUTER JOIN metasploit_credential_logins  ON metasploit_credential_logins.core_id  = metasploit_credential_cores.id 
                                        LEFT OUTER JOIN services ON services.id  = metasploit_credential_logins.service_id
                                        LEFT OUTER JOIN hosts  ON hosts.id  = services.host_id  
                                        WHERE metasploit_credential_cores.workspace_id  = {0} AND services.port = {1} AND services.proto = '{2}' GROUP BY hosts.address) n2'''.format(str(int(workspace_id)), str(int(node['port'])), str(node['proto']))
                select_vulns = '''(SELECT hosts.address, COUNT(vulns.id) AS vulns FROM vulns INNER JOIN hosts ON vulns.host_id = hosts.id 
                                        LEFT OUTER JOIN services ON services.host_id  = hosts.id
                                        WHERE workspace_id = {0} AND services.port = {1} AND services.proto = '{2}'
                                        GROUP BY hosts.address) n3'''.format(str(int(workspace_id)), str(int(node['port'])), str(node['proto']))
                select_statement = '''SELECT DISTINCT hosts.address AS label,'host' as type, hosts.id as host_id, hosts.os_family, hosts.os_name, hosts.state, hosts.purpose, false AS ticked,hosts.virtual_host, n2.creds, n3.vulns FROM hosts 
                                        LEFT OUTER JOIN {0} ON n2.address = hosts.address 
                                        LEFT OUTER JOIN {1} ON n3.address = hosts.address 
                                        INNER JOIN services ON services.host_id  = hosts.id
                                        WHERE workspace_id = {2} AND services.port = {3} AND services.proto = '{4}' ORDER BY label'''.format(select_creds, select_vulns, str(int(workspace_id)), str(int(node['port'])), str(node['proto']))
        
        else:
            select_statement = '''SELECT address as label, id as host_id, state, purpose, false AS ticked,virtual_host FROM hosts 
                                        WHERE workspace_id = {0} AND address = inet('{1}') ORDER BY label'''.format(str(int(workspace_id)), str(ipaddress.ip_network(node['label'], strict=False)))
        
        result_set = db_session.execute(select_statement)
        return  {'status':200, 'data': [dict(r) for r in result_set]}
    except Exception as e:
        log.error("Error in controllers `TreeController` function  `getTreeServices`. Details - {0}".format(str(e)))
        return {"status": 500, "message": str(e) }
    

#Получить список хостов по подсетям для дерева TreeView
def getTreeNotes(db_session: Session, workspace_id: int ,node: dict):
    dd = []
    try:
        if(node['type'] != 'host'):
            
            if(node['purpose'] == 'notes.ntypes'):
                select_statement =  '''SELECT DISTINCT notes.ntype AS label, 'directory' AS type, true AS lazy, false AS ticked, 'notes.ntype' AS purpose FROM notes 
                                            WHERE notes.workspace_id = {0}
                                            ORDER BY notes.ntype'''.format(str(int(workspace_id)))           
            
            if(node['purpose'] == 'notes.ntype'):    
                select_creds = '''(SELECT hosts.address AS address, COUNT(metasploit_credential_cores.id) AS creds FROM metasploit_credential_cores 
                                        LEFT OUTER JOIN metasploit_credential_publics ON  metasploit_credential_publics.id = metasploit_credential_cores.public_id 
                                        LEFT OUTER JOIN metasploit_credential_privates ON metasploit_credential_privates.id = metasploit_credential_cores.private_id
                                        LEFT OUTER JOIN metasploit_credential_realms  ON metasploit_credential_realms.id  = metasploit_credential_cores.realm_id 
                                        LEFT OUTER JOIN metasploit_credential_logins  ON metasploit_credential_logins.core_id  = metasploit_credential_cores.id 
                                        LEFT OUTER JOIN services ON services.id  = metasploit_credential_logins.service_id
                                        LEFT OUTER JOIN hosts  ON hosts.id  = services.host_id  
                                        WHERE metasploit_credential_cores.workspace_id  = {0} AND services.name = '{1}' GROUP BY hosts.address) n2'''.format(str(int(workspace_id)), str(node['label']))
                select_vulns = '''(SELECT hosts.address, COUNT(vulns.id) AS vulns FROM vulns INNER JOIN hosts ON vulns.host_id = hosts.id 
                                        LEFT OUTER JOIN services ON services.host_id  = hosts.id
                                        WHERE workspace_id = {0} AND services.name = '{1}'
                                        GROUP BY hosts.address) n3'''.format(str(int(workspace_id)), str(node['label']))
                select_statement = '''SELECT DISTINCT hosts.address AS label,'host' as type, hosts.id as host_id, hosts.os_family, hosts.os_name, hosts.state, hosts.purpose, false AS ticked,hosts.virtual_host, n2.creds, n3.vulns FROM hosts 
                                        LEFT OUTER JOIN {0} ON n2.address = hosts.address 
                                        LEFT OUTER JOIN {1} ON n3.address = hosts.address 
                                        INNER JOIN notes ON notes.host_id  = hosts.id
                                        WHERE notes.workspace_id = {2} AND notes.ntype = '{3}' ORDER BY label'''.format(select_creds, select_vulns, str(int(workspace_id)), str(node['label']))       
        else:
            select_statement = '''SELECT address as label, id as host_id, state, purpose, false AS ticked,virtual_host FROM hosts 
                                        WHERE workspace_id = {0} AND address = inet('{1}') ORDER BY label'''.format(str(int(workspace_id)), str(ipaddress.ip_network(node['label'], strict=False)))
        
        result_set = db_session.execute(select_statement)
        return  {'status':200, 'data': [dict(r) for r in result_set]}
    except Exception as e:
        log.error("Error in controllers `TreeController` function  `getTreeNotes`. Details - {0}".format(str(e)))
        return {"status": 500, "message": str(e) }
    

#Получить список хостов по подсетям для дерева TreeView
def getTreeLoots(db_session: Session, workspace_id: int ,node: dict):
    dd = []
    try:
        if(node['type'] != 'host'):
            
            if(node['purpose'] == 'loots.ltypes'):
                select_statement =  '''SELECT DISTINCT loots.ltype AS label, 'directory' AS type, true AS lazy, false AS ticked, 'loots.ltype' AS purpose FROM loots 
                                            WHERE loots.workspace_id = {0}
                                            ORDER BY loots.ltype'''.format(str(int(workspace_id)))           
            
            if(node['purpose'] == 'loots.ltype'):    
                select_creds = '''(SELECT hosts.address AS address, COUNT(metasploit_credential_cores.id) AS creds FROM metasploit_credential_cores 
                                        LEFT OUTER JOIN metasploit_credential_publics ON  metasploit_credential_publics.id = metasploit_credential_cores.public_id 
                                        LEFT OUTER JOIN metasploit_credential_privates ON metasploit_credential_privates.id = metasploit_credential_cores.private_id
                                        LEFT OUTER JOIN metasploit_credential_realms  ON metasploit_credential_realms.id  = metasploit_credential_cores.realm_id 
                                        LEFT OUTER JOIN metasploit_credential_logins  ON metasploit_credential_logins.core_id  = metasploit_credential_cores.id 
                                        LEFT OUTER JOIN services ON services.id  = metasploit_credential_logins.service_id
                                        LEFT OUTER JOIN hosts  ON hosts.id  = services.host_id  
                                        WHERE metasploit_credential_cores.workspace_id  = {0} AND services.name = '{1}' GROUP BY hosts.address) n2'''.format(str(int(workspace_id)), str(node['label']))
                select_vulns = '''(SELECT hosts.address, COUNT(vulns.id) AS vulns FROM vulns INNER JOIN hosts ON vulns.host_id = hosts.id 
                                        LEFT OUTER JOIN services ON services.host_id  = hosts.id
                                        WHERE workspace_id = {0} AND services.name = '{1}'
                                        GROUP BY hosts.address) n3'''.format(str(int(workspace_id)), str(node['label']))
                select_statement = '''SELECT DISTINCT hosts.address AS label,'host' as type, hosts.id as host_id, hosts.os_family, hosts.os_name, hosts.state, hosts.purpose, false AS ticked,hosts.virtual_host, n2.creds, n3.vulns FROM hosts 
                                        LEFT OUTER JOIN {0} ON n2.address = hosts.address 
                                        LEFT OUTER JOIN {1} ON n3.address = hosts.address 
                                        INNER JOIN loots ON loots.host_id  = hosts.id
                                        WHERE loots.workspace_id = {2} AND loots.ltype = '{3}' ORDER BY label'''.format(select_creds, select_vulns, str(int(workspace_id)), str(node['label']))       
        else:
            select_statement = '''SELECT address as label, id as host_id, state, purpose, false AS ticked,virtual_host FROM hosts 
                                        WHERE workspace_id = {0} AND address = inet('{1}') ORDER BY label'''.format(str(int(workspace_id)), str(ipaddress.ip_network(node['label'], strict=False)))
        
        result_set = db_session.execute(select_statement)
        return  {'status':200, 'data': [dict(r) for r in result_set]}
    except Exception as e:
        log.error("Error in controllers `TreeController` function  `getTreeLoots`. Details - {0}".format(str(e)))
        return {"status": 500, "message": str(e) }
    

#Получить список хостов по подсетям для дерева TreeView
def getTreeVulnsName(db_session: Session, workspace_id: int ,node: dict):
    dd = []
    try:
        if(node['type'] != 'host'):
            
            if(node['purpose'] == 'vulns.names'):
                select_statement =  '''SELECT DISTINCT vulns.name AS label, 'directory' AS type, true AS lazy, false AS ticked, 'vulns.name' AS purpose FROM vulns
                                            INNER JOIN hosts ON  hosts.id = vulns.host_id
                                            WHERE hosts.workspace_id = {0}
                                            ORDER BY  vulns.name'''.format(str(int(workspace_id)))           
            
            if(node['purpose'] == 'vulns.name'):    
                select_creds = '''(SELECT hosts.address AS address, COUNT(metasploit_credential_cores.id) AS creds FROM metasploit_credential_cores 
                                        LEFT OUTER JOIN metasploit_credential_publics ON  metasploit_credential_publics.id = metasploit_credential_cores.public_id 
                                        LEFT OUTER JOIN metasploit_credential_privates ON metasploit_credential_privates.id = metasploit_credential_cores.private_id
                                        LEFT OUTER JOIN metasploit_credential_realms  ON metasploit_credential_realms.id  = metasploit_credential_cores.realm_id 
                                        LEFT OUTER JOIN metasploit_credential_logins  ON metasploit_credential_logins.core_id  = metasploit_credential_cores.id 
                                        LEFT OUTER JOIN services ON services.id  = metasploit_credential_logins.service_id
                                        LEFT OUTER JOIN hosts  ON hosts.id  = services.host_id  
                                        WHERE metasploit_credential_cores.workspace_id  = {0} AND services.name = '{1}' GROUP BY hosts.address) n2'''.format(str(int(workspace_id)), str(node['label']))
                select_vulns = '''(SELECT hosts.address, COUNT(vulns.id) AS vulns FROM vulns INNER JOIN hosts ON vulns.host_id = hosts.id 
                                        LEFT OUTER JOIN services ON services.host_id  = hosts.id
                                        WHERE workspace_id = {0} AND services.name = '{1}'
                                        GROUP BY hosts.address) n3'''.format(str(int(workspace_id)), str(node['label']))
                select_statement = '''SELECT DISTINCT hosts.address AS label,'host' as type, hosts.id as host_id, hosts.os_family, hosts.os_name, hosts.state, hosts.purpose, false AS ticked,hosts.virtual_host, n2.creds, n3.vulns FROM hosts 
                                        LEFT OUTER JOIN {0} ON n2.address = hosts.address 
                                        LEFT OUTER JOIN {1} ON n3.address = hosts.address 
                                        INNER JOIN vulns ON vulns.host_id  = hosts.id
                                        WHERE hosts.workspace_id = {2} AND vulns.name = '{3}' ORDER BY label'''.format(select_creds, select_vulns, str(int(workspace_id)), str(node['label']))       
        
        result_set = db_session.execute(select_statement)
        return  {'status':200, 'data': [dict(r) for r in result_set]}
    except Exception as e:
        log.error("Error in controllers `TreeController` function  `getTreeVulnsName`. Details - {0}".format(str(e)))
        return {"status": 500, "message": str(e) }
    

#Получить список хостов по подсетям для дерева TreeView
def getTreeVulnsExploited(db_session: Session, workspace_id: int ,node: dict):
    dd = []
    try:                             
        if(node['purpose'] == 'vulns.exploited'):    
            select_creds = '''(SELECT hosts.address AS address, COUNT(metasploit_credential_cores.id) AS creds FROM metasploit_credential_cores 
                                    LEFT OUTER JOIN metasploit_credential_publics ON  metasploit_credential_publics.id = metasploit_credential_cores.public_id 
                                    LEFT OUTER JOIN metasploit_credential_privates ON metasploit_credential_privates.id = metasploit_credential_cores.private_id
                                    LEFT OUTER JOIN metasploit_credential_realms  ON metasploit_credential_realms.id  = metasploit_credential_cores.realm_id 
                                    LEFT OUTER JOIN metasploit_credential_logins  ON metasploit_credential_logins.core_id  = metasploit_credential_cores.id 
                                    LEFT OUTER JOIN services ON services.id  = metasploit_credential_logins.service_id
                                    LEFT OUTER JOIN hosts  ON hosts.id  = services.host_id  
                                    WHERE metasploit_credential_cores.workspace_id  = {0} AND services.name = '{1}' GROUP BY hosts.address) n2'''.format(str(int(workspace_id)), str(node['label']))
            select_vulns = '''(SELECT hosts.address, COUNT(vulns.id) AS vulns FROM vulns INNER JOIN hosts ON vulns.host_id = hosts.id 
                                    LEFT OUTER JOIN services ON services.host_id  = hosts.id
                                    WHERE workspace_id = {0}
                                    GROUP BY hosts.address) n3'''.format(str(int(workspace_id)))
            select_statement = '''SELECT DISTINCT hosts.address AS label,'host' as type, hosts.id as host_id, hosts.os_family, hosts.os_name, hosts.state, hosts.purpose, false AS ticked, hosts.virtual_host, n2.creds, n3.vulns FROM hosts 
                                    LEFT OUTER JOIN {0} ON n2.address = hosts.address 
                                    LEFT OUTER JOIN {1} ON n3.address = hosts.address 
                                    INNER JOIN vulns ON vulns.host_id  = hosts.id
                                    INNER JOIN vuln_attempts ON vuln_attempts.vuln_id = vulns.id
                                    WHERE hosts.workspace_id = {2} AND vuln_attempts.exploited = True ORDER BY label'''.format(select_creds, select_vulns, str(int(workspace_id)), str(node['label']))       
        
        result_set = db_session.execute(select_statement)
        return  {'status':200, 'data': [dict(r) for r in result_set]}
    except Exception as e:
        log.error("Error in controllers `TreeController` function  `getTreeVulnsExploited`. Details - {0}".format(str(e)))
        return {"status": 500, "message": str(e) }
    

#Получить список хостов по подсетям для дерева TreeView
def getTreeVulnsRefs(db_session: Session, workspace_id: int ,node: dict):
    dd = []
    try:                             
        if(node['purpose'] == 'vulns.refs'):
            select_statement =  '''SELECT DISTINCT refs.name AS label, 'directory' AS type, true AS lazy, false AS ticked, 'vulns.ref' AS purpose FROM vulns
                                        INNER JOIN vulns_refs ON  vulns_refs.vuln_id = vulns.id
                                        INNER JOIN refs ON  refs.id = vulns_refs.ref_id
                                        INNER JOIN hosts ON  hosts.id = vulns.host_id
                                        WHERE hosts.workspace_id = {0}
                                        ORDER BY refs.name'''.format(str(int(workspace_id)))  
        
        if(node['purpose'] == 'vulns.ref'):    
            select_creds = '''(SELECT hosts.address AS address, COUNT(metasploit_credential_cores.id) AS creds FROM metasploit_credential_cores 
                                    LEFT OUTER JOIN metasploit_credential_publics ON  metasploit_credential_publics.id = metasploit_credential_cores.public_id 
                                    LEFT OUTER JOIN metasploit_credential_privates ON metasploit_credential_privates.id = metasploit_credential_cores.private_id
                                    LEFT OUTER JOIN metasploit_credential_realms  ON metasploit_credential_realms.id  = metasploit_credential_cores.realm_id 
                                    LEFT OUTER JOIN metasploit_credential_logins  ON metasploit_credential_logins.core_id  = metasploit_credential_cores.id 
                                    LEFT OUTER JOIN services ON services.id  = metasploit_credential_logins.service_id
                                    LEFT OUTER JOIN hosts  ON hosts.id  = services.host_id  
                                    WHERE metasploit_credential_cores.workspace_id  = {0} AND services.name = '{1}' GROUP BY hosts.address) n2'''.format(str(int(workspace_id)), str(node['label']))
            select_vulns = '''(SELECT hosts.address, COUNT(vulns.id) AS vulns FROM vulns INNER JOIN hosts ON vulns.host_id = hosts.id 
                                    LEFT OUTER JOIN services ON services.host_id  = hosts.id
                                    WHERE workspace_id = {0}
                                    GROUP BY hosts.address) n3'''.format(str(int(workspace_id)))
            select_statement = '''SELECT DISTINCT hosts.address AS label,'host' as type, hosts.id as host_id, hosts.os_family, hosts.os_name, hosts.state, hosts.purpose, false AS ticked, hosts.virtual_host, n2.creds, n3.vulns FROM hosts 
                                    LEFT OUTER JOIN {0} ON n2.address = hosts.address 
                                    LEFT OUTER JOIN {1} ON n3.address = hosts.address 
                                    INNER JOIN vulns ON vulns.host_id  = hosts.id
                                    INNER JOIN vulns_refs ON  vulns_refs.vuln_id = vulns.id
                                    INNER JOIN refs ON  refs.id = vulns_refs.ref_id
                                    WHERE hosts.workspace_id = {2} AND refs.name = '{3}' ORDER BY label'''.format(select_creds, select_vulns, str(int(workspace_id)), str(node['label']))       
        
        result_set = db_session.execute(select_statement)
        return  {'status':200, 'data': [dict(r) for r in result_set]}
    except Exception as e:
        log.error("Error in controllers `TreeController` function  `getTreeVulnsRefs`. Details - {0}".format(str(e)))
        return {"status": 500, "message": str(e) }
    

#Получить список хостов по подсетям для дерева TreeView
def getTreeCredsUsernames(db_session: Session, workspace_id: int ,node: dict):
    dd = []
    try:                             
        if(node['purpose'] == 'creds.usernames'):
            select_statement =  '''SELECT DISTINCT metasploit_credential_publics.username AS label, 'directory' AS type, true AS lazy, false AS ticked, 'creds.username' AS purpose FROM metasploit_credential_publics
                                        INNER JOIN metasploit_credential_cores ON metasploit_credential_cores.public_id = metasploit_credential_publics.id
                                        WHERE metasploit_credential_cores.workspace_id = {0}
                                        ORDER BY  metasploit_credential_publics.username'''.format(str(int(workspace_id)))  
        
        if(node['purpose'] == 'creds.username'):    
            select_creds = '''(SELECT hosts.address AS address, metasploit_credential_publics.username AS username, COUNT(metasploit_credential_cores.id) AS creds FROM metasploit_credential_cores 
                                    LEFT OUTER JOIN metasploit_credential_publics ON  metasploit_credential_publics.id = metasploit_credential_cores.public_id 
                                    LEFT OUTER JOIN metasploit_credential_privates ON metasploit_credential_privates.id = metasploit_credential_cores.private_id
                                    LEFT OUTER JOIN metasploit_credential_realms  ON metasploit_credential_realms.id  = metasploit_credential_cores.realm_id 
                                    LEFT OUTER JOIN metasploit_credential_logins  ON metasploit_credential_logins.core_id  = metasploit_credential_cores.id 
                                    LEFT OUTER JOIN services ON services.id  = metasploit_credential_logins.service_id
                                    LEFT OUTER JOIN hosts  ON hosts.id  = services.host_id  
                                    WHERE metasploit_credential_cores.workspace_id  = {0} GROUP BY hosts.address, metasploit_credential_publics.username) n2'''.format(str(int(workspace_id)), str(node['label']))
            select_vulns = '''(SELECT hosts.address, COUNT(vulns.id) AS vulns FROM vulns INNER JOIN hosts ON vulns.host_id = hosts.id 
                                    LEFT OUTER JOIN services ON services.host_id  = hosts.id
                                    WHERE workspace_id = {0}
                                    GROUP BY hosts.address) n3'''.format(str(int(workspace_id)))
            select_statement = '''SELECT DISTINCT hosts.address AS label,'host' as type, hosts.id as host_id, hosts.os_family, hosts.os_name, hosts.state, hosts.purpose, false AS ticked, hosts.virtual_host, n2.creds, n3.vulns FROM hosts 
                                    INNER JOIN {0} ON n2.address = hosts.address 
                                    LEFT OUTER JOIN {1} ON n3.address = hosts.address 
                                    WHERE hosts.workspace_id = {2} AND n2.username = '{3}' ORDER BY label'''.format(select_creds, select_vulns, str(int(workspace_id)), str(node['label']))       
        
        result_set = db_session.execute(select_statement)
        return  {'status':200, 'data': [dict(r) for r in result_set]}
    except Exception as e:
        log.error("Error in controllers `TreeController` function  `getTreeCredsUsernames`. Details - {0}".format(str(e)))
        return {"status": 500, "message": str(e) }
    

#Получить список хостов по подсетям для дерева TreeView
def getTreeCredsPasswords(db_session: Session, workspace_id: int ,node: dict):
    dd = []
    try:                             
        if(node['purpose'] == 'creds.passwords'):
            select_statement =  '''SELECT DISTINCT metasploit_credential_privates.data AS label, 'directory' AS type, true AS lazy, false AS ticked, 'creds.password' AS purpose FROM metasploit_credential_privates
                                        INNER JOIN metasploit_credential_cores ON metasploit_credential_cores.private_id = metasploit_credential_privates.id
                                        WHERE metasploit_credential_cores.workspace_id = {0} AND metasploit_credential_privates.type = 'Metasploit::Credential::Password'
                                        ORDER BY metasploit_credential_privates.data'''.format(str(int(workspace_id)))  
        
        if(node['purpose'] == 'creds.password'):    
            select_creds = '''(SELECT hosts.address AS address, metasploit_credential_privates.data AS password, COUNT(metasploit_credential_cores.id) AS creds FROM metasploit_credential_cores 
                                    LEFT OUTER JOIN metasploit_credential_publics ON  metasploit_credential_publics.id = metasploit_credential_cores.public_id 
                                    LEFT OUTER JOIN metasploit_credential_privates ON metasploit_credential_privates.id = metasploit_credential_cores.private_id
                                    LEFT OUTER JOIN metasploit_credential_realms  ON metasploit_credential_realms.id  = metasploit_credential_cores.realm_id 
                                    LEFT OUTER JOIN metasploit_credential_logins  ON metasploit_credential_logins.core_id  = metasploit_credential_cores.id 
                                    LEFT OUTER JOIN services ON services.id  = metasploit_credential_logins.service_id
                                    LEFT OUTER JOIN hosts  ON hosts.id  = services.host_id  
                                    WHERE metasploit_credential_cores.workspace_id  = {0} AND metasploit_credential_privates.type = 'Metasploit::Credential::Password' 
                                    GROUP BY hosts.address, metasploit_credential_privates.data) n2'''.format(str(int(workspace_id)), str(node['label']))
            select_vulns = '''(SELECT hosts.address, COUNT(vulns.id) AS vulns FROM vulns INNER JOIN hosts ON vulns.host_id = hosts.id 
                                    LEFT OUTER JOIN services ON services.host_id  = hosts.id
                                    WHERE workspace_id = {0}
                                    GROUP BY hosts.address) n3'''.format(str(int(workspace_id)))
            select_statement = '''SELECT DISTINCT hosts.address AS label,'host' as type, hosts.id as host_id, hosts.os_family, hosts.os_name, hosts.state, hosts.purpose, false AS ticked, hosts.virtual_host, n2.creds, n3.vulns FROM hosts 
                                    INNER JOIN {0} ON n2.address = hosts.address 
                                    LEFT OUTER JOIN {1} ON n3.address = hosts.address 
                                    WHERE hosts.workspace_id = {2} AND n2.password = '{3}' ORDER BY label'''.format(select_creds, select_vulns, str(int(workspace_id)), str(node['label']))       
        
        result_set = db_session.execute(select_statement)
        return  {'status':200, 'data': [dict(r) for r in result_set]}
    except Exception as e:
        log.error("Error in controllers `TreeController` function  `getTreeCredsPasswords`. Details - {0}".format(str(e)))
        return {"status": 500, "message": str(e) }
    

#Получить список хостов по подсетям для дерева TreeView
def getTreeCredsAccessRights(db_session: Session, workspace_id: int ,node: dict):
    dd = []
    try:                             
        if(node['purpose'] == 'creds.access_levels'):
            select_statement =  '''SELECT DISTINCT metasploit_credential_logins.access_level AS label, 'directory' AS type, true AS lazy, false AS ticked, 'creds.access_level' AS purpose FROM metasploit_credential_logins
                                        INNER JOIN metasploit_credential_cores ON metasploit_credential_cores.id = metasploit_credential_logins.core_id
                                        WHERE metasploit_credential_cores.workspace_id = {0} AND metasploit_credential_logins.access_level IS NOT NULL
                                        ORDER BY metasploit_credential_logins.access_level'''.format(str(int(workspace_id)))  
        
        if(node['purpose'] == 'creds.access_level'):    
            select_creds = '''(SELECT hosts.address AS address, metasploit_credential_logins.access_level AS access_level, COUNT(metasploit_credential_cores.id) AS creds FROM metasploit_credential_cores 
                                    LEFT OUTER JOIN metasploit_credential_publics ON  metasploit_credential_publics.id = metasploit_credential_cores.public_id 
                                    LEFT OUTER JOIN metasploit_credential_privates ON metasploit_credential_privates.id = metasploit_credential_cores.private_id
                                    LEFT OUTER JOIN metasploit_credential_realms  ON metasploit_credential_realms.id  = metasploit_credential_cores.realm_id 
                                    LEFT OUTER JOIN metasploit_credential_logins  ON metasploit_credential_logins.core_id  = metasploit_credential_cores.id 
                                    LEFT OUTER JOIN services ON services.id  = metasploit_credential_logins.service_id
                                    LEFT OUTER JOIN hosts  ON hosts.id  = services.host_id  
                                    WHERE metasploit_credential_cores.workspace_id  = {0} 
                                    GROUP BY hosts.address, metasploit_credential_logins.access_level) n2'''.format(str(int(workspace_id)), str(node['label']))
            select_vulns = '''(SELECT hosts.address, COUNT(vulns.id) AS vulns FROM vulns INNER JOIN hosts ON vulns.host_id = hosts.id 
                                    LEFT OUTER JOIN services ON services.host_id  = hosts.id
                                    WHERE workspace_id = {0}
                                    GROUP BY hosts.address) n3'''.format(str(int(workspace_id)))
            select_statement = '''SELECT DISTINCT hosts.address AS label,'host' as type, hosts.id as host_id, hosts.os_family, hosts.os_name, hosts.state, hosts.purpose, false AS ticked, hosts.virtual_host, n2.creds, n3.vulns FROM hosts 
                                    INNER JOIN {0} ON n2.address = hosts.address 
                                    LEFT OUTER JOIN {1} ON n3.address = hosts.address 
                                    WHERE hosts.workspace_id = {2} AND n2.access_level = '{3}' ORDER BY label'''.format(select_creds, select_vulns, str(int(workspace_id)), str(node['label']))       
        
        result_set = db_session.execute(select_statement)
        return  {'status':200, 'data': [dict(r) for r in result_set]}
    except Exception as e:
        log.error("Error in controllers `TreeController` function  `getTreeCredsAccessRights`. Details - {0}".format(str(e)))
        return {"status": 500, "message": str(e) }