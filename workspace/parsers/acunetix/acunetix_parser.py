import re
import ipaddress
import socket
from typing import Tuple, Optional
import xml.etree.ElementTree as ET
from workspace.models.migration import WebSites, WebPages, WebForms, WebVulns, Vulns, VulnDetails, Hosts, Services
from workspace.controllers import VulnsController, HostsController, ServicesController, WebController
import workspace.logger as logging
from sqlalchemy.sql import label
from workspace.db_connect import create_session


log = logging.getLogger()

# class VulnWeb:

#     def __init__(self, name, description, ):
#         self.name = name 

#     # Instance method
#     def set(self):
#         return f"{self.name} says woof!"
    

def acunetix_pasrse_xml(filename: str, workspace: int, site=None):
    try:
        parse(filename, workspace, site)
    except Exception as e:        
        log.error("Error in Parser `Acunetix` function  `acunetix_pasre`. Details - {0}".format(str(e)))


def parse(filename: str, workspace: int, site: int):
    db_connect = create_session()
    host_id = None
    service_id = None
    site_id = None

    tree = ET.parse(filename)
    root = tree.getroot()

    name = root.find('./Scan/Name')
    startURL = get_text(root.find('./Scan/StartURL'))
    startTime = root.find('./Scan/StartTime')
    finishTime = root.find('./Scan/FinishTime')
    os = get_text(root.find('./Scan/OS'))
    banner = get_text(root.find('./Scan/Banner'))
    webServer =  get_text(root.find('./Scan/WebServer'))
    technologies = get_text(root.find('./Scan/Technologies'))

    if(site == None):
        parse_result = parse_url(startURL)
        if(parse_result != None):
            if('ip' in parse_result):
                host_id = db_connect.query(Hosts.id).filter(Hosts.workspace_id == workspace, Hosts.address == parse_result['ip']).first()
                #Add Host if is't exist
                if(host_id == None):
                    res = HostsController.add_hosts(db_connect, workspace, {'address': parse_result['ip'], 'os_family': os})
                    if(res['status'] == 200 or res['status'] == 503):
                        host_id = res['id']
                else:
                    host_id = host_id.id
                parse_result['vhost'] = parse_result['ip']
            else:
                host_id = db_connect.query(Hosts.id).filter(Hosts.workspace_id == workspace, Hosts.name == parse_result['dns']).first()
                #Add Host (address 127.0.0.1) if is't exist
                if(host_id == None):
                    #Resolve DNS Name
                    res = resolve_dns(parse_result['dns'])
                    if(res):
                        host_id = db_connect.query(Hosts.id).filter(Hosts.workspace_id == workspace, Hosts.address == res).first()
                        if(host_id == None):
                            res = HostsController.add_hosts(db_connect, workspace, {'address': res, 'os_family': os})
                            if(res['status'] == 200 or res['status'] == 503):
                                host_id = res['id']
                    else:
                        res = HostsController.add_hosts(db_connect, workspace, {'address': '127.0.0.1', 'os_family': os})
                        if(res['status'] == 200 or res['status'] == 503):
                            host_id = res['id']
                parse_result['vhost'] = parse_result['dns']

            if(parse_result['port'] == None):
                parse_result['port'] = get_port_from_url(root)
            else:
                res = db_connect.query(Services.id).join(Hosts, Hosts.id == Services.host_id).filter(Hosts.workspace_id == workspace, Hosts.id == host_id, Services.port == parse_result['port']).first()
                #Add Service if isn't exist
                if(res == None):
                    res = ServicesController.add_services(db_connect, workspace, {'host': {'id': host_id}, 'proto': 'tcp', 'port':  parse_result['port'], 'info': webServer})
                    if(res['status'] == 200 or res['status'] == 503):
                        service_id = res['id']
                else:
                    service_id = res.id
        else:
            return None
        

        res = db_connect.query(WebSites.id).filter(WebSites.service_id == service_id, WebSites.vhost == parse_result['vhost']).first()
        if(res == None):
            res = WebController.addSite(db_connect, workspace, {'host':  host_id, 'service': service_id, 'vhost': parse_result['vhost'], 'comments': banner, 'options': technologies})
            if(res['status'] == 200 or res['status'] == 503):
                site_id = res['id']  
        else:
            site_id = res.id
        
    else:
        res = db_connect.query(Hosts.id.label('host_id'), Services.id.label('service_id')).join(Services, Services.host_id == Hosts.id).join(WebSites, WebSites.service_id == Services.id).filter(Hosts.workspace_id == workspace, WebSites.id == site).first()
        if(res != None):
           host_id = res.host_id
           service_id = res.service_id
           site_id = site 
        else:
            return None

        
    for siteFile in root.find('./Scan/Crawler/SiteFiles'):
        page = {'fullpath': siteFile.find('URL').text, 'headers': ''}
        inputs = siteFile.find('Inputs')
        if(inputs):
            for variable in inputs:
                if(variable.attrib['Type'] == 'HTTP Header'):
                    page['headers'] += variable.attrib['Name'] + '; '
        res = db_connect.query(WebPages.id).filter(WebPages.web_site_id == site_id, WebPages.path == page['fullpath'], WebPages.headers == page['headers']).first()
        if(res == None):
            WebController.add_card_info(db_connect, site_id, 'Page', page)


    for reportItem in root.iter('ReportItem'):
        vulnweb = {
            'fullpath': get_text(reportItem.find('Affects')),
            'params': get_text(reportItem.find('Parameter')),
            'name': get_text(reportItem.find('Name')),
            'description': get_text(reportItem.find('Description')),
            'category': get_text(reportItem.find('Type')),
            'request': get_text(reportItem.find('TechnicalDetails/Request')),
            'proof': get_text(reportItem.find('Impact')),
        }

        res = db_connect.query(WebVulns.id).filter( WebVulns.web_site_id == site_id, 
                                                    WebVulns.path == vulnweb['fullpath'],
                                                    WebVulns.name == vulnweb['name'],
                                                    WebVulns.description == vulnweb['description'],
                                                    WebVulns.category == vulnweb['category'],
                                                    WebVulns.request == vulnweb['request'].encode('utf-8'),
                                                    WebVulns.proof == vulnweb['proof'].encode('utf-8')).first()
        if(res == None):
            WebController.add_card_info(db_connect, site_id, 'Vuln', vulnweb)

        refs = []
        for ref in reportItem.iter('References'):
            try:
                refs.append(get_text(ref.find('Reference/URL')))
            except:
                pass

        refs = VulnsController.get_refs(db_connect, refs)

        vuln = {
            'host': host_id,
            'service': service_id,
            'name': get_text(reportItem.find('Name')),
            'info': get_text(reportItem.find('Description')),
            'details': [
                {
                    'cvss_score':  get_text(reportItem.find('CVSS/Score')),
                    'cvss_vector':  get_text(reportItem.find('CVSS/Descriptor')),
                    'solutions': get_text(reportItem.find('Recommendation')),
                    'description': get_text(reportItem.find('Details')),
                    'title': get_text(reportItem.find('Details')),
                }
            ],
            'refs': refs
        }
        res = db_connect.query(Vulns.id).filter(    Vulns.host_id == host_id, 
                                                    Vulns.service_id == service_id,
                                                    Vulns.name == vuln['name'],
                                                    Vulns.info == vuln['info']).first()
        if(res == None):
            VulnsController.add_vulns(db_connect, workspace, vuln, None)



def get_text(element, default_value=None):
    if element is not None:
        return element.text
    else:
        return default_value
    

def resolve_dns(dns: str):
    try:
        ip_address = socket.gethostbyname(dns)
        return ip_address
    except socket.gaierror as e:
        return None
    

def get_port_from_url(root):
    try:
        startUrl = root.find('./Scan/Crawler').attrib['StartUrl']
        if(startUrl.find('https') != -1):
            return 443
        else:
            return 80
    except Exception as e:   
        return 80
    

def parse_url(s: str) -> dict:
    """
    Разбирает строку вида:
      "127.0.0.1:8080" -> ("ip", "127.0.0.1", 8080)
      "127.0.0.1"      -> ("ip", "127.0.0.1", None)
      "example.com:8001" -> ("dns", "example.com", 8001)
      "example.com"      -> ("dns", "example.com", None)
      "[::1]:8080"     -> ("ip", "::1", 8080)
      "[::1]"          -> ("ip", "::1", None)

    Возвращает: (kind, host, port) где kind в {"ip", "dns"}.
    """
    s = s.strip()

    # IPv6 в форме [addr]:port или [addr]
    if s.startswith('['):
        m = re.match(r'^\[([^\]]+)\](?::(\d{1,5}))?$', s)
        if not m:
            raise ValueError(f"Invalid IPv6/host syntax: {s}")
        host = m.group(1)
        port = int(m.group(2)) if m.group(2) else None
        # проверим валидность IPv6
        try:
            ipaddress.IPv6Address(host)
            return {"ip": host, "port": port}
        except ipaddress.AddressValueError:
            # если не IPv6, всё равно вернуть как dns
            return {"dns": host, "port": port}

    # В остальных случаях попытка разделить по последнему двоеточию (port может присутствовать)
    if ':' in s:
        # разделяем по последнему ':' чтобы корректно обработать host:port
        host_part, port_part = s.rsplit(':', 1)
        # если порт состоит только из цифр — считаем это портом
        if port_part.isdigit():
            port = int(port_part)
            host = host_part
        else:
            # если справа не цифры — это не порт, берем всю строку как host
            host = s
            port = None
    else:
        host = s
        port = None

    # Определяем, является ли host IP (v4) или DNS
    try:
        ipaddress.IPv4Address(host)
        return {"ip": host, "port": port}
    except ipaddress.AddressValueError:
        pass

    # Если хост пустой — ошибка
    if not host:
        raise ValueError("Empty host")

    # Небольшая валидация доменного имени (упрощённая)
    dns_re = re.compile(r'^(?:[A-Za-z0-9-]{1,63}\.)*[A-Za-z0-9-]{1,63}$')
    if dns_re.match(host):
        return {"dns": host, "port": port}

    # Если не попали ни в одно — вернуть как dns без строгой валидации
    return {"dns": host, "port": port}