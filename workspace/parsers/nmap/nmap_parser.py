import base64
from workspace.db_connect import create_session
from workspace.controllers import CredsController, HostsController, LootsController, NotesController, ServicesController, UserTasksController, UsersController, VulnsController, WorkspacesController
from libnmap.parser import NmapParser
from rubymarshal.reader import loads, load
from rubymarshal.writer import writes, write
from rubymarshal.classes import Symbol
import workspace.logger as logging
import json

log = logging.getLogger()


def nmap_parse(filename, workspace):
    try:
        p = NmapParser.parse_fromfile(filename)
        for host in p.hosts:
            if(host.status != 'down'):
                session = create_session()
                host_id = HostsController.get_host_id(session, workspace, host.address)
                session.close()
                #Собираем информацию про host и записываем в БД
                data_h = {"address":"", "mac":"", "info":"", "comments":"", "state":"", "os_family":"", "os_name":"", "os_flavor":"", 
                "os_sp":"", "os_lang":"", "arch": "", "name":"", "purpose":"", "virtual_host":""}
                if(host.ipv4 is not ''):       
                    data_h["address"] = host.ipv4
                elif(host.ipv6 is not ''):
                    data_h["address"] = host.ipv6
                else:
                    continue    
                data_h["mac"] = host.mac
                data_h["info"] = ''
                data_h["comments"] = ''
                data_h["state"] = 'alive'
                for os_ in host.os.osclasses:
                    data_h["os_family"] = os_.osfamily
                    data_h["os_sp"] = os_.osgen
                    break
                for os_ in host.os.osmatches:
                    data_h["os_name"] = os_.name
                    data_h["os_flavor"] = ''
                    data_h["os_lang"] = ''
                    data_h["arch"] = ''
                    break
                for name_ in host.hostnames:
                    if('output' in  name_):
                        data_h["name"] = name_['output']
                    if(str(type(name_)) == "<class 'str'>"):
                         data_h["name"] = name_
                    break
                data_h = os_normalize(data_h)
                data_h["virtual_host"] = ''
                if(host_id == None):
                    session = create_session()
                    res = HostsController.add_hosts(session, workspace, data_h)
                    if(res['status'] == 200):
                        host_id = res["id"]
                    session.close()
                else:
                    session = create_session()
                    data_h["id"] = host_id
                    HostsController.edit_hosts(session, workspace, data_h)
                    session.close()
                #Добавляем в Notes
                if(len(host.os.osclasses) or len(host.os.osmatches)):
                    #Добавляем host.os.nmap_fingerprint
                    session = create_session()
                    data_n = {"host":{"id": host_id}, "ntype": "host.os.nmap_fingerprint", "data": []}
                    os_classes = []
                    for os_ in host.os.osclasses:
                        os_classes.append({"os_vendor": os_.vendor, "os_family": os_.osfamily , "os_type": os_.type, "os_accuracy": os_.accuracy, "os_gen": os_.osgen})
                    os_matches = []
                    for os_ in host.os.osmatches:
                        os_matches.append({"os_name": os_.name, "os_accuracy": os_.accuracy})
                    data_n["data"].append(os_classes)
                    data_n["data"].append(os_matches)
                    data_n["data"] = base64.b64encode(writes(json.dumps(data_n["data"], sort_keys=True, indent=4))).decode('utf-8')
                    NotesController.add_notes(session, workspace, data_n)
                    session.close()

                    #Добавляем host.last_boot
                    if(host.lastboot != ''):
                        session = create_session()
                        data_n = {"host":{"id": host_id}, "ntype": "host.last_boot", "data": {"time":host.lastboot}}
                        data_n["data"] = base64.b64encode(writes(json.dumps(data_n["data"], sort_keys=True, indent=4))).decode('utf-8')
                        NotesController.add_notes(session, workspace, data_n)
                        session.close()

                    #Добавляем host.nmap.traceroute
                    # if(host.distance != 0):
                    #     session = create_session()
                    #     data_n = {"address": host.address, "port": None, "proto": None, "state": None, "name": None, "ntype": "host.nmap.traceroute", "data": []}
                    #     data_n["data"] = base64.b64encode(writes(json.dumps(data_n["data"], sort_keys=True, indent=4))).decode('utf-8')
                    #     notes.add_notes(session, workspace, data_n)
                    #     session.close()

                #Собираем информацию про services и записываем в БД
                for service in host.services:
                    service_id = ServicesController.get_service_id(workspace, service.protocol, service.service, service.port, host.address)
                    data = {"host":{"id": host_id}, "port": service.port, "proto": service.protocol, "state": service.state, "name": service.service, "info": ""}
                    try:
                        for banner in service.banner_dict:
                            data["info"] += service.banner_dict[banner]+" "
                    except:
                        data["info"] = ""
                    if(service_id == None):
                        session = create_session()
                        ServicesController.add_services(session, workspace, data)
                        session.close()
                    else:
                        session = create_session()
                        data["id"] = service_id
                        ServicesController.edit_services(session, workspace, data)
                        session.close()
                for script_out in host.scripts_results:
                    print ("Output of {0}: {1}".format(script_out['id'],script_out['output']))
    except Exception as e:
        log.error("Error in parser `Nmap` function  `nmap_parse`. Details - {0}".format(str(e)))


def os_normalize(os_info: list) -> list:
    os_name = [
            'Windows 10',
            'Windows 11',
            'Windows 2000',
            'Windows 2003 R2',
            'Windows 2008 R2',
            'Windows 2012',
            'Windows 2012 R2',
            'Windows 7',
            'Windows 8',
            'Windows 8.1',
            'Windows 95',
            'Windows 98',
            'Windows Longhorn',
            'Windows ME',
            'Windows Mobile',
            'Windows Server 2008',
            'Windows Server 2008 R2',
            'Windows Server 2012',
            'Windows Server 2012 R2',
            'Windows Server 2016',
            'Windows Server 2019',
            'Windows Server 2022',
            'Windows Vista',
            'Windows XP'
            ]

    #OS_Family
    if(os_info["os_family"] == 'Microsoft Windows'):
        os_info["os_family"] = 'Windows'
    elif(os_info["os_name"].lower().find("d-link") != -1):
        os_info["os_family"] = "D-Link"
        os_info["purpose"] = "router"
    elif(os_info["os_family"].lower().find("linux kernel") != -1):
        os_info["os_family"] = 'Linux'
    elif(os_info["os_family"].lower().find("ubuntu") != -1):
        os_info["os_family"] = 'Linux'
    elif(os_info["os_family"].lower().find("debian") != -1):
        os_info["os_family"] = 'Linux'
    elif(os_info["os_family"].lower().find("freebsd") != -1):
        os_info["os_family"] = 'FreeBSD'
    elif(os_info["os_name"].lower().find("unix") != -1):
        os_info["os_family"] = "Unix"
    elif(os_info["os_name"].lower().find("cisco") != -1):
        os_info["os_family"] = "Cisco"
        os_info["purpose"] = "router"
    # else:
    #     os_info["os_family"] = "Cisco"

    #Arch
    if(os_info["os_name"].lower().find("(x64)") != -1):
        os_info["arch"] = "x64"
        os_info["os_name"] = replace_string(os_info["os_name"], "(x64)")
    if(os_info["os_name"].lower().find("(x86)") != -1):
        os_info["arch"] = "x86"
        os_info["os_name"] = replace_string(os_info["os_name"], "(x86)")
    if(os_info["os_name"].lower().find("x86_64") != -1):
        os_info["arch"] = "x86_64"
        os_info["os_name"] = replace_string(os_info["os_name"], "x86_64")
    

    if(os_info["os_family"] == 'Windows'):
        #OS_SP
        if(os_info["os_name"].lower().find("service pack") != -1):
            if(os_info["os_name"].lower().find("service pack 1") != -1):
                os_info["os_sp"] = "SP1"
                os_info["os_name"] = replace_string(os_info["os_name"], "service pack 1")
            if(os_info["os_name"].lower().find("service pack 2") != -1):
                os_info["os_sp"] = "SP2"
                os_info["os_name"] = replace_string(os_info["os_name"], "service pack 2")
            if(os_info["os_name"].lower().find("service pack 3") != -1):
                os_info["os_sp"] = "SP3"
                os_info["os_name"] = replace_string(os_info["os_name"], "service pack 3")
        
        #OS_Flavour
        os_info["os_flavour"] = os_info["os_name"]

        #OS_Name
        for row in os_name:
            if(os_info["os_name"].lower().find(row.lower()) != -1):
                os_info["os_name"] = row
                if(os_info["os_name"].lower().find("server") != -1 or os_info["os_name"].lower().find("20") != -1):
                    os_info["purpose"] = "server"
                elif(os_info["os_name"].lower().find("mobile") != -1):
                    os_info["purpose"] = "smart_phone"
                else:
                    os_info["purpose"] = "client"
                break
    return os_info


def replace_string(org_str: str, rep_str: str):
    res = list(org_str)
    start_pos = org_str.lower().find(rep_str)
    for char_ in rep_str:
        res.pop(start_pos)
    return ''.join(res)