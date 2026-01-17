from workspace.db_connect import create_session
from workspace.controllers import CredsController, HostsController, LootsController, NotesController, ServicesController, UserTasksController, UsersController, VulnsController, WorkspacesController
import xml.etree.ElementTree as ET

def lanscope_parse_xml(filename, workspace):
    tree = ET.parse(filename)
    root = tree.getroot()
    host_info = []
    for host in p.hosts:
        if(host.status != 'down'):
            host_id = HostsController.get_host_id(workspace, host.address)
            #Собираем информацию про host и записываем в БД
            data = {"address":"", "mac":"", "info":"", "comments":"", "state":"", "os_family":"", "os_name":"", "os_flavor":"", 
            "os_sp":"", "os_lang":"", "arch": "", "name":"", "purpose":"", "virtual_host":""}
            data["address"] = host.address
            data["mac"] = host.mac
            data["info"] = ''
            data["comments"] = ''
            data["state"] = 'alive'
            for os_ in host.os.osclasses:
                data["os_family"] = os_.osfamily
                data["os_sp"] = os_.osgen
                break
            for os_ in host.os.osmatches:
                data["os_name"] = os_.name
                data["os_flavor"] = ''
                data["os_lang"] = ''
                data["arch"] = ''
                break
            for name_ in host.hostnames:
                data["name"] = name_['output']
                break
            data["purpose"] = 'device'
            data["virtual_host"] = ''
            if(host_id == None):
                session = create_session()
                HostsController.add_hosts(session, workspace, data)
                session.close()
            else:
                session = create_session()
                data["id"] = host_id
                HostsController.edit_hosts(session, workspace, data)
                session.close()
            #Собираем информацию про services и записываем в БД
            for service in host.services:
                service_id = ServicesController.get_service_id(workspace, service.protocol, service.service, service.port, host.address)
                data = {"address": host.address, "port": service.port, "proto": service.protocol, "state": service.state, "name": service.service, "info": ""}
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

