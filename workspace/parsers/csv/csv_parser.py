from workspace.db_connect import create_session
from workspace.controllers import HostsController
import csv
import workspace.logger as logging

log = logging.getLogger()

def csv_parse(filename, workspace):
    try:
        with open(filename) as f:
            hosts_dict = csv.DictReader(f,  delimiter=';')
            for host in hosts_dict:
                session = create_session()
                host_id = HostsController.get_host_id(session, int(workspace), host['address'])
                if(host_id == None):
                    HostsController.add_hosts(session, int(workspace), host)
                else:
                    host['id'] = host_id
                    HostsController.edit_hosts(session, int(workspace), host)
                session.close()
    except Exception as e:
        log.error("Error Parse CSV Parse (workspace_id - {0}, filename - {1}). Message: {2}".format(str(workspace), str(filename), e._message))


