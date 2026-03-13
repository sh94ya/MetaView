from workspace import app 
from flask import request
import json
import base64
from flask_jwt_extended import jwt_required
from flask_cors import cross_origin
from workspace.db_connect import create_session
from workspace.controllers import TreeController, general

#Получить доступные workspaces
@app.route('/api/v1/Tree',methods=['GET', 'POST'])
@jwt_required()
def get_tree():
    workspace_id = request.json['data']['workspace']
    node =  base64.b64decode(request.json['data']['data'])
    # node = base64.b64decode(request.args.get('node'))
    node = general.JSON_deserialize(str(node.decode("utf8"))) 
    # workspace_id = request.args.get('workspace')
    session = create_session()
    resp_data = None
    if(node['type'] == 'directory' and (node['purpose'] == 'hosts.subnets' or node['purpose'] == 'hosts.subnet') ):
        resp_data = TreeController.getTreeSubnets(session, int(workspace_id), node)

    if(node['type'] == 'directory' and (node['purpose'] == 'hosts.tags' or node['purpose'] == 'hosts.tag')):
        resp_data = TreeController.getTreeTags(session, int(workspace_id), node)

    if(node['type'] == 'directory' and (node['purpose'] == 'hosts.purposes' or node['purpose'] == 'hosts.purpose')):
        resp_data = TreeController.getTreePurpose(session, int(workspace_id), node)

    if(node['type'] == 'directory' and (node['purpose'] == 'hosts.os' or node['purpose'] == 'hosts.os_family' or node['purpose'] == 'hosts.os_name')):
        resp_data = TreeController.getTreeOS(session, int(workspace_id), node)

    if(node['type'] == 'directory' and (node['purpose'] == 'services.names' or node['purpose'] == 'services.name' or node['purpose'] == 'services.ports' or node['purpose'] == 'services.port')):
        resp_data = TreeController.getTreeServices(session, int(workspace_id), node)

    if(node['type'] == 'directory' and (node['purpose'] == 'notes.ntypes' or node['purpose'] == 'notes.ntype')):
        resp_data = TreeController.getTreeNotes(session, int(workspace_id), node)

    if(node['type'] == 'directory' and (node['purpose'] == 'loots.ltypes' or node['purpose'] == 'loots.ltype')):
        resp_data = TreeController.getTreeLoots(session, int(workspace_id), node)

    if(node['type'] == 'directory' and (node['purpose'] == 'vulns.names' or node['purpose'] == 'vulns.name')):
        resp_data = TreeController.getTreeVulnsName(session, int(workspace_id), node)

    if(node['type'] == 'directory' and (node['purpose'] == 'vulns.exploited')):
        resp_data = TreeController.getTreeVulnsExploited(session, int(workspace_id), node)

    if(node['type'] == 'directory' and (node['purpose'] == 'vulns.refs' or node['purpose'] == 'vulns.ref')):
        resp_data = TreeController.getTreeVulnsRefs(session, int(workspace_id), node)

    if(node['type'] == 'directory' and (node['purpose'] == 'creds.usernames' or node['purpose'] == 'creds.username')):
        resp_data = TreeController.getTreeCredsUsernames(session, int(workspace_id), node)

    if(node['type'] == 'directory' and (node['purpose'] == 'creds.passwords' or node['purpose'] == 'creds.password')):
        resp_data = TreeController.getTreeCredsPasswords(session, int(workspace_id), node)

    if(node['type'] == 'directory' and (node['purpose'] == 'creds.access_levels' or node['purpose'] == 'creds.access_level')):
        resp_data = TreeController.getTreeCredsAccessRights(session, int(workspace_id), node)

    session.close()
    return  resp_data
