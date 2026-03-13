from workspace import app 
from flask import request
from flask_jwt_extended import jwt_required
from workspace.secure_filename import secure_filename
#Parsers
from workspace.parsers.maxpatrol.max_patrol_parser import  mxpatrol_parse
from workspace.parsers.nmap.nmap_parser import nmap_parse
from workspace.parsers.csv.csv_parser import csv_parse

#Загрузка файла на сервер
@app.route('/upload', methods=['POST'])
@jwt_required()
def upload():
    workspace_id = request.headers['workspace']
    for fname in request.files:
        f = request.files.get(fname)
        print(f)
        filename = './uploads/%s' % secure_filename(fname)
        f.save(filename)
        try:
            nmap_parse(filename, int(workspace_id))
        except:
            pass
        try:
            csv_parse(filename, int(workspace_id))
        except:
            pass
        try:
            mxpatrol_parse(filename, int(workspace_id))
        except:
            pass
        # mxpatrol_parse(filename, int(workspace_id))
        # nmap_parse(filename, int(workspace_id))
    return 'Okay!'