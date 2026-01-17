#!/usr/bin/env python
import os
import xml.etree.ElementTree as ET
import csv
import argparse as arp
# from parsers.maxpatrol.excel_saver import save_to_excel
import html
import base64
from workspace.db_connect import create_session
from workspace.controllers import HostsController, NotesController, ServicesController, VulnsController
from workspace.db_connect import create_session
from rubymarshal.reader import loads, load
from rubymarshal.writer import writes, write
from rubymarshal.classes import Symbol
import json


namespaces = {'PT': 'http://www.ptsecurity.ru/reports'}
protocols = {'6': 'TCP', '17': 'UDP'}
port_status = {'0': 'open', '1': 'filtered', '2': 'closed'}


def risk_level(cvss, reliability):
    cvss = float(cvss)
    if int(reliability) == 0:
        if cvss >= 9:
            return 'Critical'
        elif cvss >= 7 and cvss < 9:
            return 'High'
        elif cvss > 4 and cvss < 7:
            return 'Medium'
        else:
            return 'Low'
    elif int(reliability) == 1:
        if cvss >= 9:
            return 'Critical (Suspicious)'
        elif cvss >= 7 and cvss < 9:
            return 'High (Suspicious)'
        elif cvss > 4 and cvss < 7:
            return 'Medium (Suspicious)'
        else:
            return 'Low (Suspicious)'


def mp_parse(input_filename, workspace, flags):
    level = flags['level']
    cve_is_needed = flags['cve']
    notes_is_need = flags['notes']
    tree = ET.parse(input_filename)
    root = tree.getroot()
    host_info = []
    vuln_table_creator(root)
    for host in root.findall('./PT:data/PT:host', namespaces):
        appended_info = {'ip':"", 'fqdn':"", 'os_family':"", 'os_name':"", 'os_flavor':"", 'os_sp':"", 'arch':"", 'purpose': "device",'services': []}
        appended_info["ip"] = host.attrib['ip']
        appended_info["fqdn"] = host.attrib['fqdn']
        scanner_name = host.find('PT:scanner', namespaces).text
        start_time = host.attrib['start_time']
        stop_time = host.attrib['stop_time']
        os = get_os_info(host)
        appended_info["os_family"] = os["os_family"]
        appended_info["os_name"] = os["os_name"]
        appended_info["os_flavor"] = os["os_flavour"]
        appended_info["os_sp"] = os["os_sp"]
        appended_info["arch"] = os["arch"]
        appended_info["purpose"] = os["purpose"]
        for soft in host.findall('PT:scan_objects/PT:soft', namespaces):
            appended_info["services"].append({'soft_name':"", 'soft_version':"",
                        'soft_path':"", 'port':"", 'proto':"", 'port_status':"", 'service_name':"", 'service_info':"", 'vulns': []})
            appended_info["services"][len(appended_info["services"])-1]["soft_name"] = soft.find('PT:name', namespaces).text
            try:
                appended_info["services"][len(appended_info["services"])-1]["soft_version"] = soft.find('PT:version', namespaces).text
            except:
               appended_info["services"][len(appended_info["services"])-1]["soft_version"] = None
            try:
               appended_info["services"][len(appended_info["services"])-1]["soft_path"] = soft.find('PT:path', namespaces).text
            except:
               appended_info["services"][len(appended_info["services"])-1]["soft_path"] = None
            try:
                appended_info["services"][len(appended_info["services"])-1]["port"] = soft.attrib['port']
            except:
                appended_info["services"][len(appended_info["services"])-1]["port"]  = None
            try:
                appended_info["services"][len(appended_info["services"])-1]["proto"] = protocols[soft.attrib['protocol']].lower()
            except:
                appended_info["services"][len(appended_info["services"])-1]["port"] = None
            try:
                appended_info["services"][len(appended_info["services"])-1]["port_status"] = port_status[soft.attrib['port_status']]
            except:
                appended_info["services"][len(appended_info["services"])-1]["port_status"] = None
            try:
                 appended_info["services"][len(appended_info["services"])-1]["service_name"] = soft.find('PT:name', namespaces).text.lower()
            except:
                 appended_info["services"][len(appended_info["services"])-1]["service_name"] = None
            try:
                 appended_info["services"][len(appended_info["services"])-1]["service_info"] = find_service_info(soft)
            except:
                 appended_info["services"][len(appended_info["services"])-1]["service_info"] = None
            # finds cve and cvss if exists, else sets None
            vulns_ = vuln_finder(soft, start_time, stop_time, scanner_name, level, cve_is_needed, notes_is_need)
            appended_info["services"][len(appended_info["services"])-1]["vulns"] = vulns_
            add_IN_DB(workspace, appended_info)
    return host_info


def add_IN_DB(workspace: int, appended_info):
            session = create_session()
            try:
                #Узлы
                host_id = HostsController.get_host_id(session, workspace, appended_info["ip"])
                data_h = {"id":host_id, "address":appended_info["ip"], "mac":"", "info":"", "comments":"", "state":"alive", "os_family":appended_info["os_family"], "os_name": appended_info["os_name"], 
                "os_flavor": appended_info["os_flavor"], "os_sp": appended_info["os_sp"], "os_lang":"", "arch":  appended_info["arch"],
                "name": appended_info["fqdn"], "purpose": appended_info["purpose"], "virtual_host":""}
                if(host_id == None):
                    host_res = HostsController.add_hosts(session, workspace, data_h)
                    if(host_res["status"] == 200):
                        host_id = host_res["id"]
                else:
                    data_h["id"] = host_id
                    del data_h["info"]
                    del data_h["comments"]
                    HostsController.edit_hosts(session, workspace, data_h)
                #Сервисы
                for ser in appended_info["services"]:
                    service_id = None
                    if(ser["port"]!= None or ser["port"] != ''):
                        data_s = {"id":None, "host": {'id': host_id}, "port": ser["port"], "proto": ser["proto"], "state": ser["port_status"], "name": ser["service_name"], "info": ser["service_info"]}
                    else: 
                        continue
                    service_id = ServicesController.get_service_id(workspace, ser["proto"], None,  ser["port"], appended_info["ip"])
                    if(service_id == None):
                        service_res = ServicesController.add_services(session, workspace, data_s)
                        if(service_res["status"] == 200):
                            service_id = service_res["id"]
                    else:
                        data_s["id"] = service_id
                        ServicesController.edit_services(session, workspace, data_s)
                    #Уязвимости
                    for vuln in ser["vulns"]:
                        #Заметки
                        try:
                            for note in vuln["notes"]:
                                data_n = {"id":None, "host": {'id': host_id}, "service":{'id': service_id}, "name": None, "ntype": note["ntype"], "data": note["data"]}
                                note_id = NotesController.get_Notes_by_HostID(session, workspace, host_id, service_id, note)
                                if(note_id == None):
                                    NotesController.add_notes(session, workspace, data_n)
                                else:
                                    NotesController.edit_notes(session, workspace, data_n)
                        except:
                            pass
                        vuln_id = VulnsController.get_Vulns_by_HostID(session, workspace, host_id, service_id, vuln)
                        data_v = {"id":None, "host": {'id': host_id}, "service":{'id': service_id},"name": vuln["name"], "info":vuln["info"],  
                                  "refs": [], 
                                  'details': [{'title': 'x', 'description': 'x', 'nx_vulner_id': vuln["mx_vulner_id"],'solution': vuln["solution"], 'cvss': vuln["cvss"]}], 
                                  'attempts': []
                        }
                        if(vuln_id == None and (vuln["mx_rate"][2] >= 4)):
                            data_v["refs"] = VulnsController.get_refs(session, vuln["refs"])
                            vuln_res = VulnsController.add_vulns(session, workspace, data_v, None)
                            if(vuln_res["status"] == 200):
                                vuln_id = vuln_res["id"]
                                data_v["id"] = vuln_id
                        elif(vuln["mx_rate"][2] >= 4):
                                data_v["id"] = vuln_id
                                data_v["refs"] = VulnsController.get_refs(session, vuln["refs"])
                                VulnsController.edit_vulns(session, workspace, data_v, None)
            except:
                session.rollback()
            session.close()


def find_service_info(leaf):
    res = ""
    elements = leaf.findall('PT:banner/PT:table/PT:body/PT:row/PT:field', namespaces)
    for el in elements:
        res += el.text
    return res


def mxpatrol_parse(filename: str, workspace: int):
    res = {'rsp_k':410,'message':'Не удалось импортировать данные MaxPatrol Scaner!'}
    try:
        data = mp_parse(filename, workspace, {'excel':False,'level': [4, 5],'cve':True, 'notes': True})
    except:
        pass
    return res


def get_os_info(host):
    os_info = {"os_family": None, "os_name": None, "os_flavour": None, "os_sp": None, "arch": None, "purpose": "device"}
    for prod_type in host.findall('PT:scan_objects/PT:soft', namespaces):
        if prod_type.attrib['type'] == '2':
            os_info["os_family"] = prod_type.find('PT:name', namespaces).text
            os_info["os_name"] = prod_type.find('PT:version', namespaces).text
            os_info = os_normalize(os_info)
            break
    return os_info


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


def patrol_level(lvl: str):
    return \
        {'0': 'доступна информация',
         '1': 'низкий уровень',
         '2': 'средний уровень (подозрение)',
         '3': 'средний уровень',
         '4': 'высокий уровень (подозрение)',
         '5': 'высокий уровень'}[lvl]


def notes_finder(element: ET.Element):
    notes = []
    for el in element.findall('PT:param_list/PT:table', namespaces):
        note = {"ntype":"maxpatrol.", "data": None}
        note["ntype"] = note["ntype"] + el.attrib["name"]
        column_n = []
        data = []
        for head in el.findall('PT:header/PT:column', namespaces):
            column_n.append(head.attrib["name"])
        for row in el.findall('PT:body/PT:row', namespaces):
            iter_field = 0
            row_dict = {}
            for field in row.findall('PT:field', namespaces):
                row_dict[column_n[iter_field]] = field.text
                iter_field+=1
            data.append(row_dict)
        note["data"] = base64.b64encode(writes(Symbol(json.dumps(data, sort_keys=True, indent=4, ensure_ascii=False)).name)).decode('utf8') 
        notes.append(note)
    return notes


def vuln_finder(soft: ET.Element, start_time: str, stop_time: str, scanner_name: str,
                level: list, cve: bool, notes: bool) -> list:
    counter = 0
    vuln = []
    for vulnerabilty in soft.findall('PT:vulners/PT:vulner', namespaces):
        if level is None:
            pass
        elif int(vulnerabilty.attrib['level']) not in level:
            continue
        counter += 1
        vulners_part = vulners_fast_table[vulnerabilty.attrib['id']]
        if cve and vulners_part[2] is None:
            continue
        try:
            risk = [risk_level(vulners_part[1], vulnerabilty.attrib['status'])]
        except:
            risk = ['Info']
        vuln_t = {"mx_vulner_id": None, "name": None,"cvss": None, "notes": None, "CVE": None, "info": None, "solution": None, 
                "refs": None, "mx_rate": None, "scanner_name": None, "start_time": None, "stop_time": None}
        vuln.append(vuln_t)
        patrol_risk = patrol_level(vulnerabilty.attrib['level'])
        risk.append(patrol_risk)
        risk.append(int(vulnerabilty.attrib['level']))
        if(notes is True):
            vuln[len(vuln)-1]["notes"] = notes_finder(vulnerabilty)
        vuln[len(vuln)-1]["mx_vulner_id"] = vulnerabilty.attrib['id']
        vuln[len(vuln)-1]["name"] = vulners_part[0]
        vuln[len(vuln)-1]["cvss"] = vulners_part[1]
        vuln[len(vuln)-1]["CVE"] = vulners_part[2]
        vuln[len(vuln)-1]["info"] = vulners_part[3]
        vuln[len(vuln)-1]["solution"] = vulners_part[4]
        if(vulners_part[5]!= None):
            vuln[len(vuln)-1]["refs"] = vulners_part[5].split('\n') + vuln[len(vuln)-1]["CVE"]
        vuln[len(vuln)-1]["mx_rate"] = risk
        vuln[len(vuln)-1]["scanner_name"] = scanner_name
        vuln[len(vuln)-1]["start_time"] = start_time
        vuln[len(vuln)-1]["stop_time"] = stop_time
    return vuln


vulners_fast_table = dict()


def vuln_table_creator(root: ET, ):
    for vuln in root.findall('./PT:vulners/PT:vulner', namespaces):
        vuln_info = list()
        try:
            vuln_info.append(html.unescape(vuln.find('PT:title', namespaces).text))
        except:
            vuln_info.append(None)
        try:
            vuln_info.append(vuln.find('PT:cvss', namespaces).attrib['base_score'])
        except:
            vuln_info.append(None)
        try:
            vuln_info.append(
                [a for a in [v.attrib['value'] for v in vuln.findall("PT:global_id", namespaces)] if "CVE" in a])
        except:
            vuln_info.append(None)
        try:
            vuln_info.append(html.unescape(vuln.find('PT:description', namespaces).text))
        except:
            vuln_info.append(None)
        try:
            vuln_info.append(html.unescape(vuln.find('PT:how_to_fix', namespaces).text))
        except:
            vuln_info.append(None)
        try:
            vuln_info.append(html.unescape(vuln.find('PT:links', namespaces).text))
        except:
            vuln_info.append(None)
        vulners_fast_table.update({vuln.attrib['id']: vuln_info})

