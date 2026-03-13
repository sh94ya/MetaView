from workspace import app 
from flask import request
import os
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from flask_jwt_extended import jwt_required
from workspace.secure_filename import secure_filename

from workspace.parsers.maxpatrol.max_patrol_parser import mxpatrol_parse
from workspace.parsers.nmap.nmap_parser import nmap_parse
from workspace.parsers.csv.csv_parser import csv_parse
from workspace.parsers.lanscope.lanscope_parser import lanscope_parse_xml
from workspace.parsers.acunetix.acunetix_parser import acunetix_pasrse_xml


@app.route('/api/v1/upload', methods=['POST'])
@jwt_required()
def upload():
    workspace_id = request.headers['workspace']
    for fname in request.files:
        f = request.files.get(fname)
        print(f)
        filename = './uploads/%s' % secure_filename(fname)
        f.save(filename)
        checkParserTypeForFile(filename, {'workspace_id':  int(workspace_id)})
        os.remove(filename)
    return 'Okay!'


def checkParserTypeForFile(filename: str, arg: dict):  
    type_file = detect_format(Path(filename))
    if(type_file == 'xml'):
        tree = ET.parse(filename)
        root = tree.getroot()
        if('scanner' in root.attrib and  root.attrib['scanner'] == 'nmap'):
            nmap_parse(filename, arg['workspace_id'])
        else:
            acunetix_pasrse_xml(filename, arg['workspace_id'])
            # mxpatrol_parse(filename, arg['workspace_id'])
    if(type_file == 'html'): 
        lanscope_parse_xml(filename, arg['workspace_id'])  
    if(type_file == 'csv'): 
        csv_parse(filename, arg['workspace_id'])


def detect_format(path: Path) -> str:
    text = path.read_text(encoding='utf-8', errors='ignore').lstrip()
    lower = text.lower()

    # Быстрая проверка на XML (начинается с '<?xml' или с тега '<...>')
    if lower.startswith('<?xml') or lower.startswith('<!doctype') or lower.startswith('<html') or lower.startswith('<!doctype html'):
        # если явно html
        if '<html' in lower or '<!doctype html' in lower:
            return 'html'
        return 'xml' if lower.startswith('<?xml') or lower.lstrip().startswith('<') else 'xml'

    # Если есть явные HTML-теги
    html_tags = ['<html', '<head', '<body', '<div', '<span', '<!doctype']
    if any(tag in lower for tag in html_tags):
        return 'html'

    # Простая проверка на CSV: строки с разделителями-запятыми/точкой с запятой и постоянное число столбцов
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if lines:
        # пробуем два разделителя: ',' и ';'
        for sep in (',', ';', '\t'):
            cols_counts = [len(line.split(sep)) for line in lines[:50]]  # первые 50 строк
            if len(cols_counts) >= 2 and min(cols_counts) >= 2:
                # считаем однородность: большинство строк имеют одинаковое число столбцов
                from collections import Counter
                c = Counter(cols_counts)
                most_common_count, freq = c.most_common(1)[0]
                if freq / len(cols_counts) >= 0.6:  # порог 60%
                    return 'csv'
    # Если встречаются XML-подобные теги (не обязательно в начале)
    if '<' in text and '>' in text and ('</' in text or text.strip().startswith('<')):
        # проверяем на наличие корневых xml-тэгов типа <tag ...>
        import re
        if re.search(r'<[a-zA-Z_][\w\-.]*\b[^>]*>', text):
            return 'xml'

    return 'unknown'