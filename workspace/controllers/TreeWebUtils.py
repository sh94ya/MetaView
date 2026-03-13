from typing import Dict, Any, List
import json
import posixpath


def norm_path(p: str) -> str:
    # нормализуем пути в posix-стиле
    if not p:
        return "/"
    p = posixpath.normpath(p)
    if not p.startswith("/"):
        p = "/" + p
    # если оригинал оканчивался на '/', считать это директорией
    return p if p == "/" else p.rstrip("/")


def split_parts(p: str) -> List[str]:
    p = p.rstrip("/")
    if p == "" or p == "/":
        return ["/"]
    parts = p.split("/")
    # первая пустая из-за ведущего '/'
    return ["/"] + [part for part in parts[1:] if part != ""]


class Node:
    def __init__(self, name: str, fullpath: str, typ: str = "directory"):
        self.name = name
        self.fullpath = fullpath
        self.type = typ  # "directory", "file", "form", "vuln"
        self.children: Dict[str, 'Node'] = {}
        self.code = None
        self.comment = None

    def to_dict(self) -> Dict[str, Any]:
        d = {"name": self.name, "fullpath": self.fullpath, "type": self.type, "code": self.code, "comment": self.comment}
        if self.children:
            # сортируем детей по имени для детерминированности
            d["children"] = [self.children[k].to_dict() for k in sorted(self.children.keys())]
        return d
    
    def set_code(self, code: int):
        self.code = code

    def set_comment(self, comment: dict):
        self.comment = comment


def insert(root: Node, raw_path: str, typ: str, code: int = None, comment: dict = None):
    # определим, является ли путь директорией по наличию '/' в конце в исходном raw_path
    is_dir = raw_path.endswith("/")
    p = raw_path
    # нормализуем, но сохраним признак окончания '/'
    parts = split_parts(p)
    cur = root
    cur_path = ""
    for i, part in enumerate(parts):
        if part == "/":
            cur_path = "/"
            key = "/"
            name = "/"
        else:
            cur_path = posixpath.join(cur_path, part) if cur_path != "/" else "/" + part
            key = cur_path
            name = part
        if key not in cur.children:
            # по умолчанию новые узлы считаем директориями; тип изменим для файла/формы/вулна в конце
            node_type = "directory"
            cur.children[key] = Node(name, key, node_type)
            if(code):
                cur.children[key].set_code(code)
            if(comment != None and cur.children[key].fullpath == comment['path']):
                cur.children[key].set_comment(comment)
        cur = cur.children[key]
        # if(cur.type == "directory"):
        #     is_dir = True
    # на конце: если это директория — пометим directory, иначе — file/form/vuln
    if (is_dir):
        cur.type = "directory"
    else:
        # если путь указывает файл (заканчивается не на '/'), пометим соответствующим типом
        cur.type = typ if typ in ("file", "form", "vuln") else "file"


def build_tree(site: Dict[str, Any]) -> List[Dict[str, Any]]:
    root = Node("/", "/", "directory")
    
    # добавим web_comments
    if(site["web_comments"] != None):
        for c in site.get("web_comments", []):
            path = c.get("path", "")
            # если путь выглядит как директория (заканчивается на '/'), это directory node
            if(path):
                if path.endswith("/"):
                    insert(root, path, "directory", None, c)
                else:
                    insert(root, path, "file", None, c)

    # добавим web_pages
    if(site["web_pages"] != None):
        for p in site.get("web_pages", []):
            path = p.get("path", "")
            # если путь выглядит как директория (заканчивается на '/'), это directory node
            if(path):
                if path.endswith("/"):
                    insert(root, path, "directory")
                else:
                    insert(root, path, "file", p.get("code", ""))
    
    # добавим web_forms (пометим как form; формы могут быть в директории или как файл)
    if(site["web_forms"] != None):
        for f in site.get("web_forms", []):
            path = f.get("path", "")
            # если форма указывает на директорию (часто формы расположены в папке), пометим children directory + form-file
            # Здесь пометим конечный узел типом "form"
            if(path):
                insert(root, path, "form")
    
    # добавим web_vulns (пометим как vuln)
    if(site["web_vulns"] != None):
        for v in site.get("web_vulns", []):
            path = v.get("path", "")
            # если путь выглядит как директория (заканчивается на '/'), это directory node
            if(path):
                if path.endswith("/"):
                    insert(root, path, "directory")
                else:
                    if(directory_exists(root.children['/'], path) == False):
                        insert(root, path, "vuln")

                
        # if(path):
        #     insert(root, path, "vuln")
    # результат — список корневых детей (обычно только "/")
    return [child.to_dict() for key, child in sorted(root.children.items())]


def directory_exists(root, fullpath):
    if fullpath == '/':
        return root.type == 'directory'
    
    # Прямой поиск в детях текущего узла
    if fullpath in root.children:
        return root.children[fullpath].type == 'directory'
    
    # Рекурсивный поиск во всех дочерних директориях
    for child_path, child_node in root.children.items():
        if child_node.type == 'directory' and fullpath.startswith(child_path + '/'):
            return directory_exists(child_node, fullpath)
    
    return False