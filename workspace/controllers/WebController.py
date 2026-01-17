import ipaddress
from sqlalchemy.orm import Session
from datetime import datetime
from workspace.controllers import HostsController, ServicesController
from workspace.models.migration import (
    Hosts, Events, Tags, HostsTags, Services, Notes, Loots,
    MetasploitCredentialCores, MetasploitCredentialLogins, MetasploitCredentialRealms, MetasploitCredentialPublics, MetasploitCredentialPrivates,
    MetasploitCredentialOriginCrackedPasswords, MetasploitCredentialOriginSessions, MetasploitCredentialOriginServices,
    MetasploitCredentialOriginImports, MetasploitCredentialOriginManuals,
    Sessions as MetasploitSessions, Vulns, VulnDetails, VulnAttempts, VulnsRefs, Refs, Users,
    MetasploitCredentialCoreComments, MetasploitCredentialLoginComments, Comments as MetasploitComments,
    WebSites, WebPages, WebVulns, WebForms, WebComments)

import workspace.logger as logging
from flask import jsonify

from sqlalchemy import and_, or_, func, distinct, select, exists
from sqlalchemy.orm import aliased
from sqlalchemy.dialects import postgresql
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.sql import label

from workspace.controllers.Parsers import apply_dynamic_filters
from workspace.controllers.TreeWebUtils import build_tree

log = logging.getLogger()


def getDataSites (db_session: Session, workspace_id: int, arg) -> dict:
    try:
        host_json = (
            func.jsonb_build_object('id', Hosts.id, 'address', Hosts.address, 'purpose', Hosts.purpose, 'os_family', Hosts.os_family)
        ).label('host')
        service_json = (
            func.jsonb_build_object('id', Services.id, 'port', Services.port, 'proto', Services.proto, 'name', Services.name)
        ).label('service')

        q = (
                db_session.query(
                WebSites.id,
                host_json,
                service_json,
                WebSites.vhost,
                WebSites.comments,
                WebSites.options,
                func.count(distinct(WebPages.id)).label('pages'),
                func.count(distinct(WebForms.id)).label('forms'),
                func.count(distinct(WebVulns.id)).label('vulns'),
            )
            .select_from(WebSites)
            .outerjoin(Services, Services.id == WebSites.service_id)
            .outerjoin(Hosts, Hosts.id == Services.host_id)
            .outerjoin(HostsTags, HostsTags.host_id == Hosts.id)
            .outerjoin(Tags, Tags.id == HostsTags.tag_id)
            .outerjoin(Notes, Notes.host_id == Hosts.id)
            .outerjoin(MetasploitCredentialLogins, MetasploitCredentialLogins.service_id == Services.id)
            .outerjoin(MetasploitCredentialCores, MetasploitCredentialCores.id == MetasploitCredentialLogins.core_id)
            .outerjoin(MetasploitCredentialRealms, MetasploitCredentialRealms.id == MetasploitCredentialCores.realm_id)
            .outerjoin(MetasploitCredentialPrivates, MetasploitCredentialPrivates.id == MetasploitCredentialCores.private_id)
            .outerjoin(MetasploitCredentialPublics, MetasploitCredentialPublics.id == MetasploitCredentialCores.public_id)
            .outerjoin(MetasploitCredentialOriginCrackedPasswords, MetasploitCredentialOriginCrackedPasswords.metasploit_credential_core_id == MetasploitCredentialCores.public_id)
            .outerjoin(MetasploitCredentialOriginServices, MetasploitCredentialOriginServices.service_id == Services.id)
            .outerjoin(MetasploitSessions, MetasploitSessions.host_id == Hosts.id)
            .outerjoin(MetasploitCredentialOriginSessions, MetasploitCredentialOriginSessions.session_id == MetasploitSessions.id)
            .outerjoin(Vulns, Vulns.host_id == Hosts.id)
            .outerjoin(VulnDetails, VulnDetails.vuln_id == Vulns.id)
            .outerjoin(VulnAttempts, VulnAttempts.vuln_id == Vulns.id)
            .outerjoin(VulnsRefs, VulnsRefs.vuln_id == Vulns.id)
            .outerjoin(Refs, Refs.id == VulnsRefs.ref_id)
            .outerjoin(WebPages, WebPages.web_site_id == WebSites.id)
            .outerjoin(WebForms, WebForms.web_site_id == WebSites.id)
            .outerjoin(WebVulns, WebVulns.web_site_id == WebSites.id)
            .filter(Hosts.workspace_id == workspace_id)
            .group_by(WebSites.id)
            .group_by(Hosts.id)
            .group_by(Services.id)
            .order_by(WebSites.id)
        )

        if(str(type(arg)) == "<class 'dict'>" and arg['site_id']):
            q = q.filter(WebSites.id == int(arg['site_id']))
        else:
            q = apply_dynamic_filters(q, arg)
        # 
        return jsonify([dict(r) for r in q.all()]), 200  
    except Exception as e:
        log.error("Error in controllers `WebController` function  `getDataSites`. Details - {0}".format(str(e)))
        return {"status": 500, "message": str(e) }


def getDataSiteStruct (db_session: Session, workspace_id: int, site_id: int) -> dict:
    try:
        Pagess_subquery = (
            select(
                func.coalesce(
                    func.array_agg(
                        func.jsonb_build_object(
                            'id', WebPages.id,
                            'path', WebPages.path,
                            'code', WebPages.code,
                        )
                    ),
                )
            )
            .where(
                WebPages.web_site_id == WebSites.id,
            )
            .scalar_subquery()
        )
        
        # Подзапрос для web_Formss
        Formss_subquery = (
            select(
                func.coalesce(
                    func.array_agg(
                        func.jsonb_build_object(
                            'id', WebForms.id,
                            'path', WebForms.path,
                        )
                    ),
                )
            )
            .where(
                WebForms.web_site_id == WebSites.id,
            )
            .scalar_subquery()
        )
            
        # Подзапрос для web_Vulnss
        Vulnss_subquery = (
            select(
                func.coalesce(
                    func.array_agg(
                        func.jsonb_build_object(
                            'id', WebVulns.id,
                            'path', WebVulns.path,
                        )
                    ),
                )
            )
            .where(
                WebVulns.web_site_id == WebSites.id,
            )
            .scalar_subquery()
        )


        # Подзапрос для web_Vulnss
        Commentss_subquery = (
            select(
                func.coalesce(
                    func.array_agg(
                        func.jsonb_build_object(
                            'id', WebComments.id,
                            'path', WebComments.path,
                            'comment', WebComments.comment,
                        )
                    ),
                )
            )
            .where(
                WebComments.web_site_id == WebSites.id,
            )
            .scalar_subquery()
        )
        
        # Проверка существования записей
        Pagess_exists = select(WebPages.id).where(
            WebPages.web_site_id == WebSites.id,
        ).exists()
        
        Formss_exists = select(WebForms.id).where(
            WebForms.web_site_id == WebSites.id,
        ).exists()
        
        Vulnss_exists = select(WebVulns.id).where(
            WebVulns.web_site_id == WebSites.id,
        ).exists()

        Commentss_exists = select(WebComments.id).where(
            WebComments.web_site_id == WebSites.id,
        ).exists()
        
        # Основной запрос
        stmt = (
            select(
                WebSites.id,
                Pagess_subquery.label("web_pages"),
                Formss_subquery.label("web_forms"),
                Vulnss_subquery.label("web_vulns"),
                Commentss_subquery.label("web_comments")
            )
            .where(WebSites.id == site_id)
            .where(or_(Pagess_exists, Formss_exists, Vulnss_exists, Commentss_exists))
        )
        
        result = db_session.execute(stmt).first()
        site = {
                'web_pages': None,
                'web_forms': None,
                'web_vulns': None,
                'web_comments': None
        }
        
        if result:
            site =  {
                'web_pages': result.web_pages,
                'web_forms': result.web_forms,
                'web_vulns': result.web_vulns,
                'web_comments': result.web_comments
            }

        tree = build_tree(site)
        return jsonify([dict(r) for r in tree]), 200  
    except Exception as e:
        log.error("Error in controllers `WebController` function  `getDataSiteStruct`. Details - {0}".format(str(e)))
        return {"status": 500, "message": str(e) }
    

def getDataSitePath (db_session: Session, workspace_id: int, site_id: int, path: str, typePath: str) -> dict:
    try:
        if(typePath != None and str(typePath == 'directory')):
            dirpath = path+"/"
            # Подзапрос для web_Pagess
            Pagess_subquery = (
                select(
                    func.coalesce(
                        func.array_agg(
                            func.jsonb_build_object(
                                'id', WebPages.id,
                                'query', WebPages.query,
                                'code', WebPages.code,
                                'type', 'page'
                            )
                        ),
                    )
                )
                .where(
                    WebPages.web_site_id == WebSites.id,
                    or_(WebPages.path == path, WebPages.path == dirpath)
                )
                .scalar_subquery()
            )
            
            # Подзапрос для web_Formss
            Formss_subquery = (
                select(
                    func.coalesce(
                        func.array_agg(
                            func.jsonb_build_object(
                                'id', WebForms.id,
                                'query', WebForms.query,
                                'method', WebForms.method,
                                'type', 'form'
                            )
                        ),
                    )
                )
                .where(
                    WebForms.web_site_id == WebSites.id,
                    or_(WebForms.path == path, WebForms.path == dirpath)
                )
                .scalar_subquery()
            )
            
            # Подзапрос для web_Vulnss
            Vulnss_subquery = (
                select(
                    func.coalesce(
                        func.array_agg(
                            func.jsonb_build_object(
                                'id', WebVulns.id,
                                'query', WebVulns.query,
                                'method', WebVulns.method,
                                'type', 'vuln'
                            )
                        ),
                    )
                )
                .where(
                    WebVulns.web_site_id == WebSites.id,
                    or_(WebVulns.path == path, WebVulns.path == dirpath)
                )
                .scalar_subquery()
            )
            
            # Проверка существования записей
            Pagess_exists = select(WebPages.id).where(
                WebPages.web_site_id == WebSites.id,
                or_(WebPages.path == path, WebPages.path == dirpath)
            ).exists()
            
            Formss_exists = select(WebForms.id).where(
                WebForms.web_site_id == WebSites.id,
                or_(WebForms.path == path, WebForms.path == dirpath)
            ).exists()
            
            Vulnss_exists = select(WebVulns.id).where(
                WebVulns.web_site_id == WebSites.id,
                or_(WebVulns.path == path, WebVulns.path == dirpath)
            ).exists()
        else:
            # Подзапрос для web_Pagess
            Pagess_subquery = (
                select(
                    func.coalesce(
                        func.array_agg(
                            func.jsonb_build_object(
                                'id', WebPages.id,
                                'query', WebPages.query,
                                'code', WebPages.code,
                                'type', 'page'
                            )
                        ),
                    )
                )
                .where(
                    WebPages.web_site_id == WebSites.id,
                    WebPages.path == path
                )
                .scalar_subquery()
            )
            
            # Подзапрос для web_Formss
            Formss_subquery = (
                select(
                    func.coalesce(
                        func.array_agg(
                            func.jsonb_build_object(
                                'id', WebForms.id,
                                'query', WebForms.query,
                                'method', WebForms.method,
                                'type', 'form'
                            )
                        ),
                    )
                )
                .where(
                    WebForms.web_site_id == WebSites.id,
                    WebForms.path == path
                )
                .scalar_subquery()
            )
            
            # Подзапрос для web_Vulnss
            Vulnss_subquery = (
                select(
                    func.coalesce(
                        func.array_agg(
                            func.jsonb_build_object(
                                'id', WebVulns.id,
                                'query', WebVulns.query,
                                'method', WebVulns.method,
                                'type', 'vuln'
                            )
                        ),
                    )
                )
                .where(
                    WebVulns.web_site_id == WebSites.id,
                    WebVulns.path == path
                )
                .scalar_subquery()
            )
            
            # Проверка существования записей
            Pagess_exists = select(WebPages.id).where(
                WebPages.web_site_id == WebSites.id,
                WebPages.path == path
            ).exists()
            
            Formss_exists = select(WebForms.id).where(
                WebForms.web_site_id == WebSites.id,
                WebForms.path == path
            ).exists()
            
            Vulnss_exists = select(WebVulns.id).where(
                WebVulns.web_site_id == WebSites.id,
                WebVulns.path == path
            ).exists()
        
        # Основной запрос
        stmt = (
            select(
                WebSites.id,
                Pagess_subquery.label("web_pages"),
                Formss_subquery.label("web_forms"),
                Vulnss_subquery.label("web_vulns")
            )
            .where(WebSites.id == site_id)
            .where(or_(Pagess_exists, Formss_exists, Vulnss_exists))
        )
        
        result = db_session.execute(stmt).first()
        
        if result:
            return {
                'web_pages': result.web_pages,
                'web_forms': result.web_forms,
                'web_vulns': result.web_vulns
            }
        else:
            return {
                'web_pages': None,
                'web_forms': None,
                'web_vulns': None
            }
    except Exception as e:
        log.error("Error in controllers `WebController` function  `getDataSitePath`. Details - {0}".format(str(e)))
        return {"status": 500, "message": str(e) }


def deletePath(db_session: Session, workspace_id: int, site_id: int, path: str) -> dict:
    try:
        pages_to_delete= db_session.query(WebPages.id).\
                        join(WebSites, WebSites.id == WebPages.web_site_id).\
                        join(Services, Services.id == WebSites.service_id).\
                        join(Hosts, Hosts.id == Services.host_id).\
                        filter(Hosts.workspace_id == workspace_id).\
                        filter(WebSites.id == int(site_id)).\
                        filter(WebPages.path.like(path+'%')).\
                        subquery()
        db_session.query(WebPages).filter(WebPages.id.in_(pages_to_delete)).delete(synchronize_session=False)

        forms_to_delete = db_session.query(WebForms.id).\
                            join(WebSites, WebSites.id == WebForms.web_site_id).\
                            join(Services, Services.id == WebSites.service_id).\
                            join(Hosts, Hosts.id == Services.host_id).\
                            filter(Hosts.workspace_id == workspace_id).\
                            filter(WebSites.id == int(site_id)).\
                            filter(WebForms.path.like(path+'%')).\
                            subquery()
        db_session.query(WebForms).filter(WebForms.id.in_(forms_to_delete)).delete(synchronize_session=False)

        vulns_to_delete = db_session.query(WebVulns.id).\
                            join(WebSites, WebSites.id == WebVulns.web_site_id).\
                            join(Services, Services.id == WebSites.service_id).\
                            join(Hosts, Hosts.id == Services.host_id).\
                            filter(Hosts.workspace_id == workspace_id).\
                            filter(WebSites.id == int(site_id)).\
                            filter(WebVulns.path.like(path+'%')).\
                            subquery()
        db_session.query(WebVulns).filter(WebVulns.id.in_(vulns_to_delete)).delete(synchronize_session=False)

        comments_to_delete = db_session.query(WebComments.id).\
                            join(WebSites, WebSites.id == WebComments.web_site_id).\
                            join(Services, Services.id == WebSites.service_id).\
                            join(Hosts, Hosts.id == Services.host_id).\
                            filter(Hosts.workspace_id == workspace_id).\
                            filter(WebSites.id == int(site_id)).\
                            filter(WebComments.path.like(path+'%')).\
                            subquery()
        db_session.query(WebComments).filter(WebComments.id.in_(comments_to_delete)).delete(synchronize_session=False)

        db_session.flush()
        db_session.commit()
        return {'status':200}
    except Exception as e:
        log.error("Error in controllers `WebController` function  `deletePath`. Details - {0}".format(str(e)))
        return {"status": 500, "message": str(e) }


def getDataSitePages (db_session: Session, workspace_id: int, page_id: int) -> dict:
    try:
        q = (
                db_session.query(
                WebPages.id,
                WebPages.path,
                WebPages.auth,
                WebPages.query,
                WebPages.code,
                WebPages.cookie,
                WebPages.ctype,
                WebPages.headers,
                func.encode(WebPages.body, 'escape').label('body'),
                func.encode(WebPages.request, 'escape').label('request'),
            )
            .select_from(WebPages)
            .join(WebSites, WebSites.id == WebPages.web_site_id)
            .filter(WebPages.id == page_id)
        )

        return [dict(r) for r in q.all()][0]
    except Exception as e:
        log.error("Error in controllers `WebController` function  `getDataSitePages`. Details - {0}".format(str(e)))
        return {"status": 500, "message": str(e) }
    

def getDataSiteForms (db_session: Session, workspace_id: int, form_id: int) -> dict:
    try:
        q = (
                db_session.query(
                WebForms.id,
                WebForms.path,
                WebForms.method,
                WebForms.query,
                WebForms.params,
            )
            .select_from(WebForms)
            .join(WebSites, WebSites.id == WebForms.web_site_id)
            .filter(WebForms.id == form_id)
        )

        return [dict(r) for r in q.all()][0]
    except Exception as e:
        log.error("Error in controllers `WebController` function  `getDataSiteForms`. Details - {0}".format(str(e)))
        return {"status": 500, "message": str(e) }
    

def getDataSiteVulns (db_session: Session, workspace_id: int, vuln_id: int) -> dict:
    try:
        q = (
                db_session.query(
                WebVulns.id,
                WebVulns.name,
                WebVulns.category,
                WebVulns.confidence,
                WebVulns.payload,
                WebVulns.path,
                WebVulns.method,
                WebVulns.query,
                WebVulns.params,
                WebVulns.risk,
                WebVulns.description,
                func.encode(WebVulns.proof, 'escape').label('proof'),
                func.encode(WebVulns.request, 'escape').label('request'),
            )
            .select_from(WebVulns)
            .join(WebSites, WebSites.id == WebVulns.web_site_id)
            .filter(WebVulns.id == vuln_id)
        )

        return [dict(r) for r in q.all()][0] 
    except Exception as e:
        log.error("Error in controllers `WebController` function  `getDataSiteVulns`. Details - {0}".format(str(e)))
        return {"status": 500, "message": str(e) }
    

def getDataSiteCountInfo (db_session: Session, workspace_id: int, site_id: int, path: str) -> dict:
    try:
        q = (
                db_session.query(
                WebSites.id,
                func.count(distinct(WebPages.id)).label('pages'),
                func.count(distinct(WebForms.id)).label('forms'),
                func.count(distinct(WebVulns.id)).label('vulns')
            )
            .select_from(WebSites)
            .outerjoin(Services, Services.id == WebSites.service_id)
            .outerjoin(Hosts, Hosts.id == Services.host_id)
            .outerjoin(WebPages, WebPages.web_site_id == WebSites.id)
            .outerjoin(WebForms, WebForms.web_site_id == WebSites.id)           
            .outerjoin(WebVulns, WebVulns.web_site_id == WebSites.id)
            .filter(Hosts.workspace_id == workspace_id)
            .filter(WebSites.id == site_id)
            .filter(or_(WebPages.path.like(path),WebForms.path.like(path),WebVulns.path.like(path)))
            .group_by(WebSites.id)
        )

        return jsonify([dict(r) for r in q.all()][0]), 200  
    except Exception as e:
        log.error("Error in controllers `WebController` function  `getDataSiteCountInfo`. Details - {0}".format(str(e)))
        return {"status": 500, "message": str(e) }
    

#Добавить запись
def add_card_info(db_session: Session, site_id: int, type_obj: str, data: dict):
    try:
        if(type_obj == 'Page'):
            obj = WebPages(site_id, data['fullpath'])
            db_session.add(obj)
            obj.update_state(data)
        if(type_obj == 'Form'):  
            obj = WebForms(site_id, data['fullpath'])
            db_session.add(obj)
            obj.update_state(data)
        if(type_obj == 'Vuln'): 
            obj = WebVulns(site_id, data['fullpath'])
            db_session.add(obj)
            obj.update_state(data)

        db_session.flush()
        
        db_session.commit()
        return {'status':200, 'id': obj.id}
    except Exception as e:
        log.error("Error in controllers `WebController` function  `add_card_info`. Details - {0}".format(str(e)))
        return {"status": 501, "message": str(e)}        
    

#Добавить запись
def addSiteComment(db_session: Session, site_id: int, data: dict):
    try:
        comment = db_session.query(WebComments).filter_by(web_site_id = int(site_id), path = data['fullpath']).first()

        if(comment):
            comment.comment =  data['comment']['comment']
        else:
            comment = WebComments(site_id, data['fullpath'], data['comment']['comment'])   
            db_session.add(comment)

        db_session.flush()
        
        db_session.commit()
        return {'status': 200, 'id': comment.id}
    except Exception as e:
        log.error("Error in controllers `WebController` function  `addSiteComment`. Details - {0}".format(str(e)))
        return {"status": 501, "message": str(e)}       


#Edit Page
def editPage(db_session: Session, workspace_id: int, data: dict):
    try:
        page = db_session.query(WebPages).join(WebSites, WebSites.id == WebPages.web_site_id).join(Services, Services.id == WebSites.service_id).join(Hosts, Hosts.id == Services.host_id).filter(Hosts.workspace_id == workspace_id).filter(WebPages.id == int(data['id'])).first()

        if(page):
            page.update_state(data)
            db_session.flush()
            db_session.commit()
            return {'status':200 }
        else:
            return {'status':510, 'message': "Page is not exist" }
    except Exception as e:
        log.error("Error in controllers `WebController` function  `editPage`. Details - {0}".format(str(e)))
        return {"status": 501, "message": str(e)}        
    

#Edit Form
def editForm(db_session: Session, workspace_id: int, data: dict):
    try:
        form = db_session.query(WebForms).join(WebSites, WebSites.id == WebForms.web_site_id).join(Services, Services.id == WebSites.service_id).join(Hosts, Hosts.id == Services.host_id).filter(Hosts.workspace_id == workspace_id).filter(WebForms.id == int(data['id'])).first()

        if(form):
            form.update_state(data)
            db_session.flush()
            db_session.commit()
            return {'status':200 }
        else:
            return {'status':510, 'message': "Form is not exist" }
    except Exception as e:
        log.error("Error in controllers `WebController` function  `editForm`. Details - {0}".format(str(e)))
        return {"status": 501, "message": str(e)}     
    

#Edit Vuln
def editVuln(db_session: Session, workspace_id: int, data: dict):
    try:
        vuln = db_session.query(WebVulns).join(WebSites, WebSites.id == WebVulns.web_site_id).join(Services, Services.id == WebSites.service_id).join(Hosts, Hosts.id == Services.host_id).filter(Hosts.workspace_id == workspace_id).filter(WebVulns.id == int(data['id'])).first()

        if(vuln):
            vuln.update_state(data)
            db_session.flush()
            db_session.commit()
            return {'status':200 }
        else:
            return {'status':510, 'message': "Vuln is not exist" }
    except Exception as e:
        log.error("Error in controllers `WebController` function  `editVuln`. Details - {0}".format(str(e)))
        return {"status": 501, "message": str(e)}


#Del Page
def delPage(db_session: Session, workspace_id: int, page_id: int):
    try:
        page = db_session.query(WebPages).join(WebSites, WebSites.id == WebPages.web_site_id).join(Services, Services.id == WebSites.service_id).join(Hosts, Hosts.id == Services.host_id).filter(Hosts.workspace_id == workspace_id).filter(WebPages.id == page_id).first()

        if(page):
            db_session.query(WebPages).filter(WebPages.id == page_id).delete()
            db_session.flush()
            db_session.commit()
            return {'status':200 }
        else:
            return {'status':510, 'message': "Form is not exist" }
    except Exception as e:
        log.error("Error in controllers `WebController` function  `delFrom`. Details - {0}".format(str(e)))
        return {"status": 501, "message": str(e)} 


#Del Form
def delForm(db_session: Session, workspace_id: int, form_id: int):
    try:
        form = db_session.query(WebForms).join(WebSites, WebSites.id == WebForms.web_site_id).join(Services, Services.id == WebSites.service_id).join(Hosts, Hosts.id == Services.host_id).filter(Hosts.workspace_id == workspace_id).filter(WebForms.id == form_id).first()

        if(form):
            db_session.query(WebForms).filter(WebForms.id == form_id).delete()
            db_session.flush()
            db_session.commit()
            return {'status':200 }
        else:
            return {'status':510, 'message': "Form is not exist" }
    except Exception as e:
        log.error("Error in controllers `WebController` function  `delFrom`. Details - {0}".format(str(e)))
        return {"status": 501, "message": str(e)} 



#Del Vuln
def delVuln(db_session: Session, workspace_id: int, vuln_id: int):
    try:
        vuln = db_session.query(WebVulns).join(WebSites, WebSites.id == WebVulns.web_site_id).join(Services, Services.id == WebSites.service_id).join(Hosts, Hosts.id == Services.host_id).filter(Hosts.workspace_id == workspace_id).filter(WebVulns.id == vuln_id).first()

        if(vuln):
            db_session.query(WebVulns).filter(WebVulns.id == vuln_id).delete()
            db_session.flush()
            db_session.commit()
            return {'status':200 }
        else:
            return {'status':510, 'message': "Vuln is not exist" }
    except Exception as e:
        log.error("Error in controllers `WebController` function  `delVuln`. Details - {0}".format(str(e)))
        return {"status": 501, "message": str(e)}        


#Добавить запись
def addSite(db_session: Session, workspace_id: int, data: dict):
    try:
        host = None
        host_id = None
        service_id = None

        #Get host id
        if(str(type(data['host'])) == "<class 'dict'>"):
           host_id = data['host']['id']
        if(str(type(data['host'])) == "<class 'int'>"):
            host_id = data['host']
        else:
            host_id = HostsController.get_host_id(db_session, workspace_id, data['host'])
        
        if(str(type(host_id)) == "<class 'int'>"):
            host = db_session.query(func.jsonb_build_object('id', Hosts.id, 'address', Hosts.address, 'purpose', Hosts.purpose, 'os_family', Hosts.os_family)).filter_by(workspace_id = int(workspace_id), id = host_id).first()
            host= dict(host[0])
        
        data['host_id'] = host_id

        #Get services id
        if(str(type(data['service'])) == "<class 'dict'>"):
            service_id = data['service']['id']

        if(str(type(data['service'])) == "<class 'int'>"):
            service_id = data['service'] 
            
        site = WebSites(service_id)
        db_session.add(site)
        site.update_state(data)
        db_session.flush()
        
        db_session.commit()
        return {'status':200, 'id': site.id, "created_at": site.created_at.strftime("%d.%m.%Y"), "updated_at": site.updated_at.strftime("%d.%m.%Y") }
    except Exception as e:
        log.error("Error in controllers `WebController` function  `addSite`. Details - {0}".format(str(e)))
        return {"status": 501, "message": str(e)}
    

#Редактировать запись
def editSite(db_session: Session, workspace_id: int, data: dict):
    try:
        host = None
        host_id = None
        service_id = None
        #Get host id
        if(str(type(data['host'])) == "<class 'dict'>"):
           host_id = data['host']['id']
        else:
            host_id = HostsController.get_host_id(db_session, workspace_id, data['host'])
        
        if(str(type(host_id)) == "<class 'int'>"):
            host = db_session.query(func.jsonb_build_object('id', Hosts.id, 'address', Hosts.address, 'purpose', Hosts.purpose, 'os_family', Hosts.os_family)).filter_by(workspace_id = int(workspace_id), id = host_id).first()
            host= dict(host[0])
        
        data['host_id'] = host_id

        #Get services id
        if(str(type(data['service'])) == "<class 'dict'>"):
           service_id = data['service']['id']
        else:
            if(data['service'] != None):
                service_id = ServicesController.get_service_id(workspace_id, data['service']['proto'], data['service']['name'], data['service']['port'], host['address'])
        data['service_id'] = service_id

        site = db_session.query(WebSites).filter_by( id = data['id']).first()
        
        for key in list(data.keys()):
            if (key != 'id' and key != 'vhost' and key != 'comments' and key != 'options'):
                del data[key]

        site.update_state(data)
        db_session.flush()
        
        db_session.commit()
        return {'status':200, "id":site.id, "service": service_id, "host": host, "updated_at": site.updated_at.strftime("%d.%m.%Y") }
    except Exception as e:
        log.error("Error in controllers `WebController` function  `editSite`. Details - {0}".format(str(e)))
        return {"status": 501, "message": str(e)}
    

def get_count (db_session: Session, workspace_id: int, arg) -> dict:
    try:
        q = (
                db_session.query(
                func.count(distinct(WebSites.id)).label('web')
            )
            .select_from(WebSites)
            .outerjoin(Services, Services.id == WebSites.service_id)
            .outerjoin(Hosts, Hosts.id == Services.host_id)
            .outerjoin(HostsTags, HostsTags.host_id == Hosts.id)
            .outerjoin(Tags, Tags.id == HostsTags.tag_id)
            .outerjoin(Notes, Notes.host_id == Hosts.id)
            .outerjoin(MetasploitCredentialLogins, MetasploitCredentialLogins.service_id == Services.id)
            .outerjoin(MetasploitCredentialCores, MetasploitCredentialCores.id == MetasploitCredentialLogins.core_id)
            .outerjoin(MetasploitCredentialRealms, MetasploitCredentialRealms.id == MetasploitCredentialCores.realm_id)
            .outerjoin(MetasploitCredentialPrivates, MetasploitCredentialPrivates.id == MetasploitCredentialCores.private_id)
            .outerjoin(MetasploitCredentialPublics, MetasploitCredentialPublics.id == MetasploitCredentialCores.public_id)
            .outerjoin(MetasploitCredentialOriginCrackedPasswords, MetasploitCredentialOriginCrackedPasswords.metasploit_credential_core_id == MetasploitCredentialCores.public_id)
            .outerjoin(MetasploitCredentialOriginServices, MetasploitCredentialOriginServices.service_id == Services.id)
            .outerjoin(MetasploitSessions, MetasploitSessions.host_id == Hosts.id)
            .outerjoin(MetasploitCredentialOriginSessions, MetasploitCredentialOriginSessions.session_id == MetasploitSessions.id)
            .outerjoin(Vulns, Vulns.host_id == Hosts.id)
            .outerjoin(VulnDetails, VulnDetails.vuln_id == Vulns.id)
            .outerjoin(VulnAttempts, VulnAttempts.vuln_id == Vulns.id)
            .outerjoin(VulnsRefs, VulnsRefs.vuln_id == Vulns.id)
            .outerjoin(Refs, Refs.id == VulnsRefs.ref_id)
            .outerjoin(WebPages, WebPages.web_site_id == WebSites.id)
            .outerjoin(WebForms, WebForms.web_site_id == WebSites.id)
            .outerjoin(WebVulns, WebVulns.web_site_id == WebSites.id)
            .filter(Hosts.workspace_id == workspace_id)
            .group_by(WebSites.id)
            .group_by(Hosts.id)
            .group_by(Services.id)
            .group_by(Vulns.id)
            .order_by(Hosts.address)
        )

        q = apply_dynamic_filters(q, arg)
        return len([dict(r) for r in q.all()]) 
    except Exception as e:
        log.error("Error in controllers `WebController` function  `get_count`. Details - {0}".format(str(e)))
        return {"status": 500, "message": str(e) }