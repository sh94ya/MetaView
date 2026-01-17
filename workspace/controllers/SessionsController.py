import ipaddress
import json
from sqlalchemy.orm import Session
from datetime import datetime
from workspace.controllers import HostsController, ServicesController
from workspace.models.migration import (
    Hosts, Events, Tags, HostsTags, Services, Notes, Loots,
    MetasploitCredentialCores, MetasploitCredentialLogins, MetasploitCredentialRealms, MetasploitCredentialPublics, MetasploitCredentialPrivates,
    MetasploitCredentialOriginCrackedPasswords, MetasploitCredentialOriginSessions, MetasploitCredentialOriginServices,
    MetasploitCredentialOriginImports, MetasploitCredentialOriginManuals,
    Sessions as MetasploitSessions, SessionEvents ,Vulns, VulnDetails, VulnAttempts, VulnsRefs, Refs, Users,
    MetasploitCredentialCoreComments, MetasploitCredentialLoginComments, Comments as MetasploitComments,
    WebSites, WebPages, WebVulns, WebForms)

import workspace.logger as logging
from flask import jsonify

from sqlalchemy import and_, func, distinct
from sqlalchemy.orm import aliased
from sqlalchemy.dialects import postgresql
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.sql import label

from workspace.controllers.Parsers import apply_dynamic_filters

log = logging.getLogger()


def get_sessions (db_session: Session, workspace_id: int, arg) -> dict:
    try:
        host_json = (
            func.jsonb_build_object('id', Hosts.id, 'address', Hosts.address, 'purpose', Hosts.purpose, 'os_family', Hosts.os_family)
        ).label('host')

        q = (
                db_session.query(
                MetasploitSessions.id,
                host_json,
                MetasploitSessions.stype,
                MetasploitSessions.via_exploit,
                MetasploitSessions.via_payload,
            )
            .select_from(MetasploitSessions)
            .outerjoin(Hosts, Hosts.id == MetasploitSessions.host_id)
            .outerjoin(Services, Services.host_id == Hosts.id)
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
            .outerjoin(MetasploitCredentialOriginSessions, MetasploitCredentialOriginSessions.session_id == MetasploitSessions.id)
            .outerjoin(Vulns, Vulns.host_id == Hosts.id)
            .outerjoin(VulnDetails, VulnDetails.vuln_id == Vulns.id)
            .outerjoin(VulnAttempts, VulnAttempts.vuln_id == Vulns.id)
            .outerjoin(VulnsRefs, VulnsRefs.vuln_id == Vulns.id)
            .outerjoin(Refs, Refs.id == VulnsRefs.ref_id)
            .outerjoin(WebSites, WebSites.service_id == Services.id)
            .outerjoin(WebPages, WebPages.web_site_id == WebSites.id)
            .outerjoin(WebForms, WebForms.web_site_id == WebSites.id)
            .outerjoin(WebVulns, WebVulns.web_site_id == WebSites.id)
            .filter(Hosts.workspace_id == workspace_id)
            .group_by(MetasploitSessions.id)
            .group_by(Hosts.id)
            .group_by(MetasploitSessions.stype)
            .group_by(MetasploitSessions.via_exploit)
            .group_by(MetasploitSessions.via_payload)
            .order_by(MetasploitSessions.id)
        )

        q = apply_dynamic_filters(q, arg)
        return jsonify([dict(r) for r in q.all()]), 200  
    except Exception as e:
        log.error("Error in controllers `SessionsController` function  `get_sessions`. Details - {0}".format(str(e)))
        return {"status": 500, "message": str(e) }
    

def get_session_data (db_session: Session, workspace_id: int, session_id: int) -> dict:
    try:
        q = (
                db_session.query(
                MetasploitSessions
            )
            .outerjoin(SessionEvents, SessionEvents.session_id == MetasploitSessions.id)
            .outerjoin(Hosts, Hosts.id == MetasploitSessions.host_id)
            .outerjoin(Services, Services.host_id == Hosts.id)
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
            .outerjoin(MetasploitCredentialOriginSessions, MetasploitCredentialOriginSessions.session_id == MetasploitSessions.id)
            .outerjoin(Vulns, Vulns.host_id == Hosts.id)
            .outerjoin(VulnDetails, VulnDetails.vuln_id == Vulns.id)
            .outerjoin(VulnAttempts, VulnAttempts.vuln_id == Vulns.id)
            .outerjoin(VulnsRefs, VulnsRefs.vuln_id == Vulns.id)
            .outerjoin(Refs, Refs.id == VulnsRefs.ref_id)
            .outerjoin(WebSites, WebSites.service_id == Services.id)
            .outerjoin(WebPages, WebPages.web_site_id == WebSites.id)
            .outerjoin(WebForms, WebForms.web_site_id == WebSites.id)
            .outerjoin(WebVulns, WebVulns.web_site_id == WebSites.id)
            .filter(Hosts.workspace_id == workspace_id)
            .filter(MetasploitSessions.id == session_id)
            .group_by(MetasploitSessions.id)
            .order_by(MetasploitSessions.id)
        )
        session = q.first()
        if session:
            session = session.to_dict()
        return {"status": 200, "data": json.dumps(session, indent=4, sort_keys=True, default=str)}
        # return jsonify([dict(r) for r in q.all()]), 200  
    except Exception as e:
        log.error("Error in controllers `SessionsController` function  `get_session_data`. Details - {0}".format(str(e)))
        return {"status": 500, "message": str(e) }
    

def get_session_events (db_session: Session, workspace_id: int, session_id: int) -> dict:
    try:

        q = (
                db_session.query(
                SessionEvents.id,
                SessionEvents.etype,
                func.encode(SessionEvents.command, 'escape').label('command'),
                func.encode(SessionEvents.output, 'escape').label('output'),
            )
            .select_from(MetasploitSessions)
            .outerjoin(SessionEvents, SessionEvents.session_id == MetasploitSessions.id)
            .outerjoin(Hosts, Hosts.id == MetasploitSessions.host_id)
            .outerjoin(Services, Services.host_id == Hosts.id)
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
            .outerjoin(MetasploitCredentialOriginSessions, MetasploitCredentialOriginSessions.session_id == MetasploitSessions.id)
            .outerjoin(Vulns, Vulns.host_id == Hosts.id)
            .outerjoin(VulnDetails, VulnDetails.vuln_id == Vulns.id)
            .outerjoin(VulnAttempts, VulnAttempts.vuln_id == Vulns.id)
            .outerjoin(VulnsRefs, VulnsRefs.vuln_id == Vulns.id)
            .outerjoin(Refs, Refs.id == VulnsRefs.ref_id)
            .outerjoin(WebSites, WebSites.service_id == Services.id)
            .outerjoin(WebPages, WebPages.web_site_id == WebSites.id)
            .outerjoin(WebForms, WebForms.web_site_id == WebSites.id)
            .outerjoin(WebVulns, WebVulns.web_site_id == WebSites.id)
            .filter(Hosts.workspace_id == workspace_id)
            .filter(MetasploitSessions.id == session_id)
            .group_by(SessionEvents.id)
            .order_by(SessionEvents.id)
        )

        return jsonify([dict(r) for r in q.all()]), 200  
    except Exception as e:
        log.error("Error in controllers `SessionsController` function  `get_session_events`. Details - {0}".format(str(e)))
        return {"status": 500, "message": str(e) }
    

def get_count (db_session: Session, workspace_id: int, arg) -> dict:
    try:
        q = (
                db_session.query(
                func.count(distinct(MetasploitSessions.id)).label('sessions')
            )
            .select_from(MetasploitSessions)
            .outerjoin(Hosts, Hosts.id == MetasploitSessions.host_id)
            .outerjoin(Services, Services.host_id == Hosts.id)
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
            .outerjoin(MetasploitCredentialOriginSessions, MetasploitCredentialOriginSessions.session_id == MetasploitSessions.id)
            .outerjoin(Vulns, Vulns.host_id == Hosts.id)
            .outerjoin(VulnDetails, VulnDetails.vuln_id == Vulns.id)
            .outerjoin(VulnAttempts, VulnAttempts.vuln_id == Vulns.id)
            .outerjoin(VulnsRefs, VulnsRefs.vuln_id == Vulns.id)
            .outerjoin(Refs, Refs.id == VulnsRefs.ref_id)
            .outerjoin(WebSites, WebSites.service_id == Services.id)
            .outerjoin(WebPages, WebPages.web_site_id == WebSites.id)
            .outerjoin(WebForms, WebForms.web_site_id == WebSites.id)
            .outerjoin(WebVulns, WebVulns.web_site_id == WebSites.id)
            .filter(Hosts.workspace_id == workspace_id)
        )
        
        q = apply_dynamic_filters(q, arg)
        return len([dict(r) for r in q.all()]) 
    except Exception as e:
        log.error("Error in controllers `SessionsController` function  `get_count`. Details - {0}".format(str(e)))
        return {"status": 500, "message": str(e) }