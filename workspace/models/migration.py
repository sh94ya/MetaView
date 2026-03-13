from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, Float
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy.dialects.postgresql import INET, BYTEA
from sqlalchemy import MetaData
from datetime import datetime

metadata_obj = MetaData(schema="public")
Base = declarative_base(metadata=metadata_obj)

#Создание таблиц в БД
def create_tables(engine):
    Base.metadata.create_all(engine)

class ApiKeys(Base):
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True)
    token = Column(String)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)


class ArInternalMetadata(Base):
    __tablename__ = "ar_internal_metadata"

    key = Column(String, primary_key=True)
    value = Column(String)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)


class AsyncCallbacks(Base):
    __tablename__ = "async_callbacks"

    id = Column(Integer, primary_key=True)
    uuid = Column(String, nullable=False)
    timestamp = Column(Integer, nullable=False)
    listener_uri = Column(String)
    target_host = Column(String)
    target_port = Column(String)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)


class AutomaticExploitationMatchResult(Base):
    __tablename__ = "automatic_exploitation_match_results"

    id = Column(Integer, primary_key=True)
    match_id = Column(Integer)
    run_id = Column(Integer)
    state = Column(String, nullable=False)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)


class AutomaticExploitationMatchSets(Base):
    __tablename__ = "automatic_exploitation_match_sets"

    id = Column(Integer, primary_key=True)
    workspace_id = Column(Integer)
    user_id = Column(Integer)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)


class AutomaticExploitationMatches(Base):
    __tablename__ = "automatic_exploitation_matches"

    id = Column(Integer, primary_key=True)
    module_detail_id = Column(Integer)
    state = Column(String)
    nexpose_data_vulnerability_definition_id = Column(Integer)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)
    match_set_id = Column(Integer)
    matchable_type = Column(String)
    matchable_id = Column(Integer)
    module_fullname = Column(String)


class AutomaticExploitationRuns(Base):
    __tablename__ = "automatic_exploitation_runs"

    id = Column(Integer, primary_key=True)
    workspace_id = Column(Integer)
    user_id = Column(Integer)
    match_set_id = Column(Integer)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)


class Clients(Base):
    __tablename__ = "clients"

    id = Column(Integer, primary_key=True)
    host_id = Column(Integer)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)
    ua_string = Column(String, nullable=False)
    ua_name = Column(String)
    ua_ver = Column(String)


class CredentialCoresTasks(Base):
    __tablename__ = "credential_cores_tasks"

    core_id = Column(Integer, primary_key=True)
    task_id = Column(Integer, primary_key=True)


class CredentialLoginsTasks(Base):
    __tablename__ = "credential_logins_tasks"

    core_id = Column(Integer, primary_key=True)
    task_id = Column(Integer, primary_key=True)


class Creds(Base):
    __tablename__ = "creds"

    id = Column(Integer, primary_key=True)
    service_id = Column(Integer, nullable=False)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)
    user = Column(String)
    passw = Column(String)
    active = Column(Boolean, default=True)
    proof = Column(String)
    ptype = Column(String)
    source_id = Column(Integer)
    source_type = Column(String)


class Events(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True)
    workspace_id = Column(Integer)
    host_id = Column(Integer)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)
    name = Column(String)
    critical = Column(Boolean)
    seen = Column(Boolean)
    username = Column(String)
    info = Column(String)


class ExploitAttempts(Base):
    __tablename__ = "exploit_attempts"

    id = Column(Integer, primary_key=True)
    host_id = Column(Integer)
    service_id = Column(Integer)
    vuln_id = Column(Integer)
    attempted_at = Column(DateTime)
    exploited = Column(Boolean)
    fail_reason = Column(String)
    username = Column(String)
    module = Column(String)
    session_id = Column(Integer)
    loot_id = Column(Integer)
    port = Column(Integer)
    proto = Column(String)
    fail_detail = Column(String)


class ExploitedHosts(Base):
    __tablename__ = "exploited_hosts"

    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, nullable=False)
    service_id = Column(Integer)
    session_uuid = Column(String)
    name = Column(String)
    payload = Column(String)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)


class HostDetails(Base):
    __tablename__ = "host_details"

    id = Column(Integer, primary_key=True)
    host_id = Column(Integer)
    nx_console_id = Column(Integer)
    nx_device_id = Column(Integer)
    src = Column(String)
    nx_site_name = Column(String)
    nx_site_importance = Column(String)
    nx_scan_template = Column(String)
    nx_risk_score = Column(Float)


class Hosts(Base):
    __tablename__ = "hosts"

    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime, default=datetime.now())
    updated_at = Column(DateTime, default=datetime.now())
    address = Column(INET, nullable=False)
    mac = Column(String)
    comm = Column(String)
    name = Column(String)
    state = Column(String)
    os_name = Column(String)
    os_flavor = Column(String)
    os_sp = Column(String)
    os_lang = Column(String)
    arch = Column(String)
    workspace_id = Column(Integer, nullable=False)
    purpose = Column(String)
    info = Column(String)
    comments = Column(String)
    scope = Column(String)
    virtual_host = Column(String)
    note_count = Column(Integer, default=0)
    vuln_count = Column(Integer, default=0)
    service_count = Column(Integer, default=0)
    host_detail_count = Column(Integer, default=0)
    exploit_attempt_count = Column(Integer, default=0)
    cred_count = Column(Integer, default=0)
    detected_arch = Column(String)
    os_family = Column(String)

    def __init__(self, workspace_id, address):
        self.workspace_id = int(workspace_id)
        self.address = (address)

    def update_state(self, data):
        for key in list(data.keys()):
            if (key != 'id' and hasattr(self, key)):
                setattr(self, key, data[key])
        self.updated_at = datetime.now() 


class HostsTags(Base):
    __tablename__ = "hosts_tags"

    id = Column(Integer, primary_key=True)
    host_id = Column(Integer)
    tag_id = Column(Integer)

    def __init__(self, host_id, tag_id):
        self.host_id = int(host_id)
        self.tag_id = int(tag_id)


class Comments(Base):
    __tablename__ = "comments"

    id = Column(Integer, primary_key=True)
    comment = Column(String, default=None)
    user_id = Column(Integer, default=None)
    created_at = Column(DateTime, default=datetime.now())
    updated_at = Column(DateTime, default=datetime.now())

    def __init__(self, comment):
        self.comment = str(comment)
    
    def update_state(self, data):
        for key in list(data.keys()):
            if (key != 'id' and hasattr(self, key)):
                setattr(self, key, data[key])
        self.updated_at = datetime.now() 


class Listeners(Base):
    __tablename__ = "listeners"

    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)
    workspace_id = Column(Integer, nullable=False, default=1)
    task_id = Column(Integer)
    enabled = Column(Boolean, default=True)
    owner = Column(String)
    payload = Column(String)
    address = Column(String)
    port = Column(Integer)
    options = Column(BYTEA)
    macro = Column(String)


class Loots(Base):
    __tablename__ = "loots"

    id = Column(Integer, primary_key=True)
    workspace_id = Column(Integer, nullable=False, default=1)
    host_id = Column(Integer)
    service_id = Column(Integer)
    ltype = Column(String, default='')
    path = Column(String, default='')
    data = Column(String, default='')
    created_at = Column(DateTime, nullable=False, default=datetime.now())
    updated_at = Column(DateTime, nullable=False, default=datetime.now())
    content_type = Column(String, default='')
    name = Column(String)
    info = Column(String)
    module_run_id = Column(Integer)

    def __init__(self, workspace_id):
        self.workspace_id = int(workspace_id)

    def update_state(self, data):
        for key in list(data.keys()):
            if (key != 'id' and hasattr(self, key)):
                setattr(self, key, data[key])
        self.updated_at = datetime.now() 


class Macros(Base):
    __tablename__ = "macros"

    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)
    owner = Column(String)
    name = Column(String)
    description = Column(String)
    actions = Column(BYTEA)
    prefs = Column(BYTEA)


class MetasploitCredentialCoreComments(Base):
    __tablename__ = "metasploit_credential_core_comments"

    id = Column(Integer, primary_key=True)
    core_id = Column(Integer)
    comment_id = Column(Integer)
    
    def __init__(self, core_id, comment_id):
        self.core_id = core_id
        self.comment_id = comment_id


class MetasploitCredentialLoginComments(Base):
    __tablename__ = "metasploit_credential_login_comments"

    id = Column(Integer, primary_key=True)
    login_id = Column(Integer)
    comment_id = Column(Integer)
    
    def __init__(self, login_id, comment_id):
        self.login_id = login_id
        self.comment_id = comment_id


class MetasploitCredentialCores(Base):
    __tablename__ = "metasploit_credential_cores"

    id = Column(Integer, primary_key=True)
    origin_type = Column(String, nullable=False)
    origin_id = Column(Integer, nullable=False)
    private_id = Column(Integer)
    public_id = Column(Integer)
    realm_id = Column(Integer)
    workspace_id = Column(Integer, nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.now())
    updated_at = Column(DateTime, nullable=False, default=datetime.now())
    logins_count = Column(Integer, default=0)

    def __init__(self, origin_type, origin_id, public_id, private_id, realm_id, workspace_id):
        self.origin_type = origin_type
        self.origin_id = origin_id
        self.public_id = public_id
        self.private_id = private_id
        self.realm_id = realm_id
        self.workspace_id = workspace_id
    
    def update_state(self, data):
        for key in list(data.keys()):
            if (key != 'id' and hasattr(self, key)):
                setattr(self, key, data[key])
        self.updated_at = datetime.now() 


class MetasploitCredentialLogins(Base):
    __tablename__ = "metasploit_credential_logins"

    id = Column(Integer, primary_key=True)
    core_id = Column(Integer, nullable=False)
    service_id = Column(Integer, nullable=False)
    access_level = Column(String)
    status = Column(String, nullable=False)
    last_attempted_at = Column(DateTime, default=datetime.now())
    created_at = Column(DateTime, nullable=False, default=datetime.now())
    updated_at = Column(DateTime, nullable=False, default=datetime.now())

    def __init__(self, core_id, service_id, access_level, status):
        self.core_id = core_id
        self.service_id = service_id
        self.access_level = access_level
        self.status = status

    def update_state(self, data):
        for key in list(data.keys()):
            if (key != 'id' and hasattr(self, key)):
                setattr(self, key, data[key])
        self.updated_at = datetime.now() 


class MetasploitCredentialOriginCrackedPasswords(Base):
    __tablename__ = "metasploit_credential_origin_cracked_passwords"

    id = Column(Integer, primary_key=True)
    metasploit_credential_core_id = Column(Integer, nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.now())
    updated_at = Column(DateTime, nullable=False, default=datetime.now())


class MetasploitCredentialOriginImports(Base):
    __tablename__ = "metasploit_credential_origin_imports"

    id = Column(Integer, primary_key=True)
    filename = Column(String, nullable=False)
    task_id = Column(Integer, default=None)
    created_at = Column(DateTime, nullable=False, default=datetime.now())
    updated_at = Column(DateTime, nullable=False, default=datetime.now())

    def __init__(self, filename):
        self.filename = filename

    def update_state(self, data):
        for key in list(data.keys()):
            if (key != 'id' and hasattr(self, key)):
                setattr(self, key, data[key])
        self.updated_at = datetime.now()


class MetasploitCredentialOriginManuals(Base):
    __tablename__ = "metasploit_credential_origin_manuals"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.now())
    updated_at = Column(DateTime, nullable=False, default=datetime.now())

    def __init__(self, user_id):
        self.user_id = user_id

    def update_state(self, data):
        for key in list(data.keys()):
            if (key != 'id' and hasattr(self, key)):
                setattr(self, key, data[key])
        self.updated_at = datetime.now()


class MetasploitCredentialOriginServices(Base):
    __tablename__ = "metasploit_credential_origin_services"

    id = Column(Integer, primary_key=True)
    service_id = Column(Integer, nullable=False)
    module_full_name = Column(String, nullable=False)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)

    def __init__(self, service_id, module_full_name, created_at, updated_at):
        self.service_id = int(service_id)
        self.module_full_name = str(module_full_name)
        self.created_at = created_at
        self.updated_at = updated_at


class MetasploitCredentialOriginSessions(Base):
    __tablename__ = "metasploit_credential_origin_sessions"

    id = Column(Integer, primary_key=True)
    post_reference_name = Column(String, nullable=False)
    session_id = Column(Integer, nullable=False)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)

    def __init__(self, session_id, post_reference_name, created_at, updated_at):
        self.session_id = int(session_id)
        self.post_reference_name = str(post_reference_name)
        self.created_at = created_at
        self.updated_at = updated_at


class MetasploitCredentialPrivates(Base):
    __tablename__ = "metasploit_credential_privates"

    id = Column(Integer, primary_key=True)
    type = Column(String, nullable=False)
    data = Column(String, nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.now())
    updated_at = Column(DateTime, nullable=False, default=datetime.now())
    jtr_format = Column(String, nullable=True, default=None)

    def __init__(self, type, data, jtr_format):
        self.type = str(type)
        self.data = str(data)
        self.jtr_format = jtr_format

    def update_state(self, data):
        for key in list(data.keys()):
            if (key != 'id' and hasattr(self, key)):
                setattr(self, key, data[key])
        self.updated_at = datetime.now() 


class MetasploitCredentialPublics(Base):
    __tablename__ = "metasploit_credential_publics"

    id = Column(Integer, primary_key=True)
    username = Column(String, nullable=False)
    type = Column(String, nullable=False, default="Metasploit::Credential::Username")
    created_at = Column(DateTime, nullable=False, default=datetime.now())
    updated_at = Column(DateTime, nullable=False, default=datetime.now())

    def __init__(self, username):
        self.username = str(username)


class MetasploitCredentialRealms(Base):
    __tablename__ = "metasploit_credential_realms"

    id = Column(Integer, primary_key=True)
    key = Column(String, nullable=False)
    value = Column(String, nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.now())
    updated_at = Column(DateTime, nullable=False, default=datetime.now())

    def __init__(self, key, value):
        self.key = str(key)
        self.value = str(value)


class ModRefs(Base):
    __tablename__ = "mod_refs"

    id = Column(Integer, primary_key=True)
    module = Column(String)
    mtype = Column(String)
    ref = Column(String)


class ModuleActions(Base):
    __tablename__ = "module_actions"

    id = Column(Integer, primary_key=True)
    detail_id = Column(Integer)
    name = Column(String)


class ModuleArchs(Base):
    __tablename__ = "module_archs"

    id = Column(Integer, primary_key=True)
    detail_id = Column(Integer)
    name = Column(String)


class ModuleAuthors(Base):
    __tablename__ = "module_authors"

    id = Column(Integer, primary_key=True)
    detail_id = Column(Integer)
    name = Column(String)
    email = Column(String)


class ModuleDetails(Base):
    __tablename__ = "module_details"

    id = Column(Integer, primary_key=True)
    mtime = Column(DateTime)
    file = Column(String)
    mtype = Column(String)
    refname = Column(String)
    name = Column(String)
    fullname = Column(String)
    description = Column(String)
    license = Column(String)
    rank = Column(Integer)
    privileged = Column(Boolean)
    disclosure_date = Column(DateTime)
    default_target = Column(Integer)
    default_action = Column(String)
    stance = Column(String)
    ready = Column(Boolean)


class ModuleMixins(Base):
    __tablename__ = "module_mixins"

    id = Column(Integer, primary_key=True)
    detail_id = Column(Integer)
    name = Column(String)


class ModulePlatforms(Base):
    __tablename__ = "module_platforms"

    id = Column(Integer, primary_key=True)
    detail_id = Column(Integer)
    name = Column(String)


class ModuleRefs(Base):
    __tablename__ = "module_refs"

    id = Column(Integer, primary_key=True)
    detail_id = Column(Integer)
    name = Column(String)


class ModuleRuns(Base):
    __tablename__ = "module_runs"

    id = Column(Integer, primary_key=True)
    port = Column(Integer)
    session_id = Column(Integer)
    trackable_id = Column(Integer)
    user_id = Column(Integer)
    fail_detail = Column(String)
    module_fullname = Column(String)
    attempted_at = Column(DateTime)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)
    fail_reason = Column(String)
    proto = Column(String)
    status = Column(String)
    trackable_type = Column(String)
    username = Column(String)


class ModuleTargets(Base):
    __tablename__ = "module_targets"

    id = Column(Integer, primary_key=True)
    detail_id = Column(Integer)
    index = Column(Integer)
    name = Column(String)


class NexposeConsoles(Base):
    __tablename__ = "nexpose_consoles"

    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)
    owner = Column(String)
    address = Column(String)
    username = Column(String)
    password = Column(String)
    status = Column(String)
    version = Column(String)
    cert = Column(String)
    name = Column(String)
    port = Column(Integer, default=3780)
    cached_sites = Column(BYTEA)
    enabled = Column(Boolean, default=True)


class Notes(Base):
    __tablename__ = "notes"

    id = Column(Integer, primary_key=True)
    critical = Column(Boolean,  default=None)
    seen = Column(Boolean,  default=None)
    workspace_id = Column(Integer, nullable=False, default=0)
    service_id = Column(Integer, default=None)
    host_id = Column(Integer,  default=None)
    vuln_id = Column(Integer,  default=None)
    data = Column(String,  default=None)
    ntype = Column(String,  default=None)
    created_at = Column(DateTime)
    updated_at = Column(DateTime)

    def __init__(self, workspace_id):
        self.workspace_id = int(workspace_id)
        self.created_at = datetime.now() 
        self.updated_at = datetime.now() 

    def update_state(self, data):
        for key in list(data.keys()):
            if (key != 'id' and hasattr(self, key)):
                setattr(self, key, data[key])
        self.updated_at = datetime.now() 


class Payloads(Base):
    __tablename__ = "payloads"

    id = Column(Integer, primary_key=True)
    name = Column(String)
    uuid = Column(String)
    uuid_mask = Column(Integer)
    timestamp = Column(Integer)
    arch = Column(String)
    platform = Column(String)
    urls = Column(String)
    description = Column(String)
    raw_payload = Column(String)
    raw_payload_hash = Column(String)
    build_status = Column(String)
    build_opts = Column(String)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)


class Profiles(Base):
    __tablename__ = "profiles"

    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)
    active = Column(Boolean, default=True)
    name = Column(String)
    owner = Column(String)
    settings = Column(BYTEA)


class Refs(Base):
    __tablename__ = "refs"

    id = Column(Integer, primary_key=True)
    ref_id = Column(Integer)
    created_at = Column(DateTime, default=datetime.now() )
    updated_at = Column(DateTime, default=datetime.now() )
    name = Column(String)

    def __init__(self, name):
        self.name = str(name)

    def update_state(self, data):
        for key in list(data.keys()):
            if (key != 'id' and hasattr(self, key)):
                setattr(self, key, data[key])
        self.updated_at = datetime.now() 


class ReportTemplates(Base):
    __tablename__ = "report_templates"

    id = Column(Integer, primary_key=True)
    workspace_id = Column(Integer, nullable=False, default=1)
    created_by = Column(String)
    path = Column(String)
    name = Column(String)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)


class Reports(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True)
    workspace_id = Column(Integer, nullable=False, default=1)
    created_by = Column(String)
    rtype = Column(String)
    path = Column(String)
    options = Column(String)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)
    downloaded_at = Column(DateTime)
    task_id = Column(Integer)
    name = Column(String)


class Routes(Base):
    __tablename__ = "routes"

    id = Column(Integer, primary_key=True)
    session_id = Column(Integer)
    subnet = Column(String)
    netmask = Column(String)


class SchemaMigrations(Base):
    __tablename__ = "schema_migrations"

    version = Column(String, primary_key=True)


class Services(Base):
    __tablename__ = "services"

    id = Column(Integer, primary_key=True)
    host_id = Column(Integer)
    created_at = Column(DateTime)
    updated_at = Column(DateTime)
    port = Column(Integer, nullable=False)
    proto = Column(String, nullable=False)
    state = Column(String)
    name = Column(String)
    info = Column(String)

    def __init__(self, host_id):
        self.host_id = int(host_id)
        self.created_at = datetime.now()
        self.updated_at = datetime.now()

    def update_state(self, data):
        for key in list(data.keys()):
            if (key != 'id' and hasattr(self, key)):
                setattr(self, key, data[key])
        self.updated_at = datetime.now() 


class SessionEvents(Base):
    __tablename__ = "session_events"

    id = Column(Integer, primary_key=True)
    session_id = Column(Integer)
    etype = Column(String)
    command = Column(BYTEA)
    output = Column(BYTEA)
    remote_path = Column(String)
    local_path = Column(String)
    created_at = Column(DateTime)


class Sessions(Base):
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True)
    host_id = Column(Integer)
    stype = Column(String)
    via_exploit = Column(String)
    via_payload = Column(String)
    desc = Column(String)
    port = Column(Integer)
    platform = Column(String)
    datastore = Column(String)
    opened_at = Column(DateTime, nullable=False)
    closed_at = Column(DateTime)
    close_reason = Column(String)
    local_id = Column(Integer)
    last_seen = Column(DateTime)
    module_run_id = Column(Integer)

    def __init__(self, host_id, stype, desc, port, datastore, opened_at):
        self.host_id = host_id
        self.stype = stype
        self.desc = desc
        self.port = port
        self.datastore = datastore
        self.opened_at = opened_at
    
    def to_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


class Tags(Base):
    __tablename__ = "tags"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer)
    name = Column(String)
    desc = Column(String)
    report_summary = Column(Boolean, nullable=False, default=False)
    report_detail = Column(Boolean, nullable=False, default=False)
    critical = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)

    def __init__(self, name, desc, created_at, updated_at):
        self.name = name
        self.desc = desc
        self.created_at = created_at
        self.updated_at = updated_at


class TaskCreds(Base):
    __tablename__ = "task_creds"

    id = Column(Integer, primary_key=True)
    task_id = Column(Integer, nullable=False)
    cred_id = Column(Integer, nullable=False)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)


class TaskHosts(Base):
    __tablename__ = "task_hosts"

    id = Column(Integer, primary_key=True)
    task_id = Column(Integer, nullable=False)
    host_id = Column(Integer, nullable=False)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)


class TaskServices(Base):
    __tablename__ = "task_services"

    id = Column(Integer, primary_key=True)
    task_id = Column(Integer, nullable=False)
    service_id = Column(Integer, nullable=False)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)


class TaskSessions(Base):
    __tablename__ = "task_sessions"

    id = Column(Integer, primary_key=True)
    task_id = Column(Integer, nullable=False)
    sessions_id = Column(Integer, nullable=False)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)


class Tasks(Base):
    __tablename__ = "tasks"

    id = Column(Integer, primary_key=True)
    workspace_id = Column(Integer, nullable=False, default=1)
    created_by = Column(String)
    module = Column(String)
    completed_at = Column(DateTime)
    path = Column(String)
    info = Column(String)
    description = Column(String)
    progress = Column(Integer)
    options = Column(String)
    error = Column(String)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)
    result = Column(String)
    module_uuid = Column(String)
    settings = Column(BYTEA)


class VulnAttempts(Base):
    __tablename__ = "vuln_attempts"

    id = Column(Integer, primary_key=True)
    vuln_id = Column(Integer)
    attempted_at = Column(DateTime, default=datetime.now())
    exploited = Column(Boolean)
    fail_reason = Column(String)
    username = Column(String)
    module = Column(String)
    fail_detail = Column(String)
    session_id = Column(Integer)
    loot_id = Column(Integer)

    def __init__(self, vuln_id):
        self.vuln_id = int(vuln_id)

    def update_state(self, data):
        for key in list(data.keys()):
            if (key != 'id' and hasattr(self, key)):
                setattr(self, key, data[key])


class VulnDetails(Base):
    __tablename__ = "vuln_details"

    id = Column(Integer, primary_key=True)
    vuln_id = Column(Integer)
    cvss_score = Column(Float)
    cvss_vector = Column(String)
    title = Column(String)
    description = Column(String)
    solution = Column(String)
    proof = Column(BYTEA)
    nx_console_id = Column(Integer)
    nx_device_id = Column(Integer)
    nx_vuln_id = Column(String)
    nx_severity = Column(Float)
    nx_pci_severity = Column(Float)
    nx_published = Column(DateTime)
    nx_added = Column(DateTime)
    nx_modified = Column(DateTime)
    nx_tags = Column(String)
    nx_vuln_status = Column(String)
    nx_proof_key = Column(String)
    src = Column(String)
    nx_scan_id = Column(Integer)
    nx_vulnerable_since = Column(DateTime)
    nx_pci_compliance_status = Column(String)

    def __init__(self, vuln_id):
        self.vuln_id = int(vuln_id)
    
    def update_state(self, data):
        for key in list(data.keys()):
            if (key != 'id' and hasattr(self, key)):
                setattr(self, key, data[key])


class Vulns(Base):
    __tablename__ = "vulns"

    id = Column(Integer, primary_key=True)
    host_id = Column(Integer)
    service_id = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.now())
    updated_at = Column(DateTime, default=datetime.now())
    name = Column(String)
    info = Column(String)
    exploited_at = Column(DateTime)
    vuln_detail_count = Column(Integer, default=0)
    vuln_attempt_count = Column(Integer, default=0)
    origin_id = Column(Integer)
    origin_type = Column(String)

    def __init__(self, name):
        self.name = name

    def update_state(self, data):
        for key in list(data.keys()):
            if (key != 'id' and hasattr(self, key)):
                setattr(self, key, data[key])
        self.updated_at = datetime.now() 


class VulnsRefs(Base):
    __tablename__ = "vulns_refs"

    ref_id = Column(Integer)
    vuln_id = Column(Integer)
    id = Column(Integer, primary_key=True)

    def __init__(self, ref_id, vuln_id):
        self.ref_id = int(ref_id)
        self.vuln_id = int(vuln_id)


class WebForms(Base):
    __tablename__ = "web_forms"

    id = Column(Integer, primary_key=True)
    web_site_id = Column(Integer, nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.now())
    updated_at = Column(DateTime, nullable=False, default=datetime.now())
    path = Column(String)
    method = Column(String)
    params = Column(String)
    query = Column(String)

    def __init__(self, web_site_id, path):
        self.web_site_id = int(web_site_id)
        self.path = path

    def update_state(self, data):
        for key in list(data.keys()):
            if (key != 'id' and hasattr(self, key)):
                setattr(self, key, data[key])
        self.updated_at = datetime.now() 


class WebPages(Base):
    __tablename__ = "web_pages"

    id = Column(Integer, primary_key=True)
    web_site_id = Column(Integer, nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.now())
    updated_at = Column(DateTime, nullable=False, default=datetime.now())
    path = Column(String)
    query = Column(String)
    code = Column(Integer, nullable=False, default=200)
    cookie = Column(String)
    auth = Column(String)
    ctype = Column(String)
    mtime = Column(DateTime, default=None)
    location = Column(String)
    headers = Column(String)
    body = Column(BYTEA)
    request = Column(BYTEA)

    def __init__(self, web_site_id, path):
        self.web_site_id = int(web_site_id)
        self.path = path
    
    def update_state(self, data):
        for key in list(data.keys()):
            if (key != 'id' and hasattr(self, key)):
                if(key == 'code'):
                    setattr(self, key, int(data[key]))
                elif(key == 'body' or key == 'request'):
                    setattr(self, key, str(data[key]).encode('utf-8'))
                else:
                    setattr(self, key, data[key])
        self.updated_at = datetime.now() 


class WebComments(Base):
    __tablename__ = "web_comments"

    id = Column(Integer, primary_key=True)
    web_site_id = Column(Integer, nullable=False)
    path = Column(String, nullable=False)
    comment = Column(String)
    created_at = Column(DateTime, nullable=False, default=datetime.now())
    updated_at = Column(DateTime, nullable=False, default=datetime.now())

    def __init__(self, web_site_id, path, comment):
        self.web_site_id = int(web_site_id)
        self.path = path
        self.comment = comment

    def update_state(self, data):
        for key in list(data.keys()):
            if (key != 'id' and hasattr(self, key)):
                setattr(self, key, data[key])
        self.updated_at = datetime.now() 


class WebSites(Base):
    __tablename__ = "web_sites"

    id = Column(Integer, primary_key=True)
    service_id = Column(Integer, nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.now())
    updated_at = Column(DateTime, nullable=False, default=datetime.now())
    vhost = Column(String)
    comments = Column(String)
    options = Column(String)

    def __init__(self, service_id):
        self.service_id = service_id

    def update_state(self, data):
        for key in list(data.keys()):
            if (key != 'id' and hasattr(self, key)):
                setattr(self, key, data[key])
        self.updated_at = datetime.now() 


class WebVulns(Base):
    __tablename__ = "web_vulns"

    id = Column(Integer, primary_key=True)
    web_site_id = Column(Integer, nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.now())
    updated_at = Column(DateTime, nullable=False, default=datetime.now())
    path = Column(String, nullable=False)
    method = Column(String, nullable=False, default='GET')
    params = Column(String)
    pname = Column(String)
    risk = Column(Integer, nullable=False, default=0)
    name = Column(String, nullable=False, default='web')
    query = Column(String)
    category = Column(String, nullable=False, default='web')
    confidence = Column(Integer, nullable=False, default=0)
    description = Column(String)
    blame = Column(String)
    request = Column(BYTEA)
    proof = Column(BYTEA, nullable=False, default=str('').encode('utf-8'))
    owner = Column(String)
    payload = Column(String)

    def __init__(self, web_site_id, path):
        self.web_site_id = int(web_site_id)
        self.path = path

    def update_state(self, data):
        for key in list(data.keys()):
            if (key != 'id' and hasattr(self, key)):
                if(key == 'proof' or key == 'request'):
                    setattr(self, key, str(data[key]).encode('utf-8'))
                else:
                    setattr(self, key, data[key])
        self.updated_at = datetime.now() 


class WmapRequests(Base):
    __tablename__ = "wmap_requests"

    id = Column(Integer, primary_key=True)
    host = Column(String)
    address = Column(INET)
    port = Column(Integer)
    ssl = Column(Integer)
    meth = Column(String)
    path = Column(String)
    headers = Column(String)
    query = Column(String)
    body = Column(String)
    respcode = Column(String)
    resphead = Column(String)
    response = Column(String)
    created_at = Column(DateTime)
    updated_at = Column(DateTime)


class WmapTargets(Base):
    __tablename__ = "wmap_targets"

    id = Column(Integer, primary_key=True)
    host = Column(String)
    address = Column(INET)
    port = Column(Integer)
    ssl = Column(Integer)
    selected = Column(Integer)
    created_at = Column(DateTime)
    updated_at = Column(DateTime)


class WorkspaceMembers(Base):
    __tablename__ = "workspace_members"

    workspace_id = Column(Integer, primary_key=True)
    user_id = Column(Integer, primary_key=True)

    def __init__(self, workspace_id, user_id):
        self.workspace_id = int(workspace_id)
        self.user_id = int(user_id)


class Users(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String)
    crypted_password = Column(String)
    password_salt = Column(String)
    persistence_token = Column(String)
    created_at = Column(DateTime, nullable=False, default=datetime.now())
    updated_at = Column(DateTime, nullable=False, default=datetime.now())
    fullname = Column(String)
    email = Column(String)
    phone = Column(String)
    company = Column(String)
    prefs = Column(String)
    admin = Column(Boolean, nullable=False, default=True)

    def __init__(self, username, crypted_password, password_salt, fullname, email, phone, company, admin):
        self.username = str(username)
        self.crypted_password = str(crypted_password)
        self.password_salt = str(password_salt)
        self.fullname = str(fullname)
        self.email = str(email)
        self.phone = str(phone)
        self.company = str(company)
        self.admin = admin

    def update_state(self, data):
        for key in list(data.keys()):
            if (key != 'id' and hasattr(self, key)):
                setattr(self, key, data[key])
        self.updated_at = datetime.now() 

    def to_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


class Workspaces(Base):
    __tablename__ = "workspaces"

    id = Column(Integer, primary_key=True)
    name = Column(String)
    created_at = Column(DateTime, nullable=False, default=datetime.now())
    updated_at = Column(DateTime, nullable=False, default=datetime.now())
    boundary = Column(String)
    description = Column(String)
    owner_id = Column(Integer, default=None)
    limit_to_network = Column(Boolean, nullable=False, default=False)
    import_fingerprint = Column(Boolean, default=False)

    def __init__(self, name):
        self.name = str(name)

    def update_state(self, data):
        for key in list(data.keys()):
            if (key != 'id' and hasattr(self, key)):
                setattr(self, key, data[key])
        self.updated_at = datetime.now() 

# class UserTaskStatus(Base):
#     __tablename__ = "user_tasks_status"

#     id = Column(Integer, primary_key=True)
#     name = Column(String, nullable=False)

#     def __init__(self, name):
#         self.name = name


class UserTasks(Base):
    __tablename__ = "user_tasks"

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    description = Column(String, nullable=True)
    final_date = Column(DateTime, nullable=True)
    status = Column(Boolean, nullable=False)
    workspace_id = Column(Integer, ForeignKey("workspaces.id", ondelete="CASCADE", onupdate="CASCADE"))
    # status = relationship("UserTaskStatus")
    workspace = relationship("Workspaces")

    def __init__(self, workspace_id, name):
        self.workspace_id = int(workspace_id)
        self.name = str(name)

    def update_state(self, data):
        for key in list(data.keys()):
            if (key != 'id' and hasattr(self, key)):
                setattr(self, key, data[key])
        self.updated_at = datetime.now() 


class UserTasksPerformers(Base):
    __tablename__ = "user_tasks_performers"

    id = Column(Integer, primary_key=True)
    user_task_id = Column(Integer, ForeignKey("user_tasks.id", ondelete="CASCADE", onupdate="CASCADE"))
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE", onupdate="CASCADE"))
    user_task = relationship("UserTasks")
    user = relationship("Users")

    def __init__(self, user_task_id, user_id):
        self.user_task_id = user_task_id
        self.user_id = user_id

