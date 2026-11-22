"""Reusable input validation and CLI case intake."""
import ipaddress,os,re,uuid
from datetime import datetime,timezone
from url_analysis import normalize_url
EMAIL_RE=re.compile(r'^[^\s@]+@[^\s@]+\.[^\s@]+$')

def validate_file(path):
    path=os.path.abspath(os.path.expanduser(str(path).strip()))
    return (True,path) if os.path.isfile(path) and not os.path.islink(path) and os.access(path,os.R_OK) else (False,'File not found, unreadable, or symlink')
def validate_url(url):
    try:return True,normalize_url(url)
    except ValueError as e:return False,str(e)
def validate_email(value):
    value=value.strip().lower();return (True,value) if EMAIL_RE.fullmatch(value) else (False,'Invalid email')
def validate_username(value):
    value=value.strip();return (True,value) if re.fullmatch(r'[\w.-]{3,32}',value) else (False,'Invalid username')
def validate_ip_or_domain(value):
    value=value.strip().lower()
    try:return True,str(ipaddress.ip_address(value))
    except ValueError:pass
    return (True,value) if re.fullmatch(r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}',value) else (False,'Invalid IP or domain')
def new_case(investigator='Unknown',case_name='Untitled case'):
    return {'case_id':'CASE-'+uuid.uuid4().hex[:8].upper(),'case_name':case_name,'investigator':investigator,'created_at':datetime.now(timezone.utc).isoformat(),'inputs':{'file_path':None,'url':None,'port_target':None}}
def collect_inputs(file_path=None,url=None,port_target=None,investigator='Unknown',case_name='Untitled case'):
    case=new_case(investigator,case_name)
    for key,value,validator in [('file_path',file_path,validate_file),('url',url,validate_url),('port_target',port_target,validate_ip_or_domain)]:
        if value:
            ok,clean=validator(value)
            if not ok:raise ValueError(clean)
            case['inputs'][key]=clean
    return case
def collect_inputs_interactive():
    name=input('Case title: ').strip() or 'Untitled case';investigator=input('Investigator: ').strip() or 'Unknown'
    return collect_inputs(file_path=input('File path (optional): ').strip() or None,url=input('URL (optional): ').strip() or None,investigator=investigator,case_name=name)
if __name__=='__main__':
    import json;print(json.dumps(collect_inputs_interactive(),indent=2))
