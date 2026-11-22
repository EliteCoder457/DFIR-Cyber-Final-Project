"""Defensive URL triage. Never fetches page bodies or follows redirects."""
import ipaddress, re, socket, ssl, math
from datetime import datetime,timezone
from urllib.parse import urlsplit,parse_qs,unquote

KEYWORDS={'verify','password','reset','signin','login','wallet','account','payment','confirm','urgent'}
SHORTENERS={'bit.ly','tinyurl.com','t.co','is.gd','cutt.ly','tiny.cc'}
REDIRECT_KEYS={'url','next','redirect','redirect_uri','return','continue','destination'}

def normalize_url(value):
    value=value.strip()
    if not value or len(value)>4096 or any(ord(c)<32 or c.isspace() for c in value): raise ValueError('URL must be nonempty, under 4096 characters, without whitespace/control characters')
    if '://' not in value: value='https://'+value
    p=urlsplit(value)
    if p.scheme.lower() not in ('http','https') or not p.hostname: raise ValueError('Only HTTP(S) URLs with a hostname are supported')
    try: port=p.port
    except ValueError as e: raise ValueError('Invalid URL port') from e
    # Username-only authority syntax is inspected as a phishing indicator, never used for authentication.
    if p.password is not None: raise ValueError('URLs containing embedded passwords are not supported')
    if port==0: raise ValueError('Invalid port')
    try: p.hostname.encode('idna')
    except UnicodeError as e: raise ValueError('Invalid hostname') from e
    return value

def _public(ip): return ipaddress.ip_address(ip).is_global

def _dns(host):
    try:
        ips=sorted({item[4][0] for item in socket.getaddrinfo(host,None,type=socket.SOCK_STREAM)})
        return {'resolved':bool(ips),'ips':ips,'public_only':bool(ips) and all(_public(ip) for ip in ips)}
    except (socket.gaierror,ValueError,OSError) as e: return {'resolved':False,'ips':[],'public_only':False,'error':str(e)[:180]}

def _tls(host,port,timeout=3):
    try:
        context=ssl.create_default_context()
        with socket.create_connection((host,port),timeout=timeout) as raw:
            with context.wrap_socket(raw,server_hostname=host) as secure:
                cert=secure.getpeercert()
                return {'status':'valid','protocol':secure.version(),'issuer':str(cert.get('issuer',''))[:300],'expires':cert.get('notAfter')}
    except Exception as e: return {'status':'unverified','error':str(e)[:200]}

def split_host(host):
    try:
        import tldextract
        x=tldextract.extract(host); reg='.'.join(v for v in (x.domain,x.suffix) if v)
        return x.subdomain,reg,x.suffix
    except ImportError:
        labels=host.split('.'); return '.'.join(labels[:-2]),'.'.join(labels[-2:]),labels[-1] if len(labels)>1 else ''

def analyze_url(url,online=False):
    url=normalize_url(url); p=urlsplit(url); host=p.hostname.lower(); sub,reg,tld=split_host(host)
    try: ipaddress.ip_address(host); ip_literal=True
    except ValueError: ip_literal=False
    params=parse_qs(p.query,keep_blank_values=True,max_num_fields=100)
    flags=[]
    def flag(points,severity,message): flags.append({'points':points,'severity':severity,'message':message})
    if p.scheme=='http': flag(12,'MEDIUM','HTTP does not encrypt traffic')
    if p.username is not None:
        flag(28,'HIGH','Deceptive userinfo before @: the actual destination is '+host+', not '+p.username)
    # A brand-like subdomain is not the brand owner: use registered-domain boundaries.
    protected={'paypal':'paypal.com','microsoft':'microsoft.com','google':'google.com','apple':'apple.com','amazon':'amazon.com','netflix':'netflix.com'}
    for brand,official in protected.items():
        if re.search(r'(?i)(?<![a-z])'+brand+r'(?![a-z])',host) and reg!=official:
            flag(24,'HIGH',f'Possible {brand} impersonation: registered domain is {reg}, not {official}')
            break
    if ip_literal: flag(18,'MEDIUM','URL uses a literal IP address')
    if len(url)>120: flag(10,'LOW','Unusually long URL')
    if len(sub.split('.'))>=4: flag(12,'MEDIUM','Deep subdomain nesting')
    if 'xn--' in host: flag(10,'LOW','Internationalized domain encoding; inspect for lookalikes')
    if reg in SHORTENERS: flag(15,'MEDIUM','URL shortener conceals destination')
    if p.port and p.port not in (80,443): flag(8,'LOW','Unusual destination port')
    if len(re.findall('%[0-9a-fA-F]{2}',url))>=8: flag(10,'LOW','Heavy percent encoding')
    if any(k.lower() in REDIRECT_KEYS for k in params): flag(12,'MEDIUM','Redirect-related query parameter; not proof of an open redirect')
    if re.search(r'(?i)(?:javascript:|<script|\.\./)',unquote(p.path)): flag(22,'HIGH','Encoded or literal traversal/script-like path pattern; inspect manually')
    hits=sorted(k for k in KEYWORDS if re.search(r'(?i)(?<![a-z])'+re.escape(k)+r'(?![a-z])',sub+' '+p.path))
    if len(hits)>=2: flag(8,'LOW','Multiple account-related terms: '+', '.join(hits))
    network={'status':'not_requested','note':'No webpage content or redirects are fetched.'}
    if online:
        dns=_dns(host); network={'status':'completed','dns':dns,'note':'DNS and certificate metadata only; no webpage requests or redirect following.'}
        if not dns['resolved']: flag(6,'LOW','DNS lookup failed; this is not proof of maliciousness')
        if not dns['public_only']:
            network['status']='blocked'; network['note']='Non-public or unresolved IP; outbound checks blocked to prevent internal-network access.'
        elif p.scheme=='https':
            # DNS precheck is not a binding: DNS rebinding remains possible. Therefore
            # do not open sockets to user-supplied hosts in this application.
            network['tls']={'status':'not_checked','note':'Live TLS connection disabled to avoid DNS-rebinding/SSRF risks; use a dedicated isolated scanner for active probes.'}
    lexical={'hostname_length':len(host),'hostname_labels':len(host.split('.')),'path_depth':len([x for x in p.path.split('/') if x]),'query_parameter_count':len(params),'digit_count':sum(c.isdigit() for c in host),'hyphen_count':host.count('-'),'percent_encoded_count':len(re.findall(r'%[0-9a-fA-F]{2}',url)),'url_length':len(url)}
    if host.count('-')>=3: flag(8,'LOW','Hostname contains many hyphens; verify its intended owner')
    if lexical['hostname_labels']>=6: flag(8,'LOW','Deeply nested hostname; check the registered domain carefully')
    if lexical['query_parameter_count']>=8: flag(6,'LOW','Large number of query parameters')
    if re.search(r'(?i)(?:password|passwd|token|api_key|secret)=',p.query): flag(18,'MEDIUM','Query key suggests a secret could be exposed in URL history or logs')
    if p.scheme=='https' and p.port==80: flag(10,'LOW','HTTPS on port 80 is unusual')
    if ip_literal and not _public(host):
        flag(0,'INFO','IP is non-public/reserved: synthetic testing or internal addressing, not a verified internet threat')
    if host.startswith('www.') and host.count('www.')>1: flag(8,'LOW','Repeated www labels')
    breakdown={'transport':0,'identity':0,'obfuscation':0,'navigation':0}
    for x in flags:
        m=x['message'].lower()
        cat='transport' if any(k in m for k in ('http','port','dns')) else 'identity' if any(k in m for k in ('domain','hostname','ip address','subdomain','internationalized')) else 'obfuscation' if any(k in m for k in ('encoding','long','shortener','hyphen')) else 'navigation'
        breakdown[cat]+=x['points']
    recommendations=['Confirm the registered domain against an independently trusted source.','Do not enter credentials based solely on a low heuristic score.']
    if p.scheme=='http': recommendations.append('Prefer the verified HTTPS destination when sharing sensitive data.')
    if p.username is not None: recommendations.append('Ignore the text before @ when identifying the destination host; do not enter credentials.')
    if any('impersonation' in x['message'].lower() for x in flags): recommendations.append('Verify the true registered domain with the organization through a trusted channel.')
    if any('redirect' in x['message'].lower() for x in flags): recommendations.append('Review redirect parameters manually; this analyzer does not establish exploitability.')
    if network.get('status')=='not_requested': recommendations.append('Enable optional DNS inspection to add resolution evidence (external lookup).')
    # Calibrated heuristic severity, NOT probability of maliciousness.
    # Correlated signals (login + redirect + brand words) should not add up
    # indefinitely. Strong deception signals retain priority.
    categories={'transport':[], 'identity':[], 'obfuscation':[], 'navigation':[]}
    for finding in flags:
        if finding['points'] <= 0:
            continue
        msg=finding['message'].lower()
        if 'http does not' in msg or 'destination port' in msg or 'https on port' in msg:
            category='transport'
        elif any(t in msg for t in ('impersonation','userinfo','literal ip','domain','hostname','subdomain','internationalized')):
            category='identity'
        elif any(t in msg for t in ('encoding','traversal','script-like','shortener','long url','hyphens')):
            category='obfuscation'
        else:
            category='navigation'
        categories[category].append(finding['points'])
    # Full weight for the strongest observation in each family; reduced
    # incremental weight for supporting observations in that same family.
    caps={'transport':14,'identity':32,'obfuscation':20,'navigation':16}
    adjusted={}
    for category,weights in categories.items():
        weights.sort(reverse=True)
        adjusted[category]=min(caps[category], round(weights[0]+0.30*sum(weights[1:]))) if weights else 0
    raw_score=sum(f['points'] for f in flags)
    score=min(89,sum(adjusted.values()))
    # No lexical-only inspection can claim a certain malicious verdict.
    risk='HIGH' if score>=55 else 'MEDIUM' if score>=28 else 'LOW' if score>=10 else 'MINIMAL'
    breakdown=adjusted
    confidence='LIMITED' if not online else 'PARTIAL'

    return {'module':'URL Analysis','analysed_at':datetime.now(timezone.utc).isoformat(),'url':url,'structure':{'scheme':p.scheme,'host':host,'port':p.port,'path':p.path or '/','query_keys':list(params),'fragment_present':bool(p.fragment),'userinfo_present':p.username is not None,'url_length':len(url),'subdomain':sub,'registered_domain':reg,'tld':tld},'network':network,'lexical_metrics':lexical,'risk_breakdown':breakdown,'recommendations':recommendations,'indicators':flags,'risk_score':score,'raw_signal_points':raw_score,'scoring_method':'Diminishing returns per independent signal family; lexical-only scores capped at 89/100','analysis_confidence':confidence,'risk_level':risk,'note':'Heuristic triage only. No reputation verdict, webpage fetch, or redirect verification is performed.'}

def print_report(result):
    import json;print(json.dumps(result,indent=2))
if __name__=='__main__':
    import sys,json
    print(json.dumps(analyze_url(sys.argv[1],'--online' in sys.argv),indent=2))
