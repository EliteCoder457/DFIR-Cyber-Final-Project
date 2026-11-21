"""Privacy-preserving breach lookup via optional HIBP API key; no invented results."""
import os,re
from datetime import datetime,timezone

def validate_email(value): return bool(re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+',value or ''))
def mask_email(email):
    user,domain=email.split('@',1);return (user[:1]+'***' if user else '***')+'@'+domain

def check_data_leak(email,api_key=None):
    email=email.strip().lower()
    if not validate_email(email): return {'status':'ERROR','message':'Invalid email address'}
    result={'email':mask_email(email),'status':'NOT_CHECKED','breaches_found':0,'breaches':[],'source':'Have I Been Pwned API v3','checked_at':datetime.now(timezone.utc).isoformat()}
    key=api_key or os.getenv('HIBP_API_KEY')
    if not key:
        result['message']='Live breach lookup unavailable: configure HIBP_API_KEY. No exposure verdict was made.'
        return result
    try:
        import requests
        from urllib.parse import quote
        response=requests.get('https://haveibeenpwned.com/api/v3/breachedaccount/'+quote(email,safe=''),headers={'hibp-api-key':key,'user-agent':'DFIR-Case-Toolkit/2.0'},params={'truncateResponse':'true'},timeout=12)
        if response.status_code==404: result.update(status='NOT_FOUND',message='No matching breaches returned by HIBP (not proof of safety).')
        elif response.status_code==200:
            names=[x.get('Name','Unknown') for x in response.json() if isinstance(x,dict)]
            result.update(status='EXPOSED' if names else 'NOT_FOUND',breaches_found=len(names),breaches=names,message='HIBP query completed')
        else: result.update(status='UNAVAILABLE',message=f'HIBP returned HTTP {response.status_code}; no verdict made.')
    except (ValueError,requests.RequestException) as e: result.update(status='UNAVAILABLE',message=f'Lookup failed: {type(e).__name__}')
    return result
