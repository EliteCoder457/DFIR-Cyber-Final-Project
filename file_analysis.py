"""Read-only, bounded forensic file inspection. Never executes input."""
import hashlib, math, mimetypes, os, re, stat, zipfile, struct
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

MAX_FILE_SIZE = 200 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 500
SIGNATURES = [(b'MZ','Windows PE executable',{'.exe','.dll','.sys','.scr'}),(b'\x7fELF','ELF executable',{'.elf','.so','.bin',''}),(b'%PDF','PDF document',{'.pdf'}),(b'PK\x03\x04','ZIP container',{'.zip','.docx','.xlsx','.pptx','.jar','.apk','.docm','.xlsm','.pptm'}),(b'\x89PNG\r\n\x1a\n','PNG image',{'.png'}),(b'\xff\xd8\xff','JPEG image',{'.jpg','.jpeg'}),(b'GIF8','GIF image',{'.gif'}),(b'Rar!\x1a\x07','RAR archive',{'.rar'}),(b'7z\xbc\xaf\x27\x1c','7z archive',{'.7z'}),(b'\x1f\x8b','GZIP archive',{'.gz','.tgz'}),(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1','OLE document',{'.doc','.xls','.ppt','.msi'}),(b'#!','Script',{'.sh','.py','.pl','.rb'})]
RISKY = {'.exe','.dll','.scr','.ps1','.bat','.cmd','.vbs','.js','.jse','.hta','.jar','.msi','.docm','.xlsm','.pptm'}
DOCUMENTS = {'.pdf','.doc','.docx','.xls','.xlsx','.ppt','.pptx','.txt','.png','.jpg'}
EICAR = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'

def _time(value): return datetime.fromtimestamp(value, timezone.utc).isoformat()
def _flag(out, severity, message, evidence=''):
    out.append({'severity':severity,'message':message,'evidence':evidence})

def compute_hashes(path):
    hashes = {k:hashlib.new(k) for k in ('md5','sha1','sha256')}
    counts = [0]*256; total=0
    with open(path,'rb') as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b''):
            for h in hashes.values(): h.update(chunk)
            total += len(chunk)
            freq=Counter(chunk); counts=[a+freq.get(i,0) for i,a in enumerate(counts)]
    entropy = -sum((c/total)*math.log2(c/total) for c in counts if c) if total else 0
    return {k:h.hexdigest() for k,h in hashes.items()},round(entropy,3)

def detect_file_type(path):
    with open(path,'rb') as stream: head=stream.read(4096)
    for magic,name,extensions in SIGNATURES:
        if head.startswith(magic): return name,extensions
    if not head: return 'Empty file',set()
    if b'\0' not in head:
        try:
            head.decode('utf-8'); return 'Text file',{'.txt','.csv','.log','.md','.json','.xml','.html','.htm','.py','.js','.sh','.bat','.ps1','.yaml','.yml','.ini',''}
        except UnicodeDecodeError: pass
    return 'Unidentified binary',set()

def analyze_file(path, original_name=None):
    p=Path(path)
    if p.is_symlink() or not p.is_file(): raise ValueError('Evidence must be a regular, non-symlink file')
    st=p.stat()
    if st.st_size>MAX_FILE_SIZE: raise ValueError('File exceeds 200 MiB analysis limit')
    name=os.path.basename(original_name or p.name); ext=Path(name).suffix.lower()
    hashes,entropy=compute_hashes(p); kind,expected=detect_file_type(p)
    flags=[]; archive={}; findings=[]
    if hashes['sha256']==EICAR: _flag(flags,'HIGH','EICAR antivirus test signature detected (harmless test sample)')
    if len(Path(name).suffixes)>1 and ext in RISKY and Path(name).suffixes[-2].lower() in DOCUMENTS: _flag(flags,'HIGH','Executable or script disguised with a document double extension')
    if expected and ext not in expected: _flag(flags,'HIGH' if 'executable' in kind.lower() else 'MEDIUM','Filename extension does not match detected content',f'{ext or "none"} vs {kind}')
    if ext in RISKY: _flag(flags,'MEDIUM','File extension can execute active content',ext)
    if st.st_size==0: _flag(flags,'LOW','Empty file')
    if entropy>7.6 and st.st_size>4096 and kind not in ('PNG image','JPEG image','ZIP container','GZIP archive','7z archive','RAR archive'): _flag(flags,'LOW','High entropy; may be compressed, encrypted, or packed',str(entropy))
    if kind=='ZIP container':
        try:
            with zipfile.ZipFile(p) as z:
                infos=z.infolist(); archive={'entries':len(infos),'encrypted_entries':sum(bool(i.flag_bits & 1) for i in infos),'uncompressed_bytes':sum(i.file_size for i in infos),'sample_names':[i.filename[:180] for i in infos[:30]]}
                if len(infos)>MAX_ARCHIVE_ENTRIES: _flag(flags,'MEDIUM','Archive contains unusually many entries')
                if archive['uncompressed_bytes']>max(st.st_size*100,100*1024*1024): _flag(flags,'MEDIUM','Archive has extreme declared expansion ratio (potential decompression bomb)')
                if any(i.filename.startswith('/') or '..' in Path(i.filename).parts for i in infos): _flag(flags,'HIGH','Archive contains potentially unsafe traversal paths')
                if any(Path(i.filename).suffix.lower() in RISKY for i in infos): _flag(flags,'MEDIUM','Archive contains executable or macro-enabled files')
                if any('vbaproject.bin' in i.filename.lower() for i in infos): _flag(flags,'HIGH','Office VBA macro component found')
                if any('[content_types].xml'==i.filename.lower() for i in infos): findings.append('Office Open XML container')
        except (zipfile.BadZipFile,OSError,RuntimeError) as e: _flag(flags,'MEDIUM','ZIP signature present but archive cannot be parsed',str(e)[:160])
    if kind=='PDF document':
        with open(p,'rb') as f: sample=f.read(min(st.st_size,2*1024*1024)).lower()
        for token in (b'/javascript',b'/js ',b'/openaction',b'/launch',b'/embeddedfile'):
            if token in sample: _flag(flags,'MEDIUM','PDF contains an active-content indicator',token.decode('ascii'))
    # Bounded content sampling: evidence is never executed, unpacked or transmitted.
    with open(p,'rb') as stream:
        head=stream.read(min(st.st_size, 1024*1024))
    counts=Counter(head)
    byte_histogram=[{'range':f'{i:02X}-{i+15:02X}','count':sum(counts.get(j,0) for j in range(i,i+16))} for i in range(0,256,16)]
    printable=sum(32<=b<=126 or b in (9,10,13) for b in head)
    strings=[m.group().decode('ascii','replace')[:160] for m in re.finditer(rb'[ -~]{8,}',head)][:60]
    urls=list(dict.fromkeys(re.findall(r'https?://[A-Za-z0-9._~:/?#\[\]@!$&\'()*+,;=%-]{4,180}', '\n'.join(strings),re.I)))[:20]
    content_profile={'sampled_bytes':len(head),'printable_ratio':round(printable/max(len(head),1)*100,1),'null_bytes':counts.get(0,0),'byte_histogram':byte_histogram,'strings_preview':strings[:30],'embedded_urls':urls,'sample_limit_note':'First 1 MiB only; embedded URLs are extracted, never contacted.'}
    if kind=='Windows PE executable' and len(head)>0x40:
        try:
            pe_offset=struct.unpack_from('<I',head,0x3c)[0]
            if pe_offset+24<=len(head) and head[pe_offset:pe_offset+4]==b'PE\0\0':
                machine,sections,timestamp=struct.unpack_from('<HHI',head,pe_offset+4)
                content_profile['pe_header']={'machine':hex(machine),'sections':sections,'coff_timestamp_utc':datetime.fromtimestamp(timestamp,timezone.utc).isoformat() if timestamp else None}
                if sections>20: _flag(flags,'MEDIUM','Unusually high PE section count',str(sections))
            else: _flag(flags,'MEDIUM','MZ header present but PE header not found in bounded sample')
        except (ValueError,struct.error,OverflowError): pass
    if kind=='PDF document':
        pdf_tokens={token:len(re.findall(re.escape(token),head,re.I)) for token in (b'/JavaScript',b'/OpenAction',b'/Launch',b'/EmbeddedFile',b'/Encrypt',b'/ObjStm')}
        content_profile['pdf_markers']={k.decode():v for k,v in pdf_tokens.items()}
    if archive:
        archive['suspicious_entries']=[n for n in archive.get('sample_names',[]) if Path(n).suffix.lower() in RISKY][:20]
    recommendations=[]
    if any(x['severity']=='HIGH' for x in flags): recommendations.append('Quarantine this sample and request deeper analysis in an isolated forensic environment.')
    if ext in RISKY or 'executable' in kind.lower(): recommendations.append('Do not execute the sample on an investigator workstation; validate publisher and provenance independently.')
    if archive: recommendations.append('Inspect archive members in an isolated environment; the toolkit reads directory metadata only.')
    if kind=='PDF document': recommendations.append('Review document provenance and embedded actions using a dedicated PDF forensic parser.')
    if not recommendations: recommendations.append('Correlate the SHA-256 digest with trusted threat intelligence and source context before drawing conclusions.')
    levels={'HIGH':35,'MEDIUM':15,'LOW':4}; score=min(100,sum(levels[x['severity']] for x in flags))
    risk='HIGH' if score>=60 else 'MEDIUM' if score>=25 else 'LOW' if score else 'MINIMAL'
    return {'module':'File Analysis','analysed_at':datetime.now(timezone.utc).isoformat(),'file_name':name,'full_path':str(p.absolute()),'extension':ext or '(none)','size_bytes':st.st_size,'size_readable':f'{st.st_size/1024:.1f} KiB','detected_type':kind,'mime_guess':mimetypes.guess_type(name)[0] or 'unknown','timestamps':{'modified':_time(st.st_mtime),'accessed':_time(st.st_atime),'metadata_changed':_time(st.st_ctime)},'metadata':{'permissions':stat.filemode(st.st_mode),'is_symlink':False},'hashes':hashes,'entropy':entropy,'archive':archive,'findings':findings,'content_profile':content_profile,'recommendations':recommendations,'indicators':flags,'risk_score':score,'risk_level':risk,'note':'Read-only static inspection; absence of indicators does not prove safety. Upload timestamps describe the temporary copy, not original evidence.'}

def print_report(result):
    import json; print(json.dumps(result,indent=2))
if __name__=='__main__':
    import sys,json
    print(json.dumps(analyze_file(sys.argv[1]),indent=2))
