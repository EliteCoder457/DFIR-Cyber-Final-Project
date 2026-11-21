"""Aegis DFIR | local defensive investigation workspace."""
import json, os, tempfile, html
from pathlib import Path
import streamlit as st
import plotly.graph_objects as go
from file_analysis import analyze_file, MAX_FILE_SIZE
from url_analysis import analyze_url
from leak_checker import check_data_leak
from result_collector import InvestigationCase
from report_generator import generate_report

st.set_page_config(page_title='AEGIS // DFIR WORKSPACE',page_icon='◈',layout='wide',initial_sidebar_state='expanded')
st.markdown("""<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=Space+Grotesk:wght@400;500;600;700&display=swap');
:root{--bg:#050911;--surface:#0d1724;--line:#23364b;--cyan:#46e9f0;--lime:#b6ff64;--muted:#8ca2b6}
.stApp{background:radial-gradient(ellipse at 75% -15%,#123c4c 0%,transparent 37%),radial-gradient(ellipse at 10% 85%,#172334 0%,transparent 32%),#050911;color:#e9f4ff;font-family:'Space Grotesk',sans-serif}
.block-container{max-width:1510px;padding:1.6rem 2.5rem 5rem}
section[data-testid='stSidebar']{background:#08111d;border-right:1px solid #1b3343}
section[data-testid='stSidebar'] .stRadio label{font-size:.93rem}
h1,h2,h3{font-family:'Space Grotesk',sans-serif!important;letter-spacing:-.035em;color:#f0faff!important}
h1{font-size:2.5rem!important}h2{font-size:1.65rem!important}h3{font-size:1.15rem!important}
[data-testid='stMetric']{background:linear-gradient(145deg,#132333,#0b1623);border:1px solid #254357;border-radius:15px;padding:17px 19px;min-height:116px;box-shadow:0 9px 35px #0003}
[data-testid='stMetricLabel']{color:#9db4c5!important;text-transform:uppercase;letter-spacing:.12em;font-size:.72rem!important}
[data-testid='stMetricValue']{color:#e9faff!important;font-family:'IBM Plex Mono',monospace;font-size:1.65rem!important}
[data-testid='stExpander'],[data-testid='stForm']{background:#0c1826;border:1px solid #233a4e;border-radius:13px}
[data-testid='stAlert']{border-radius:12px}
.stButton button[kind='primary'],[data-testid='stFormSubmitButton'] button{background:linear-gradient(95deg,#49e6ea,#a9ff83);border:0;color:#06121a;font-weight:800;border-radius:9px;padding:.62rem 1.2rem}
.stButton button{border-radius:9px}
.stTextInput input,.stTextArea textarea{background:#0b1723!important;color:#e9faff!important;border:1px solid #29465a!important;border-radius:9px}
.stTabs [data-baseweb='tab-list']{gap:8px}.stTabs [data-baseweb='tab']{background:#0b1826;border-radius:8px;color:#a5b9c8;padding:9px 17px}
[data-testid='stDataFrame']{border:1px solid #274055;border-radius:12px}
.hero{background:linear-gradient(105deg,#112b39 0%,#0a1623 62%,#13263a 100%);border:1px solid #2a5261;border-radius:20px;padding:28px 30px;margin-bottom:22px;position:relative;overflow:hidden}
.hero:after{content:'◈';position:absolute;right:35px;top:-55px;font-size:230px;color:#47f2dc12}
.eyebrow{font:600 11px 'IBM Plex Mono',monospace;color:#5de8e5;letter-spacing:.22em;text-transform:uppercase}
.hero-title{font-size:36px;font-weight:700;letter-spacing:-.05em;margin:7px 0;color:#f0faff}
.hero-sub{color:#a6c0d0;max-width:800px;font-size:15px}
.pill{display:inline-block;border:1px solid #35616a;background:#15343c;color:#83f3dc;border-radius:100px;padding:5px 12px;font:11px 'IBM Plex Mono',monospace;margin-top:12px}
.section-label{font:600 12px 'IBM Plex Mono',monospace;letter-spacing:.14em;color:#71e9e5;text-transform:uppercase;margin:22px 0 12px}
.finding{border-left:3px solid #f2b65c;background:#101e2b;padding:14px 18px;border-radius:0 12px 12px 0;margin:10px 0}
.finding.high{border-color:#ff6077}.finding.low{border-color:#7ed9ff}.finding .severity{font:600 11px 'IBM Plex Mono',monospace;color:#a8d7e5;letter-spacing:.12em}
.finding .message{font-size:14px;margin-top:5px;color:#e6f1fa}
.mono{font-family:'IBM Plex Mono',monospace;color:#8ae7e9}
.small-note{font-size:12px;color:#91aabf}
</style>""",unsafe_allow_html=True)
for key in ('case','last_file_analysis','last_url_analysis','last_scan','report_bytes'):
    if key not in st.session_state: st.session_state[key]=None
case=st.session_state.case
pages=['◈  Mission Control','▣  Case Workspace','⬡  File Intelligence','◎  URL Intelligence','◉  Breach Intelligence','▤  Evidence Vault','▧  Report Studio']
st.sidebar.markdown('### ◈ AEGIS / DFIR')
st.sidebar.caption('FORENSIC OPERATIONS PLATFORM  /  2026')
st.sidebar.divider()
page=st.sidebar.radio('WORKSPACES',pages,label_visibility='visible')
st.sidebar.divider()
st.sidebar.markdown('**SYSTEM STATUS**')
st.sidebar.caption('● STATIC ENGINE READY')
st.sidebar.caption('● LOCAL EVIDENCE PROCESSING')
st.sidebar.caption('● NO SAMPLE EXECUTION')
if case:
    st.sidebar.success('CASE ACTIVE  /  '+case.case_id)
    st.sidebar.caption(case.case_title)
else: st.sidebar.info('NO ACTIVE CASE')

def hero(code,title,subtitle):
    st.markdown(f'<div class="hero"><div class="eyebrow">AEGIS // {html.escape(code)}</div><div class="hero-title">{html.escape(title)}</div><div class="hero-sub">{html.escape(subtitle)}</div><div class="pill">● ENGINE ONLINE &nbsp; / &nbsp; DEFENSIVE MODE</div></div>',unsafe_allow_html=True)
def label(s): st.markdown('<div class="section-label">'+html.escape(s)+'</div>',unsafe_allow_html=True)
def store(module,result):
    if st.session_state.case:
        {'file':st.session_state.case.add_file_result,'url':st.session_state.case.add_url_result,'leak':st.session_state.case.add_leak_result}[module](result)
    else: st.warning('Temporary result: create a case to retain evidence in the vault.')
def chart_layout(fig,height=290):
    fig.update_layout(height=height,margin=dict(l=8,r=8,t=20,b=10),paper_bgcolor='rgba(0,0,0,0)',plot_bgcolor='rgba(0,0,0,0)',font=dict(color='#aec6d5',family='IBM Plex Mono'),showlegend=False)
    fig.update_xaxes(gridcolor='#233649',zeroline=False);fig.update_yaxes(gridcolor='#233649',zeroline=False)
    st.plotly_chart(fig,use_container_width=True,config={'displayModeBar':False})
def gauge(score):
    # Red-led security visualization. Risk intensity follows the observed score.
    color='#ff465f' if score>=55 else '#ff7868' if score>=28 else '#ffb85c' if score>=10 else '#59d5c3'
    fig=go.Figure(go.Indicator(
        mode='gauge+number',value=score,
        number={'suffix':' / 100','font':{'size':30,'color':color}},
        gauge={'axis':{'range':[0,100],'tickcolor':'#8da4b5'},
               'bar':{'color':color,'thickness':0.32},
               'bgcolor':'#101f2e','borderwidth':0,
               'steps':[{'range':[0,28],'color':'#153832'},
                        {'range':[28,55],'color':'#493522'},
                        {'range':[55,100],'color':'#4e202d'}],
               'threshold':{'line':{'color':'#ff465f','width':3},'thickness':0.8,'value':55}}))
    chart_layout(fig,230)

def indicators(result):
    items=result.get('indicators',[])
    if not items: st.info('No rules triggered in the inspected scope. This is not a safety verdict or reputation lookup.')
    for x in sorted(items,key=lambda z:z.get('points',{'HIGH':30,'MEDIUM':15,'LOW':5}.get(z.get('severity'),0)),reverse=True):
        severity=x.get('severity','LOW');msg=x.get('message','');evidence=x.get('evidence','')
        st.markdown(f'<div class="finding {severity.lower()}"><div class="severity">{html.escape(severity)} SIGNAL {" / +"+str(x["points"]) if "points" in x else ""}</div><div class="message">{html.escape(msg)}</div><div class="small-note">{html.escape(str(evidence))}</div></div>',unsafe_allow_html=True)
def actions(result):
    label('Analyst next steps')
    for n,x in enumerate(result.get('recommendations',[]),1):st.markdown(f'**{n:02d}** &nbsp; {x}')
def export_result(result,prefix):
    st.download_button('↓ Export analysis JSON',json.dumps(result,indent=2,default=str),file_name=prefix+'_analysis.json',mime='application/json')
def display_file(r):
    label('Evidence verdict / scope')
    a,b,c,d=st.columns(4);a.metric('Risk classification',r['risk_level']);b.metric('Heuristic score',f"{r['risk_score']}/100");c.metric('Detected format',r['detected_type']);d.metric('File size',r['size_readable'])
    tab1,tab2,tab3,tab4=st.tabs(['◈  Intelligence brief','▥  Byte analytics','⬡  Artifacts','▣  Evidence metadata'])
    with tab1:
        left,right=st.columns([1,1.4]);
        with left:label('Risk meter');gauge(r['risk_score'])
        with right:label('Observed signals');indicators(r)
        actions(r)
        st.info('Interpretation: static indicators are triage clues, not a malware diagnosis. Hashes are identification evidence, not a reputation verdict.')
    with tab2:
        c=r.get('content_profile',{});a,b,c3=st.columns(3);a.metric('Shannon entropy',f"{r['entropy']:.3f} / 8");b.metric('Printable sample',str(c.get('printable_ratio',0))+'%');c3.metric('Sample inspected',f"{c.get('sampled_bytes',0):,} B")
        label('Byte-frequency distribution / 16 buckets')
        hist=c.get('byte_histogram',[])
        if hist:
            fig=go.Figure(go.Bar(x=[x['range'] for x in hist],y=[x['count'] for x in hist],marker_color='#55dfd9',hovertemplate='Hex range %{x}<br>Count %{y}<extra></extra>'));chart_layout(fig,310)
        st.caption('Frequency is calculated from the first 1 MiB. High entropy alone does not imply maliciousness, especially for compressed files.')
        with st.expander('Printable strings (bounded preview)'):st.code('\n'.join(c.get('strings_preview',[])) or 'No preview strings',language=None)
    with tab3:
        label('Cryptographic identity')
        for k,v in r['hashes'].items():st.code(f'{k.upper():7}  {v}',language=None)
        if r.get('archive'):label('Archive directory inspection');st.json(r['archive'])
        if r.get('content_profile',{}).get('pdf_markers'):label('PDF marker counts');st.json(r['content_profile']['pdf_markers'])
        if r.get('content_profile',{}).get('pe_header'):label('PE header');st.json(r['content_profile']['pe_header'])
        if r.get('content_profile',{}).get('embedded_urls'):label('Extracted URL strings (not visited)');st.code('\n'.join(r['content_profile']['embedded_urls']),language=None)
        if r.get('findings'):st.write(r['findings'])
    with tab4:
        st.json({k:r.get(k) for k in ('file_name','detected_type','extension','mime_guess','size_bytes','analysed_at','metadata','timestamps')})
        st.caption('Upload filesystem timestamps refer to the temporary copy, not original source metadata.')
    st.caption(r['note']);export_result(r,'file')
def display_url(r):
    s=r['structure'];label('Target verdict / scope');a,b,c,d=st.columns(4);a.metric('Risk classification',r['risk_level']);b.metric('Heuristic score',f"{r['risk_score']}/100");c.metric('Registered domain',s['registered_domain']);d.metric('URL length',s['url_length'])
    tab1,tab2,tab3,tab4=st.tabs(['◈  Intelligence brief','▥  Risk analytics','◎  Domain anatomy','▣  Network evidence'])
    with tab1:
        left,right=st.columns([1,1.4]);
        with left:label('Heuristic risk meter');gauge(r['risk_score']);st.caption('Weighted signal severity, not the probability that this URL is malicious. Scores are capped below 90 without verified threat intelligence.')
        with right:label('Observed signals');indicators(r)
        actions(r)
        st.info('Scope: URL syntax and optional DNS only. A minimal score does not verify website ownership, content, redirect behavior, or reputation.')
    with tab2:
        label('Risk contribution by category')
        breakdown=r.get('risk_breakdown',{});fig=go.Figure(go.Bar(x=list(breakdown),y=list(breakdown.values()),marker_color=['#55dfd9','#b6ff64','#ffa96e','#d18eff'],text=list(breakdown.values()),textposition='outside'));chart_layout(fig)
        label('Lexical indicators')
        metrics=r.get('lexical_metrics',{});st.dataframe([{'Signal':k.replace('_',' ').title(),'Value':v} for k,v in metrics.items()],hide_index=True,use_container_width=True)
        st.caption('Category contributions are adjusted for overlapping signals; they sum to the displayed score. These are not calibrated probabilities of compromise.')
    with tab3:
        label('URL components')
        st.json(s)
        st.code('HOST: '+s['host']+'\nREGISTERED DOMAIN: '+s['registered_domain']+'\nSUBDOMAIN: '+(s['subdomain'] or 'none')+'\nPATH: '+s['path'],language=None)
        st.caption('Inspect the registered domain, not just the brand-looking words in a subdomain or path.')
    with tab4:
        st.json(r['network']);st.caption('DNS results are transient. No page bodies or redirects are fetched; TLS and reputation are not verified by this module.')
    st.caption(r['note']);export_result(r,'url')

if page==pages[0]:
    hero('MISSION CONTROL','Investigation overview','Evidence-first workflow, transparent risk signals, repeatable analysis, and exportable case records.')
    count=len(case.evidence) if case else 0
    a,b,c,d=st.columns(4);a.metric('Case status','ACTIVE' if case else 'STANDBY');b.metric('Evidence items',count);c.metric('Analysis engines','03');d.metric('Execution mode','STATIC')
    label('Investigation workflow')
    st.markdown('**01 / Establish case**  →  **02 / Acquire evidence**  →  **03 / Inspect signals**  →  **04 / Record interpretation**  →  **05 / Export report**')
    if case and case.evidence:
        label('Recent case activity');st.dataframe([{'Evidence':e['evidence_id'],'Module':e['module'],'Recorded UTC':e['recorded_at'],'Risk / Status':e['result'].get('risk_level',e['result'].get('status',''))} for e in case.evidence[-30:]],use_container_width=True,hide_index=True)
        risks={k:sum(e['result'].get('risk_level')==k for e in case.evidence) for k in ('HIGH','MEDIUM','LOW','MINIMAL')}
        fig=go.Figure(go.Bar(x=list(risks),y=list(risks.values()),marker_color=['#ff6077','#ffb75e','#64d9ff','#b6ff64']));label('Risk distribution across evidence');chart_layout(fig,240)
    else:st.info('Create a case to build a persistent in-session evidence timeline. Export JSON to preserve it between sessions.')
elif page==pages[1]:
    hero('CASE WORKSPACE','Case management','Create, import and export an investigation workspace with append-only evidence history.')
    with st.form('case_form'):
        a,b=st.columns(2);cid=a.text_input('Case ID',value='CASE-001');investigator=a.text_input('Investigator');title=b.text_input('Investigation title')
        if st.form_submit_button('Initialize case'):
            try:
                st.session_state.case=InvestigationCase(cid,title,investigator)
                for k in ('last_file_analysis','last_url_analysis','last_scan','report_bytes'):st.session_state[k]=None
                st.success('Case initialized. Workspace is ready.')
            except ValueError as e:st.error(str(e))
    label('Restore existing workspace');uploaded=st.file_uploader('Import case JSON',type=['json'])
    if uploaded and st.button('Import case'):
        try:
            if uploaded.size>5*1024*1024:raise ValueError('Case exceeds 5 MiB')
            st.session_state.case=InvestigationCase.from_dict(json.loads(uploaded.getvalue()));st.session_state.report_bytes=None;st.success('Case imported')
        except (ValueError,KeyError,TypeError) as e:st.error(str(e))
    if st.session_state.case:
        data=st.session_state.case.get_case_data();st.download_button('↓ Export case JSON',json.dumps(data,indent=2),file_name='case_'+st.session_state.case.case_id+'.json',mime='application/json')
elif page==pages[2]:
    hero('ENGINE 01 / FILE','File intelligence','Read-only artifact triage: file identity, signature validation, byte statistics, archive directory inspection and forensic indicators.')
    uploaded=st.file_uploader('Upload evidence (maximum 200 MiB)',key='evidence_upload')
    if uploaded:st.caption(f'Selected / {uploaded.name} / {uploaded.size:,} bytes')
    if st.button('▶ Execute file inspection',type='primary'):
        if not uploaded:st.error('Select a file first.')
        elif uploaded.size>MAX_FILE_SIZE:st.error('Maximum size is 200 MiB.')
        else:
            path=None
            try:
                with tempfile.NamedTemporaryFile(delete=False) as f:
                    path=f.name
                    uploaded.seek(0)
                    while chunk:=uploaded.read(1024*1024):f.write(chunk)
                with st.spinner('Computing hashes and inspecting bounded evidence...'):result=analyze_file(path,original_name=uploaded.name)
                result['full_path']='Uploaded evidence (temporary local copy)';st.session_state.last_file_analysis=result;store('file',result);st.success('Inspection complete. Findings are ready below.')
            except Exception as e:st.error(f'Analysis failed: {e}')
            finally:
                if path and os.path.exists(path):os.unlink(path)
    if st.session_state.last_file_analysis:display_file(st.session_state.last_file_analysis)
elif page==pages[3]:
    hero('ENGINE 02 / URL','URL intelligence','Decompose URL identity and navigation signals, quantify lexical anomalies, and optionally capture DNS resolution evidence.')
    target=st.text_input('Target URL',placeholder='https://example.org/account/verify',key='target_url')
    online=st.checkbox('Include DNS resolution (external lookup)',value=False)
    if st.button('▶ Execute URL inspection',type='primary'):
        try:
            with st.spinner('Parsing URL and evaluating indicators...'):result=analyze_url(target,online=online)
            st.session_state.last_url_analysis=result;store('url',result);st.success('URL inspection complete.')
        except Exception as e:st.error(f'URL inspection failed: {e}')
    if st.session_state.last_url_analysis:display_url(st.session_state.last_url_analysis)
elif page==pages[4]:
    hero('ENGINE 03 / EXPOSURE','Breach intelligence','Consent-based exposure checking through Have I Been Pwned; no simulated clean results.')
    st.info('Requires a valid HIBP API key. Lookup sends the supplied email to HIBP. Without credentials, the result is NOT_CHECKED, not clean.')
    email=st.text_input('Email identifier');key=st.text_input('HIBP API key (or HIBP_API_KEY environment variable)',type='password')
    if st.button('▶ Check exposure',type='primary'):
        result=check_data_leak(email,api_key=key or None);st.session_state.last_scan=result
        if result['status']!='ERROR':store('leak',result)
    if st.session_state.last_scan:
        r=st.session_state.last_scan;a,b=st.columns(2);a.metric('Lookup status',r['status']);b.metric('Breach records',r.get('breaches_found',0));st.write(r.get('message',''))
        if r.get('breaches'):st.json(r['breaches'])
        export_result(r,'breach')
elif page==pages[5]:
    hero('EVIDENCE VAULT','Evidence & findings','Case-linked analysis snapshots and investigator annotations, ordered by collection time.')
    if not case:st.warning('Create or import a case to record evidence.')
    else:
        a,b=st.columns(2);a.metric('Evidence records',len(case.evidence));b.metric('Observations',len(case.observations))
        for e in reversed(case.evidence):
            with st.expander(f"{e['evidence_id']}  /  {e['module']}  /  {e['recorded_at']}"):
                st.json(e['result'])
        note=st.text_area('Investigator observation',placeholder='Record evidence interpretation, provenance, limitations, or follow-up actions...')
        if st.button('Add observation'):
            if note.strip():case.add_observation(note);st.success('Observation recorded.')
            else:st.warning('Enter an observation first.')
        if case.observations:st.json(case.observations)
elif page==pages[6]:
    hero('REPORT STUDIO','Investigation reporting','Compile evidence, timestamps and analyst notes into a portable PDF and structured JSON record.')
    if not case:st.warning('Create or import a case first.')
    else:
        a,b=st.columns(2);a.metric('Evidence records',len(case.evidence));b.metric('Analyst notes',len(case.observations))
        if st.button('▧ Compile PDF report',type='primary'):
            try:
                with tempfile.TemporaryDirectory() as directory:
                    path=generate_report(case.get_case_data(),output_dir=directory);st.session_state.report_bytes=Path(path).read_bytes()
                st.success('PDF generated.')
            except Exception as e:st.error(f'Report generation failed: {e}')
        if st.session_state.report_bytes:st.download_button('↓ Download PDF',st.session_state.report_bytes,file_name='Investigation_'+case.case_id+'.pdf',mime='application/pdf')
        st.download_button('↓ Download full evidence JSON',json.dumps(case.get_case_data(),indent=2),file_name='Investigation_'+case.case_id+'.json',mime='application/json')
