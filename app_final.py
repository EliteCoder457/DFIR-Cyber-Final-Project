"""ThreatNova | cybersecurity intelligence and investigation workspace."""
import json, os, tempfile, html
from pathlib import Path
import streamlit as st
import plotly.graph_objects as go
from file_analysis import analyze_file, MAX_FILE_SIZE
from url_analysis import analyze_url
from network_analysis import analyze_network, COMMON_PORTS
from result_collector import InvestigationCase
from report_generator import generate_report

st.set_page_config(page_title='ThreatNova | Cybersecurity Intelligence',page_icon='◈',layout='wide',initial_sidebar_state='expanded')
st.markdown("""<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=Space+Grotesk:wght@400;500;600;700&display=swap');
:root{--bg:#03070c;--panel:rgba(8,18,27,.82);--panel2:rgba(11,24,35,.72);--line:rgba(103,238,224,.16);--line2:rgba(103,238,224,.30);--cyan:#67eee0;--lime:#b8ff78;--text:#ecfbff;--muted:#87a5b3;--danger:#ff5d78}
html,body,[class*="css"]{font-family:'Space Grotesk',sans-serif}
.stApp{background:#03070c;color:var(--text);overflow-x:hidden}
.stApp:before{content:'';position:fixed;inset:0;pointer-events:none;z-index:0;background-image:linear-gradient(rgba(79,224,210,.045) 1px,transparent 1px),linear-gradient(90deg,rgba(79,224,210,.045) 1px,transparent 1px),radial-gradient(circle at 72% 18%,rgba(0,231,210,.12),transparent 28%),radial-gradient(circle at 18% 82%,rgba(67,117,255,.09),transparent 26%);background-size:42px 42px,42px 42px,100% 100%,100% 100%;animation:gridDrift 18s linear infinite}
.stApp:after{content:'';position:fixed;left:0;right:0;top:-20%;height:18%;pointer-events:none;z-index:0;background:linear-gradient(180deg,transparent,rgba(103,238,224,.055),rgba(103,238,224,.12),transparent);filter:blur(1px);animation:scanline 8s linear infinite}
@keyframes gridDrift{0%{background-position:0 0,0 0,0 0,0 0}100%{background-position:42px 84px,42px 84px,0 0,0 0}}
@keyframes scanline{0%{transform:translateY(-30vh)}100%{transform:translateY(150vh)}}
@keyframes pulseDot{0%,100%{box-shadow:0 0 0 0 rgba(103,238,224,.35)}50%{box-shadow:0 0 0 6px rgba(103,238,224,0)}}
.block-container{max-width:1480px;padding:1.8rem 2.5rem 5rem;position:relative;z-index:1}
header[data-testid='stHeader']{background:rgba(3,7,12,.60);backdrop-filter:blur(16px);border-bottom:1px solid rgba(103,238,224,.08)}
section[data-testid='stSidebar']{background:rgba(5,12,19,.93);border-right:1px solid var(--line);backdrop-filter:blur(20px)}
section[data-testid='stSidebar']>div{padding-top:1.1rem}
section[data-testid='stSidebar'] [data-testid='stMarkdownContainer'] h3{font-family:'IBM Plex Mono',monospace!important;letter-spacing:.08em!important;font-size:1rem!important}
section[data-testid='stSidebar'] .stRadio>div{gap:.28rem}
section[data-testid='stSidebar'] .stRadio label{padding:.66rem .72rem;border:1px solid transparent;border-radius:10px;transition:.2s ease}
section[data-testid='stSidebar'] .stRadio label:hover{background:rgba(103,238,224,.055);border-color:rgba(103,238,224,.10)}
h1,h2,h3{font-family:'Space Grotesk',sans-serif!important;letter-spacing:-.035em;color:#f3fdff!important}h1{font-size:2.5rem!important}h2{font-size:1.65rem!important}h3{font-size:1.15rem!important}
[data-testid='stMetric']{background:linear-gradient(145deg,rgba(12,28,39,.88),rgba(6,15,23,.82));border:1px solid var(--line);border-radius:14px;padding:16px 18px;min-height:112px;box-shadow:inset 0 1px 0 rgba(255,255,255,.025);transition:transform .2s ease,border-color .2s ease}
[data-testid='stMetric']:hover{transform:translateY(-2px);border-color:var(--line2)}
[data-testid='stMetricLabel']{color:#8faab7!important;text-transform:uppercase;letter-spacing:.12em;font-size:.69rem!important;font-family:'IBM Plex Mono',monospace!important}
[data-testid='stMetricValue']{color:#effdff!important;font-family:'IBM Plex Mono',monospace;font-size:1.55rem!important}
[data-testid='stExpander'],[data-testid='stForm']{background:var(--panel);border:1px solid var(--line);border-radius:14px;backdrop-filter:blur(12px);overflow:hidden}
[data-testid='stAlert']{border-radius:12px;background:rgba(10,24,34,.80);border-color:var(--line)!important}
.stButton button,.stDownloadButton button,[data-testid='stFormSubmitButton'] button{min-height:42px;border-radius:9px;border:1px solid rgba(103,238,224,.22);background:rgba(9,23,32,.9);transition:.18s ease;font-family:'IBM Plex Mono',monospace;font-size:.82rem}
.stButton button:hover,.stDownloadButton button:hover{border-color:rgba(103,238,224,.55);transform:translateY(-1px);box-shadow:0 8px 28px rgba(0,0,0,.22)}
.stButton button[kind='primary'],[data-testid='stFormSubmitButton'] button{background:linear-gradient(95deg,#62e9df,#b8ff78);border:0;color:#041116;font-weight:800;box-shadow:0 0 28px rgba(103,238,224,.12)}
.stTextInput input,.stTextArea textarea{background:rgba(5,15,23,.92)!important;color:#edfbff!important;border:1px solid rgba(103,238,224,.20)!important;border-radius:9px!important;font-family:'IBM Plex Mono',monospace!important}
.stTextInput input:focus,.stTextArea textarea:focus{border-color:rgba(103,238,224,.65)!important;box-shadow:0 0 0 1px rgba(103,238,224,.22)!important}
.stTabs [data-baseweb='tab-list']{gap:5px;background:rgba(5,14,21,.58);border:1px solid var(--line);border-radius:11px;padding:4px}.stTabs [data-baseweb='tab']{border-radius:7px;color:#9bb1bc;padding:9px 15px}.stTabs [aria-selected='true']{background:rgba(103,238,224,.10)!important;color:#dffffb!important}
[data-testid='stDataFrame']{border:1px solid var(--line);border-radius:12px;overflow:hidden;background:rgba(6,15,23,.78)}
.hero{background:linear-gradient(115deg,rgba(11,31,41,.92) 0%,rgba(5,15,23,.86) 58%,rgba(9,28,37,.86) 100%);border:1px solid rgba(103,238,224,.22);border-radius:18px;padding:30px 32px;margin-bottom:24px;position:relative;overflow:hidden;box-shadow:inset 0 1px 0 rgba(255,255,255,.035),0 22px 70px rgba(0,0,0,.20)}
.hero:before{content:'';position:absolute;inset:0;background:linear-gradient(90deg,transparent,rgba(103,238,224,.045),transparent);transform:translateX(-100%);animation:heroSweep 7s ease-in-out infinite}
.hero:after{content:'THREATNOVA';position:absolute;right:28px;top:10px;font:700 58px 'IBM Plex Mono',monospace;letter-spacing:-.08em;color:rgba(103,238,224,.025)}
@keyframes heroSweep{0%,25%{transform:translateX(-100%)}70%,100%{transform:translateX(100%)}}
.eyebrow{font:600 10px 'IBM Plex Mono',monospace;color:var(--cyan);letter-spacing:.24em;text-transform:uppercase;position:relative;z-index:1}.hero-title{font-size:38px;font-weight:700;letter-spacing:-.055em;margin:8px 0 6px;color:#f2fdff;position:relative;z-index:1}.hero-sub{color:#9db6c2;max-width:790px;font-size:14px;line-height:1.65;position:relative;z-index:1}.pill{display:inline-flex;align-items:center;gap:8px;border:1px solid rgba(103,238,224,.22);background:rgba(103,238,224,.065);color:#9ff7e9;border-radius:100px;padding:6px 11px;font:10px 'IBM Plex Mono',monospace;margin-top:15px;position:relative;z-index:1}.pill:before{content:'';width:6px;height:6px;border-radius:50%;background:var(--cyan);animation:pulseDot 2s infinite}
.section-label{font:600 10px 'IBM Plex Mono',monospace;letter-spacing:.18em;color:#75e9df;text-transform:uppercase;margin:24px 0 10px;display:flex;align-items:center;gap:10px}.section-label:after{content:'';height:1px;flex:1;background:linear-gradient(90deg,rgba(103,238,224,.20),transparent)}
.finding{border:1px solid rgba(242,182,92,.18);border-left:3px solid #f2b65c;background:rgba(16,30,43,.74);padding:13px 16px;border-radius:0 11px 11px 0;margin:9px 0}.finding.high{border-left-color:#ff6077}.finding.low{border-left-color:#7ed9ff}.finding .severity{font:600 10px 'IBM Plex Mono',monospace;color:#a8d7e5;letter-spacing:.13em}.finding .message{font-size:14px;margin-top:5px;color:#e6f1fa}.mono{font-family:'IBM Plex Mono',monospace;color:#8ae7e9}.small-note{font-size:12px;color:#829dab;margin-top:3px}
hr{border-color:rgba(103,238,224,.10)!important}
@media(max-width:900px){.block-container{padding:1.2rem 1rem 4rem}.hero{padding:23px 20px}.hero-title{font-size:30px}.hero:after{display:none}}
@media(prefers-reduced-motion:reduce){.stApp:before,.stApp:after,.hero:before,.pill:before{animation:none!important}.stButton button,[data-testid='stMetric']{transition:none!important}}

/* ThreatNova welcome and feature experience */
.home-hero{position:relative;overflow:hidden;border:1px solid rgba(103,238,224,.25);border-radius:22px;padding:48px 46px;margin-bottom:28px;background:radial-gradient(ellipse at 85% 40%,rgba(31,152,168,.20),transparent 43%),linear-gradient(115deg,#102432 0%,#08121d 62%,#07131d 100%);box-shadow:0 24px 80px rgba(0,0,0,.22)}
.home-glow{position:absolute;right:-110px;top:-145px;width:440px;height:440px;border:1px solid rgba(103,238,224,.12);border-radius:50%;box-shadow:0 0 0 50px rgba(103,238,224,.025),0 0 0 105px rgba(103,238,224,.018);pointer-events:none}
.home-content{position:relative;z-index:1}.home-kicker{font:600 10px 'IBM Plex Mono',monospace;letter-spacing:.17em;color:#86e9e2}.home-dot{display:inline-block;width:7px;height:7px;border-radius:50%;background:#b8ff78;box-shadow:0 0 12px rgba(184,255,120,.7);margin-right:8px}.home-headline{font-size:clamp(38px,5vw,67px);font-weight:700;letter-spacing:-.065em;line-height:1.09;margin:22px 0;color:#f4feff}.home-headline span{background:linear-gradient(90deg,#67eee0,#b8ff78);background-clip:text;-webkit-background-clip:text;color:transparent}.home-description{max-width:690px;font-size:16px;line-height:1.8;color:#b0c7d2}.home-tags{display:flex;flex-wrap:wrap;gap:10px;margin-top:25px}.home-tags span{font:11px 'IBM Plex Mono',monospace;padding:9px 12px;border:1px solid rgba(103,238,224,.20);border-radius:30px;background:rgba(103,238,224,.055);color:#c3eae8}.feature-card{height:220px;background:linear-gradient(145deg,rgba(13,33,44,.94),rgba(7,18,28,.94));border:1px solid rgba(103,238,224,.17);border-radius:16px;padding:22px;margin-bottom:10px;display:flex;flex-direction:column}.feature-icon{font-size:27px;color:#67eee0}.feature-title{font-weight:700;font-size:19px;color:#f0fcff;margin:12px 0 8px}.feature-copy{font-size:13px;line-height:1.6;color:#a2bdca;flex:1}.feature-foot{font:10px 'IBM Plex Mono',monospace;letter-spacing:.10em;color:#76dfd7;margin-top:12px}.steps{display:flex;flex-wrap:wrap;gap:10px;margin:14px 0 22px}.steps span{flex:1;min-width:155px;border:1px solid rgba(103,238,224,.16);background:rgba(8,23,33,.8);border-radius:10px;padding:15px 12px;font-size:12px;color:#c4dce5}.steps b{color:#67eee0;font-family:'IBM Plex Mono',monospace;margin-right:8px}@media(max-width:900px){.home-hero{padding:32px 23px}.home-description{font-size:14px}.feature-card{height:auto;min-height:205px}}
</style>""",unsafe_allow_html=True)
for key in ('case','last_file_analysis','last_url_analysis','last_network_analysis','report_bytes'):
    if key not in st.session_state: st.session_state[key]=None
case=st.session_state.case
pages=['◈  Mission Control','▣  Case Workspace','⬡  File Intelligence','◎  URL Intelligence','◉  Network Intelligence','▤  Evidence Vault','▧  Report Studio']
st.sidebar.markdown('### ◈ THREATNOVA')
st.sidebar.caption('CYBERSECURITY INTELLIGENCE  //  DEFENSIVE')
st.sidebar.divider()
page=st.sidebar.radio('WORKSPACES',pages,label_visibility='visible',key='active_workspace')
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
    st.markdown(f'<div class="hero"><div class="eyebrow">THREATNOVA // {html.escape(code)}</div><div class="hero-title">{html.escape(title)}</div><div class="hero-sub">{html.escape(subtitle)}</div><div class="pill">ENGINE ONLINE &nbsp; // &nbsp; DEFENSIVE MODE</div></div>',unsafe_allow_html=True)
def label(s): st.markdown('<div class="section-label">'+html.escape(s)+'</div>',unsafe_allow_html=True)
def store(module,result):
    if st.session_state.case:
        {'file':st.session_state.case.add_file_result,'url':st.session_state.case.add_url_result,'network':st.session_state.case.add_network_result}[module](result)
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
    st.markdown("""<div class="home-hero">
      <div class="home-glow"></div>
      <div class="home-content">
        <div class="home-kicker"><span class="home-dot"></span> WELCOME TO THREATNOVA &nbsp; / &nbsp; CYBERSECURITY INTELLIGENCE</div>
        <div class="home-headline">See the Threat.<br><span>Own the Defense.</span></div>
        <div class="home-description">Your dedicated cybersecurity investigation workspace. Analyze suspicious files, inspect URLs, assess authorized network activity, and turn technical findings into clear, actionable intelligence — all in one place.</div>
        <div class="home-tags"><span>◈ Evidence-first analysis</span><span>⬡ Defensive by design</span><span>▤ Exportable reports</span></div>
      </div>
    </div>""",unsafe_allow_html=True)
    label('Your investigation at a glance')
    count=len(case.evidence) if case else 0
    a,b,c,d=st.columns(4)
    a.metric('Workspace status','ACTIVE' if case else 'READY')
    b.metric('Evidence collected',count)
    c.metric('Analysis modules','03')
    d.metric('Operating mode','DEFENSIVE')
    label('Explore ThreatNova')
    st.markdown('Choose a capability below to get started. All analysis is designed to support responsible, evidence-based investigation.')
    c1,c2,c3=st.columns(3)
    with c1:
        st.markdown('<div class="feature-card"><div class="feature-icon">⬡</div><div class="feature-title">File Intelligence</div><div class="feature-copy">Inspect file signatures, hashes, byte patterns, and suspicious indicators without executing uploaded samples.</div><div class="feature-foot">01 / STATIC FILE ANALYSIS</div></div>',unsafe_allow_html=True)
        if st.button('Explore file analysis →',key='home_file',use_container_width=True):
            st.session_state.active_workspace=pages[2]
            st.rerun()
    with c2:
        st.markdown('<div class="feature-card"><div class="feature-icon">◎</div><div class="feature-title">URL Intelligence</div><div class="feature-copy">Review URL structure, identify lexical risk signals, and optionally collect DNS resolution evidence.</div><div class="feature-foot">02 / URL RISK TRIAGE</div></div>',unsafe_allow_html=True)
        if st.button('Explore URL analysis →',key='home_url',use_container_width=True):
            st.session_state.active_workspace=pages[3]
            st.rerun()
    with c3:
        st.markdown('<div class="feature-card"><div class="feature-icon">◉</div><div class="feature-title">Network Intelligence</div><div class="feature-copy">Check selected TCP ports on private or loopback hosts you are authorized to assess.</div><div class="feature-foot">03 / AUTHORIZED NETWORK CHECKS</div></div>',unsafe_allow_html=True)
        if st.button('Explore network analysis →',key='home_network',use_container_width=True):
            st.session_state.active_workspace=pages[4]
            st.rerun()
    label('How ThreatNova works')
    st.markdown('<div class="steps"><span><b>01</b> Create a case</span><span><b>02</b> Collect evidence</span><span><b>03</b> Analyze signals</span><span><b>04</b> Document findings</span><span><b>05</b> Export reports</span></div>',unsafe_allow_html=True)
    if case and case.evidence:
        label('Recent case activity')
        st.dataframe([{'Evidence':e['evidence_id'],'Module':e['module'],'Recorded UTC':e['recorded_at'],'Risk / Status':e['result'].get('risk_level',e['result'].get('status',''))} for e in case.evidence[-30:]],use_container_width=True,hide_index=True)
        risks={k:sum(e['result'].get('risk_level')==k for e in case.evidence) for k in ('HIGH','MEDIUM','LOW','MINIMAL')}
        fig=go.Figure(go.Bar(x=list(risks),y=list(risks.values()),marker_color=['#ff6077','#ffb75e','#64d9ff','#b6ff64']))
        label('Risk distribution across evidence');chart_layout(fig,240)
    else:
        st.info('New here? Open Case Workspace in the sidebar to create your first investigation. Export your case JSON to preserve it between sessions.')
    st.caption('ThreatNova provides heuristic triage and local evidence analysis, not a guarantee that a file, URL, or host is safe.')
elif page==pages[1]:
    hero('CASE WORKSPACE','Case management','Create, import and export an investigation workspace with append-only evidence history.')
    with st.form('case_form'):
        a,b=st.columns(2);cid=a.text_input('Case ID',value='CASE-001');investigator=a.text_input('Investigator');title=b.text_input('Investigation title')
        if st.form_submit_button('Initialize case'):
            try:
                st.session_state.case=InvestigationCase(cid,title,investigator)
                for k in ('last_file_analysis','last_url_analysis','last_network_analysis','report_bytes'):st.session_state[k]=None
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
    hero('ENGINE 03 / NETWORK','Network intelligence',
         'Authorized local-network visibility: bounded TCP connection checks, port states and service hints.')
    st.info('Only assess devices you own or administer. This module accepts one private/loopback IP at a time, checks up to 24 explicitly selected TCP ports, and does not identify vulnerabilities.')
    left,right=st.columns([1.2,1])
    with left:
        target=st.text_input('Private or loopback IP address',value='127.0.0.1',key='network_target',help='Examples: 127.0.0.1, 192.168.1.10, 10.0.0.5')
    with right:
        ports=st.text_input('TCP ports (comma-separated; max 24)',value='22,80,443,445,3389,8080',key='network_ports')
    authorized=st.checkbox('I own or have explicit authorization to assess this host',key='network_authorized')
    if st.button('▶ Inspect TCP connectivity',type='primary'):
        try:
            with st.spinner('Checking selected TCP ports with bounded timeouts...'):
                st.session_state.last_network_analysis=analyze_network(target,ports,authorized=authorized)
                store('network',st.session_state.last_network_analysis)
            st.success('TCP connectivity check completed.')
        except ValueError as exc:
            st.error(str(exc))
        except OSError as exc:
            st.error(f'Network connectivity check failed: {exc}')
    if st.session_state.last_network_analysis:
        r=st.session_state.last_network_analysis
        label('Network snapshot')
        a,b,c,d=st.columns(4)
        a.metric('Target',r['target'])
        b.metric('TCP open',r['open_count'])
        c.metric('TCP closed',r['closed_count'])
        d.metric('Inconclusive',r['inconclusive_count'])
        tab1,tab2=st.tabs(['◈  Port visibility','▣  Scope & evidence'])
        with tab1:
            st.dataframe(r['results'],hide_index=True,use_container_width=True)
            if r['open_count']:
                label('Reachable TCP services (port-based hints only)')
                for item in r['results']:
                    if item['status']=='open':
                        st.markdown(f"**TCP {item['port']}** — {html.escape(item['service_hint'])} · connected in {item['elapsed_ms']} ms")
            else:
                st.caption('No successful TCP connections observed on the selected ports.')
        with tab2:
            st.json({k:v for k,v in r.items() if k!='results'})
            st.caption(r['note'])
        st.download_button('↓ Export network JSON',json.dumps(r,indent=2),
                           file_name='network_analysis.json',mime='application/json')
        st.caption('Network snapshots can be exported as JSON and are retained in the active case Evidence Vault.')
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
