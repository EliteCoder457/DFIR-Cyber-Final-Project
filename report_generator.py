"""Paginated, escaped investigation PDF with evidence IDs and findings."""
import os,re,tempfile
from html import escape
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet,ParagraphStyle
from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,KeepTogether

def generate_report(case_data,output_dir='reports'):
    os.makedirs(output_dir,exist_ok=True)
    safe=re.sub(r'[^a-zA-Z0-9_-]','_',str(case_data['case_id']))[:70]
    path=os.path.join(output_dir,f'Investigation_{safe}.pdf')
    styles=getSampleStyleSheet();styles.add(ParagraphStyle(name='SmallMono',parent=styles['BodyText'],fontSize=8,leading=12,spaceAfter=5,wordWrap='CJK'))
    story=[]
    def line(value,style='BodyText'):
        story.append(Paragraph(escape(str(value)).replace('\n','<br/>'),styles[style]));story.append(Spacer(1,5))
    line('DIGITAL FORENSICS INVESTIGATION REPORT','Title')
    for key in ('case_id','case_title','investigator','created_at'):line(f'{key.replace("_"," ").title()}: {case_data.get(key,"")}')
    story.append(Spacer(1,15));line('Evidence and findings','Heading2')
    evidence=case_data.get('evidence') or [{'evidence_id':'LEGACY','module':k,'recorded_at':'unknown','result':v} for k,v in case_data.get('results',{}).items() if v]
    if not evidence:line('No evidence collected.')
    for record in evidence:
        result=record.get('result') or {}
        line(f"{record.get('evidence_id','')} | {record.get('module','')} | {record.get('recorded_at','')}",'Heading3')
        for key in ('file_name','url','detected_type','size_readable','risk_level','risk_score','status','source','message'):
            if key in result:line(f'{key}: {result[key]}','SmallMono')
        for key,value in result.get('hashes',{}).items():line(f'{key.upper()}: {value}','SmallMono')
        for indicator in result.get('indicators',[]):line(f"[{indicator.get('severity','')}] {indicator.get('message','')}",'SmallMono')
        for recommendation in result.get('recommendations',[]):line('NEXT STEP: '+str(recommendation),'SmallMono')
        if result.get('content_profile'):
            profile=result['content_profile'];line('Sampled bytes: '+str(profile.get('sampled_bytes',''))+'; printable ratio: '+str(profile.get('printable_ratio',''))+'%','SmallMono')
        if result.get('risk_breakdown'):line('Risk contribution: '+str(result['risk_breakdown']),'SmallMono')
        if result.get('network'):line('Network metadata: '+str(result['network'])[:1200],'SmallMono')
        if result.get('note'):line(result['note'],'SmallMono')
        story.append(Spacer(1,12))
    line('Investigator observations','Heading2')
    for obs in case_data.get('observations',[]):
        if isinstance(obs,dict):line(f"{obs.get('recorded_at','')}: {obs.get('text','')}")
        else:line(obs)
    story.append(Spacer(1,15));line('Scope: preliminary static triage. Findings are not proof of maliciousness, absence of compromise, or a complete chain of custody.','Italic')
    doc=SimpleDocTemplate(path,pagesize=A4,rightMargin=42,leftMargin=42,topMargin=48,bottomMargin=48)
    def footer(canvas,doc):
        canvas.saveState();canvas.setFont('Helvetica',8);canvas.drawRightString(A4[0]-42,24,f'Page {doc.page}');canvas.restoreState()
    doc.build(story,onFirstPage=footer,onLaterPages=footer)
    return path
