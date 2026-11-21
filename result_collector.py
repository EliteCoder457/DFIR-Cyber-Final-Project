"""Case and append-only evidence history, with JSON round-trip."""
import copy,json,uuid
from datetime import datetime,timezone

def now(): return datetime.now(timezone.utc).isoformat()
class InvestigationCase:
    MODULES=('file_analysis','url_analysis','data_leak','port_analysis')
    def __init__(self,case_id,case_title,investigator):
        if not all(str(x).strip() for x in (case_id,case_title,investigator)): raise ValueError('All case fields are required')
        self.case_id=str(case_id)[:80];self.case_title=str(case_title)[:200];self.investigator=str(investigator)[:120];self.created_at=now()
        self.results={k:None for k in self.MODULES};self.evidence=[];self.observations=[]
    def _add(self,module,result):
        record={'evidence_id':uuid.uuid4().hex[:12].upper(),'module':module,'recorded_at':now(),'result':copy.deepcopy(result)}
        self.evidence.append(record);self.results[module]=copy.deepcopy(result);return record
    def add_file_result(self,result):return self._add('file_analysis',result)
    def add_url_result(self,result):return self._add('url_analysis',result)
    def add_leak_result(self,result):return self._add('data_leak',result)
    def add_port_result(self,result):return self._add('port_analysis',result)
    def add_observation(self,text):
        if str(text).strip():self.observations.append({'recorded_at':now(),'text':str(text).strip()[:10000]})
    def get_case_data(self):return copy.deepcopy({'schema_version':2,'case_id':self.case_id,'case_title':self.case_title,'investigator':self.investigator,'created_at':self.created_at,'results':self.results,'evidence':self.evidence,'observations':self.observations})
    @classmethod
    def from_dict(cls,data):
        obj=cls(data['case_id'],data['case_title'],data['investigator']);obj.created_at=data.get('created_at',now());obj.evidence=data.get('evidence',[]);obj.observations=data.get('observations',[])
        obj.results={k:data.get('results',{}).get(k) for k in cls.MODULES};return obj
