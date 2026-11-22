"""CLI entrypoint. Run `streamlit run app_final.py` for the web UI."""
import argparse,json
from pathlib import Path
from file_analysis import analyze_file
from url_analysis import analyze_url
from network_analysis import analyze_network
from result_collector import InvestigationCase
from report_generator import generate_report

def run(argv=None):
    parser=argparse.ArgumentParser(description='Defensive digital-forensics triage')
    parser.add_argument('--file');parser.add_argument('--url');parser.add_argument('--network-ip');parser.add_argument('--ports',default='22,80,443');parser.add_argument('--authorized',action='store_true');parser.add_argument('--online-dns',action='store_true');parser.add_argument('--case-id',default='CASE-CLI');parser.add_argument('--title',default='CLI investigation');parser.add_argument('--investigator',default='Analyst');parser.add_argument('--pdf',action='store_true');parser.add_argument('--output',default='case_results.json')
    args=parser.parse_args(argv)
    case=InvestigationCase(args.case_id,args.title,args.investigator)
    if args.file:case.add_file_result(analyze_file(args.file))
    if args.url:case.add_url_result(analyze_url(args.url,online=args.online_dns))
    if args.network_ip:case.add_network_result(analyze_network(args.network_ip,args.ports,authorized=args.authorized))
    data=case.get_case_data();Path(args.output).write_text(json.dumps(data,indent=2),encoding='utf-8')
    if args.pdf:print('PDF:',generate_report(data))
    print('Case JSON:',args.output)
    return data
if __name__=='__main__':run()
