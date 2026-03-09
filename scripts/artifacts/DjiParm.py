import re
from scripts.artifact_report import ArtifactHtmlReport
from scripts.ilapfuncs import logfunc, tsv

def get_dji_parm(files_found, report_folder, seeker, wrap_text):
    data_list = []
    
    for file_found in files_found:
        file_found = str(file_found)
        target_file = file_found
        with open(file_found, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                match = re.search(r'<([\d.]+)>\(([\d-]+)\)(.*)', line)
                if match:
                    timestamp = match.group(1)
                    log_id = match.group(2)
                    message = match.group(3).strip()
                    
                    data_list.append((timestamp, log_id, message, file_found))
    # Write the report into html report file
    if data_list:
        report = ArtifactHtmlReport('Drone Log Info')
        headers = ('Timestamp', 'Log ID', 'Event Message', 'Source File')
        report.start_artifact_report(report_folder, 'Drone Log Info')
        report.write_artifact_data_table(headers, data_list, target_file)
        report.end_artifact_report()
    else:
        logfunc('No DJI system log found')
    
__artifacts__ = {
    "dji_parms": (
        "Drone System Information", 
        ('**/PARM.LOG'),
        get_dji_parm
    )
}