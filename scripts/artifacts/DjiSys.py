import struct
import re
from scripts.artifact_report import ArtifactHtmlReport
from scripts.ilapfuncs import logfunc

def get_dji_sys(files_found, report_folder, seeker, wrap_text):
    data_list = []
    for file_found in files_found:
        file_found = str(file_found)
        target_file = file_found
        if 'SYS.DJI' in str(file_found).upper():
            with open(file_found, 'rb') as f:
                content = f.read()
                
                if len(content) >= 13:
                    field_1 = struct.unpack('<I', content[3:7])[0]
                    counter = struct.unpack('<I', content[7:11])[0]
                    status = content[12]
                    data_list.append((hex(field_1), counter, status, file_found))
                
                # Extraction for serial number pattern usually alphanumeric
                # sn_match = re.search(r'([A-Z0-9]{14,16})', content.decode(errors='ignore'))
                # sn = sn_match.group(0) if sn_match else 'N/A'
                
                # # Extraction for DJI model 
                # model_match = re.search(r'(DJI\s[\w\s]+)', content.decode(errors='ignore'))
                # model = model_match.group(0) if model_match else 'N/A'
                
                # data_list.append((model, sn, file_found))
    
    if data_list:
        report = ArtifactHtmlReport('DJI SYS Info')
        report.start_artifact_report(report_folder, 'DJI SYS Info')
        report.add_script()
        headers = ('ID Field', 'Counter Value', 'Status Flag', 'Source File')
        report.write_artifact_data_table(headers, data_list, target_file)
        report.end_artifact_report()
    else:
        logfunc('No DJI SYS data found')

__artifacts__ = {
    "dji_sys": (
        "Drone system information",
        ('*/SYS.DJI*'),
        get_dji_sys
    )
}