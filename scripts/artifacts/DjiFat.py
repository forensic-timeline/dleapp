import struct
from scripts.artifact_report import ArtifactHtmlReport
from scripts.ilapfuncs import logfunc

def get_dji_fat(files_found, report_folder, seeker, wrap_text):
    data_list = []
    
    for file_found in files_found:
        file_found = str(file_found)
        target_file = file_found
        
        # Initialize counter for spaces variables 
        free = 0
        allocated = 0
        eoc = 0
        
        with open(file_found, 'rb') as f:
            f.read(8) # Skip the 2 first cluster (reserved for the boot sector)
            while True:
                chunk = f.read(4)
                if not chunk or len(chunk) < 4: 
                    break
                
                entry = struct.unpack('<I', chunk)[0] & 0x0FFFFFFF
                
                # Fat32 uses 28 bits for cluster addresses, the upper 4 bits are reserved
                if entry == 0:
                    free += 1
                elif 0x0FFFFFF8 <= entry <= 0x0FFFFFFF:
                    eoc += 1
                else:
                    allocated += 1
                
        data_list.append((allocated, free, eoc, file_found))
    
    if data_list:
        report = ArtifactHtmlReport('Drone FAT(filesystem) Information')
        report.start_artifact_report(report_folder, 'Drone FAT(filesystem) Information')
        headers = ('Allocated Clusters', 'Free Clusters', 'End of Chain Clusters', 'Source File')
        report.write_artifact_data_table(headers, data_list, target_file)
        report.end_artifact_report()
    else:
        logfunc('No DJI FAT32 data found')

__artifacts__ = {
    "dji_fat": (
        "Drone System Information",
        ('**/*FAT*'),
        get_dji_fat
    )
}