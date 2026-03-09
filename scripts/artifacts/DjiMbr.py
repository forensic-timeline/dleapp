import struct 
from scripts.artifact_report import ArtifactHtmlReport
from scripts.ilapfuncs import logfunc

def partitionIdList(id):
    partitionTypes = {"01": "FAT12", "04": "FAT16", "0b": "FAT32", "0c": "FAT32 LBA", "07":"NTFS/exFAT"}
    return partitionTypes.get(id, "Unknown")

def get_dji_mbr(files_found, report_folder, seeker, wrap_text):
    data_list = []
    
    for file_found in files_found:
        file_found = str(file_found)
        target_file = file_found
        with open(file_found, 'rb') as f:
            data = f.read(512)
            if len(data) < 512:
                continue
            rawData = ["{:02x}".format(b) for b in data]
        
        # MBR signature check
        if rawData[511] == "aa" and rawData[510] == "55":
            oem_name = "".join([chr(int(b, 16)) for b in rawData[3:11]])
            
            if("MSDOS" in oem_name.upper() or "FAT32" in "".join([chr(int(b, 16)) for b in rawData[82:87]]).upper()):
                data_list.append(("VBR(Boot Sector)", "FAT32", "0 (Relative)", "N/A", oem_name, file_found))
            
            disk_signature = rawData[443] + rawData[442] + rawData[441] + rawData[440]
            
            # Parsing 1st Partition
            if rawData[450] != "00":
                part1_type = partitionIdList(rawData[450])
                lba1_hex = rawData[457] + rawData[456] + rawData[455] + rawData[454]
                lba1_start = int(lba1_hex, 16)
                no_sec1_hex = rawData[461] + rawData[460] + rawData[459] + rawData[458]
                no_sec1_count = int(no_sec1_hex, 16)
                
                data_list.append(("1st", part1_type, lba1_start, no_sec1_count, disk_signature, file_found))
            
            # Parsing 2nd Partition
            if rawData[466] != "00":
                part2_type = partitionIdList(rawData[466])
                lba2_hex = rawData[473] + rawData[472] + rawData[471] + rawData[470]
                lba2_start = int(lba2_hex, 16)
                no_sec2_hex = rawData[477] + rawData[476] + rawData[475] + rawData[474]
                no_sec2_count = int(no_sec2_hex, 16)
                
                data_list.append(("2nd", part2_type, lba2_start, no_sec2_count, disk_signature, file_found))
                
            # Parsing 3rd Partition
            if rawData[482] != "00":
                part3_type = partitionIdList(rawData[482])
                lba3_hex = rawData[489] + rawData[488] + rawData[487] + rawData[486]
                lba3_start = int(lba3_hex, 16)
                no_sec3_hex = rawData[493] + rawData[492] + rawData[491] + rawData[490]
                no_sec3_count = int(no_sec3_hex, 16)
                
                data_list.append(("3rd", part3_type, lba3_start, no_sec3_count, disk_signature, file_found))
            
            # Parsing 4th Partition
            if rawData[498] != "00":
                part4_type = partitionIdList(rawData[498])
                lba4_hex = rawData[505] + rawData[504] + rawData[503] + rawData[502]
                lba4_start = int(lba4_hex, 16)
                no_sec4_hex = rawData[509] + rawData[508] + rawData[507] + rawData[506]
                no_sec4_count = int(no_sec4_hex, 16)
                
                data_list.append(("4th", part4_type, lba4_start, no_sec4_count, disk_signature, file_found))
                
    if data_list:
        report = ArtifactHtmlReport('Drone MBR Information')
        report.start_artifact_report(report_folder, 'Drone MBR Information')
        report.add_script()
        headers = ('Partition', 'Type', 'LBA Start', 'No. Of Sectors', 'Disk Signature', 'Source File')
        report.write_artifact_data_table(headers, data_list, target_file)
        report.end_artifact_report()
    else:
        logfunc("No MBR Data Found")

__artifacts__ = {
    "dji_mbr": (
        "Drone System Information",
        ('*/*MBR*', '*_MBR*'),
        get_dji_mbr
    )
}