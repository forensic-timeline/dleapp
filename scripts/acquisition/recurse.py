import argparse
import csv
import datetime
import os
import pytsk3
import pyewf
from scripts.ilapfuncs import logfunc

# Derived class to handle EWF files with pytsk3
class ewf_Img_Info(pytsk3.Img_Info):
    def __init__(self, ewf_handle):
        self._ewf_handle = ewf_handle
        super().__init__()
    
    def read(self, offset, size):
        self._ewf_handle.seek(offset)
        return self._ewf_handle.read(size)
    
    def get_size(self):
        return self._ewf_handle.get_media_size()

def convert_time(ts):
    if str(ts) == '0' or ts is None:
        return ""
    return datetime.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")

# Use to extract files from the image    
def extract_data(fs_obj, out_path):
    try:
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, 'wb') as f:
            offset = 0
            size = fs_obj.info.meta.size
            while offset < size:
                to_read = min(1024 * 1024, size - offset)
                data = fs_obj.read_random(offset, to_read)
                if not data:
                    break
                f.write(data)
                offset += len(data)
    except Exception as e:
        print(f"\n[ERROR] Could not extract file to {out_path} : {e}")

def find_offset(img_info):
    """
    Scanning sector to find MBR FAT32/exFAT
    Used if filesystem does not contain MBR or FAT 
    """
    sector_size = 512
    # Scanning the first 100000 sector (10MB)
    max_scan_sector = 100000
    
    for i in range (max_scan_sector):
        offset = i * sector_size
        try:
            # Read 512 byte per sector
            data = img_info.read()
            if not data or len(data) < sector_size:
                break
            
            if data[3:11] == b'EXFAT   ':
                return offset
            
            if data[510:512] == b'\x55\xAA' and data[0] in [0xEB, 0xE9]:
                if b'FAT32' in data[54:82] or b'MSDOS' in data[3:11] or b'mfks' in data[3:11]:
                    return offset
        except Exception:
            continue
    return None


def recurseFiles(part, fs, dirs, parent, data, out_dir=None):
    """ Recursive function to traverse directories and extract the disk image files 
        Traverses all directories and files starting from the given directory object.
        Part - Partition number
        fs - Filesystem object
        dirs - Current directory object
        data - List to store file information
        parent - Current path in the filesystem
        out_dir - Output directory to extract files (if None, no extraction)
    """
    for fs_obj in dirs:
        try:
            name = fs_obj.info.name.name.decode('utf-8', 'ignore')
            if name in [".", ".."]:
                continue
            
            # Prevent path crashes on extraction
            path = f"{parent}/{name}".replace("//", "/")
            filetype = ""
            
            size = fs_obj.info.meta.size if fs_obj.info.meta else 0
            created = convert_time(fs_obj.info.meta.crtime) if fs_obj.info.meta else ""
            modified = convert_time(fs_obj.info.meta.mtime) if fs_obj.info.meta else ""
            
            if fs_obj.info.meta and fs_obj.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                try:
                    sub_dir = fs.open_dir(path=path)
                    recurseFiles(part, fs, sub_dir, path, data, out_dir)
                except:
                    continue
                # filetype = "DIR"
            else:
                if out_dir:
                    dest_folder = os.path.join(out_dir, f"PARTITION_{part}")
                    os.makedirs(dest_folder, exist_ok=True)
                    
                    dest_path = os.path.join(dest_folder, name)
                    print(f"[INFO] Extracting: {name}")
                    extract_data(fs_obj, dest_path)
                    
                    data.append([f"Partition_{part}", name, "FILE", "", "", fs_obj.info.meta.size, path])
                filetype = "FILE"
            
        except Exception as e:
            print(f"\n[ERROR] Could not process file system object: {e}")


def run_extraction(evidence_file, evidence_type, outdir):
    if evidence_type == "ewf":
        filename = pyewf.glob(evidence_file)
        handle = pyewf.handle()
        handle.open(filename)
        img_info = ewf_Img_Info(handle)
    else:
        img_info = pytsk3.Img_Info(evidence_file)
    
    all_data = []
    
    try:
        vol = pytsk3.Volume_Info(img_info)
        for p in vol:
            logfunc(f"Trying partition: {p.addr} - {p.desc} - {p.len} sectors")
            if b"Unallocated" not in p.desc and p.len > 2048:
                logfunc(f"Partition found at offset: {p.start * 512}")
                try:
                    fs = pytsk3.FS_Info(img_info, offset=p.start * 512)
                    root = fs.open_dir(path="/")
                    recurseFiles(p.addr, fs, root, "/", all_data, outdir)
                except: 
                    pass
    except Exception as e:
        print(f"Volume info failed: {e}")
        try:
            fs = pytsk3.FS_Info(img_info, offset=0)    
            root = fs.open_dir(path="/")
            recurseFiles(0, fs, root, "/", all_data, outdir)
        except Exception as e:
            offset = find_offset(img_info)
            if offset is not None:
                print(f"[INFO] Signature found at offset: {offset}")
                try:
                    fs = pytsk3.FS_Info(img_info, offset=offset)
                    root = fs.open_dir(path="/")
                    recurseFiles(f"RAW_OFFSET_{offset}", root, fs, "/", all_data, outdir)
                except Exception as err:
                    print(f"[ERROR] Offset found but directory corrupted: {err}")
            else:
                print("[ERROR] Filesystem does not contain any MBR")        
    return all_data

if __name__ == '__main__':
    # Parse Command-Line Arguments
    parser = argparse.ArgumentParser(description="DLEAPP - Drone Log Event and Protobuf Parser")
    parser.add_argument("EVIDENCE_FILE", help="Path to the evidence files")
    parser.add_argument("TYPE", help="Type of evidence", choices=("ewf", "raw"))
    parser.add_argument("-csv", dest="csv", help="Output CSV file", required=False)
    parser.add_argument("-p", help="Partition Type", choices=("DOS", "GPT", "MAC", "SUN"))
    parser.add_argument("-o", dest="outdir", help="Output directory to extraccted files", required=False)
    
    args = parser.parse_args()
    
    # Validate input arguments
    if not args.csv and not args.outdir:
        print("\n[ERROR] At least one of -csv or -o arguments must be used.")
        
    print(f"\n[INFO] Starting extraction from {args.EVIDENCE_FILE} of type {args.TYPE}")
    all_data = run_extraction(args.EVIDENCE_FILE, args.TYPE, args.outdir)
    
    if args.csv:
        print(f"\n[INFO] Writing output to CSV file")
        with open(args.csv, 'w', newline='', encoding='utf-8') as csvf:
            csv_writer = csv.writer(csvf)
            headers = ['PARTITION', 'FILENAME', 'TYPE', 'CREATED', 'MODIFIED', 'SIZE', 'PATH']
            csv_writer.writerows(headers)
        
    print("\n[INFO] Extraction completed.")