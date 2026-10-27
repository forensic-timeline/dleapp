import struct
from pathlib import Path

from scripts.artifact_report import ArtifactHtmlReport
from scripts.ilapfuncs import logfunc


# FAT32 entry
EOC_START = 0x0FFFFFF8
EOC_END = 0x0FFFFFFF
BAD_CLUSTER = 0x0FFFFFF7
RESERVED_START = 0x0FFFFFF0
RESERVED_END = 0x0FFFFFF6


def parse_fat32_bpb(boot_data):
    """
    Parse FAT32 BPB from a raw Boot Sector / VBR.
    Returns filesystem parameters or raises ValueError.
    """

    if len(boot_data) < 512:
        raise ValueError("Boot Sector is smaller than 512 bytes")

    if boot_data[510:512] != b"\x55\xAA":
        raise ValueError("Invalid Boot Sector signature")

    bytes_per_sector = struct.unpack_from(
        "<H", boot_data, 0x0B
    )[0]

    sectors_per_cluster = boot_data[0x0D]

    reserved_sectors = struct.unpack_from("<H", boot_data, 0x0E)[0]

    number_of_fats = boot_data[0x10]

    root_entry_count = struct.unpack_from("<H", boot_data, 0x11)[0]

    total_sectors_16 = struct.unpack_from("<H", boot_data, 0x13)[0]

    fat_size_16 = struct.unpack_from("<H", boot_data, 0x16)[0]

    total_sectors_32 = struct.unpack_from("<I", boot_data, 0x20)[0]

    fat_size_32 = struct.unpack_from("<I", boot_data, 0x24)[0]

    root_cluster = struct.unpack_from("<I", boot_data, 0x2C)[0] & 0x0FFFFFFF

    # Basic BPB validation
    if bytes_per_sector not in (512, 1024, 2048, 4096):
        raise ValueError("Invalid bytes-per-sector value")

    if (sectors_per_cluster == 0 or sectors_per_cluster & (sectors_per_cluster - 1)):
        raise ValueError("Invalid sectors-per-cluster value")

    if reserved_sectors == 0 or number_of_fats == 0:
        raise ValueError("Invalid reserved-sector or FAT count")

    # FAT32-specific BPB structure
    if root_entry_count != 0 or fat_size_16 != 0:
        raise ValueError("BPB does not match FAT32 structure")

    if fat_size_32 == 0:
        raise ValueError("Invalid FAT32 FAT size")

    total_sectors = total_sectors_16 or total_sectors_32

    if total_sectors == 0:
        raise ValueError("Invalid total sector count")

    fat_size_sectors = fat_size_32

    # RootDirSectors is zero for FAT32.
    root_dir_sectors = ((root_entry_count * 32 + bytes_per_sector - 1) // bytes_per_sector)

    data_sectors = total_sectors - (reserved_sectors + number_of_fats * fat_size_sectors + root_dir_sectors)

    if data_sectors <= 0:
        raise ValueError("Invalid data-region size")

    total_data_clusters = (data_sectors // sectors_per_cluster)

    if total_data_clusters <= 0:
        raise ValueError("No valid data clusters")

    # Data cluster IDs start at 2.
    max_cluster = total_data_clusters + 1

    return {
        "bytes_per_sector": bytes_per_sector,
        "sectors_per_cluster": sectors_per_cluster,
        "cluster_size": (bytes_per_sector * sectors_per_cluster),
        "reserved_sectors": reserved_sectors,
        "number_of_fats": number_of_fats,
        "total_sectors": total_sectors,
        "fat_size_sectors": fat_size_sectors,
        "fat_size_bytes": (fat_size_sectors * bytes_per_sector),
        "root_cluster": root_cluster,
        "total_data_clusters": total_data_clusters,
        "max_cluster": max_cluster,
    }


def find_matching_bpb(fat_path, actual_fat_size):
    """
    Find a matching raw Boot Sector/VBR in the FAT file's directory.

    The BPB must declare the same FAT byte length as the actual FAT file.
    If multiple incompatible candidates match, do not guess.
    """

    fat_path = Path(fat_path)
    directory = fat_path.parent

    matches = []

    try:
        candidates = sorted(directory.iterdir())
    except OSError as exc:
        logfunc(f"[ERROR] Cannot inspect directory for {fat_path}: {exc}")
        return None

    for candidate in candidates:
        if not candidate.is_file():
            continue

        if candidate.resolve() == fat_path.resolve():
            continue

        name = candidate.name.upper()

        # DLEAPP may label the extracted VBR as "$MBR".
        if not any(
            marker in name
            for marker in ("MBR", "VBR", "BOOT")
        ):
            continue

        try:
            boot_data = candidate.read_bytes()
            bpb = parse_fat32_bpb(boot_data)
        except (OSError, ValueError, struct.error):
            # Ignore non-BPB files or invalid candidate sectors.
            continue

        if bpb["fat_size_bytes"] != actual_fat_size:
            continue

        matches.append((candidate, bpb))

    if not matches:
        logfunc(
            "[ERROR] No matching FAT32 Boot Sector found for "
            f"{fat_path}. FAT analysis skipped."
        )
        return None

    # Compare all parameters that affect the volume layout.
    def profile_key(bpb):
        return (
            bpb["bytes_per_sector"],
            bpb["sectors_per_cluster"],
            bpb["reserved_sectors"],
            bpb["number_of_fats"],
            bpb["total_sectors"],
            bpb["fat_size_sectors"],
            bpb["root_cluster"],
        )

    profiles = {}

    for candidate, bpb in matches:
        key = profile_key(bpb)
        profiles.setdefault(key, []).append((candidate, bpb))

    if len(profiles) > 1:
        logfunc(
            "[ERROR] Multiple incompatible Boot Sector candidates "
            f"match {fat_path}. FAT analysis skipped."
        )
        return None

    # Multiple identical BPBs are acceptable for calculating layout.
    # The directory/provenance must still correspond to the same volume.
    candidate, bpb = next(iter(profiles.values()))[0]

    return candidate, bpb


def follow_chain(
    start,
    fat,
    max_cluster,
    globally_visited
):
    """
    Follow one cluster chain until EOC or a detected anomaly.
    """

    cur = start
    chain_length = 0
    fragmented = False
    corrupt = False
    local_visited = set()

    while True:
        if cur < 2 or cur > max_cluster:
            corrupt = True
            break

        if cur in local_visited:
            # A cycle within this chain.
            corrupt = True
            break

        if cur in globally_visited:
            # The chain intersects another previously visited chain.
            corrupt = True
            break

        entry = fat[cur]

        # A chain must not continue into a free, bad, reserved, or invalid-entry cluster.
        if (entry == 0 or entry == 1 or entry == BAD_CLUSTER or RESERVED_START <= entry <= RESERVED_END):
            corrupt = True
            break

        local_visited.add(cur)
        globally_visited.add(cur)
        chain_length += 1

        # End of Chain
        if EOC_START <= entry <= EOC_END:
            break

        # A normal FAT32 next-cluster pointer
        if 2 <= entry < RESERVED_START:
            if entry > max_cluster:
                corrupt = True
                break

            if entry != cur + 1:
                fragmented = True

            cur = entry
            continue

        corrupt = True
        break

    return chain_length, fragmented, corrupt


def analyze_fat_entries(fat, max_cluster):
    """
    Classify data-cluster entries and reconstruct allocation chains.
    """

    free = 0
    allocated = 0
    eoc = 0
    bad = 0
    reserved = 0
    invalid_entries = 0
    invalid_pointers = 0

    referenced_clusters = set()
    chain_nodes = set()


    for cluster in range(2, max_cluster + 1):
        entry = fat[cluster]

        if entry == 0:
            free += 1

        elif EOC_START <= entry <= EOC_END:
            allocated += 1
            eoc += 1
            chain_nodes.add(cluster)

        elif entry == BAD_CLUSTER:
            bad += 1

        elif RESERVED_START <= entry <= RESERVED_END:
            reserved += 1

        elif entry == 1:
            invalid_entries += 1

        elif 2 <= entry < RESERVED_START:
            # The cur cluster has a non-free pointer value.
            allocated += 1
            chain_nodes.add(cluster)

            if entry <= max_cluster:
                referenced_clusters.add(entry)
            else:
                invalid_pointers += 1

        else:
            invalid_entries += 1

    start_clusters = sorted(chain_nodes - referenced_clusters)

    allocation_chains = 0
    longest_chain = 0
    fragmented_chains = 0
    corrupt_chains = 0

    globally_visited = set()

    for start in start_clusters:
        if start in globally_visited:
            continue

        length, fragmented, corrupt = follow_chain(start, fat, max_cluster, globally_visited)

        allocation_chains += 1
        longest_chain = max(longest_chain, length)

        if fragmented:
            fragmented_chains += 1

        if corrupt:
            corrupt_chains += 1

    for cluster in sorted(chain_nodes):
        if cluster in globally_visited:
            continue

        length, fragmented, corrupt = follow_chain(cluster, fat, max_cluster, globally_visited)

        allocation_chains += 1
        longest_chain = max(longest_chain, length)

        if fragmented:
            fragmented_chains += 1

        if corrupt:
            corrupt_chains += 1

    return {
        "allocated": allocated,
        "free": free,
        "eoc": eoc,
        "bad": bad,
        "reserved": reserved,
        "invalid_entries": invalid_entries,
        "invalid_pointers": invalid_pointers,
        "allocation_chains": allocation_chains,
        "longest_chain": longest_chain,
        "fragmented_chains": fragmented_chains,
        "corrupt_chains": corrupt_chains,
    }


def get_dji_fat(files_found, report_folder, seeker, wrap_text):
    data_list = []

    for file_found in files_found:
        file_found = str(file_found)
        fat_path = Path(file_found)

        try:
            data = fat_path.read_bytes()
        except OSError as exc:
            logfunc(f"[ERROR] Cannot read FAT file {file_found}: {exc}")
            continue

        entry_count = len(data) // 4

        if entry_count < 2:
            logfunc(f"[ERROR] Invalid FAT file: {file_found}")
            continue

        if len(data) % 4 != 0:
            logfunc(
                f"[WARNING] FAT file size is not divisible by 4: "
                f"{file_found}"
            )

        match = find_matching_bpb(fat_path, len(data))

        if match is None:
            continue

        boot_path, bpb = match

        raw_entries = struct.unpack(f"<{entry_count}I", data[:entry_count * 4])

        fat = [entry & 0x0FFFFFFF for entry in raw_entries]

        max_cluster = bpb["max_cluster"]

        if max_cluster >= len(fat):
            logfunc(
                f"[ERROR] FAT does not contain enough entries for "
                f"the volume described by {boot_path}. "
                f"File skipped: {file_found}"
            )
            continue

        metrics = analyze_fat_entries(fat, max_cluster)

        data_list.append((
            bpb["total_data_clusters"],
            entry_count,
            bpb["cluster_size"],
            metrics["allocated"],
            metrics["free"],
            metrics["eoc"],
            metrics["bad"],
            metrics["reserved"],
            metrics["allocation_chains"],
            metrics["longest_chain"],
            metrics["fragmented_chains"],
            metrics["corrupt_chains"],
            metrics["invalid_pointers"],
            metrics["invalid_entries"],
            str(boot_path),
            file_found,
        ))

    if data_list:
        report = ArtifactHtmlReport("Drone FAT (Filesystem) Information")

        report.start_artifact_report(report_folder, "Drone FAT (Filesystem) Information")

        headers = (
            "Total Data Clusters",
            "FAT Entry Capacity",
            "Cluster Size (Bytes)",
            "Allocated Clusters (Including EOC)",
            "Free Clusters",
            "EOC Clusters",
            "Bad Clusters",
            "Reserved Marker Entries",
            "Allocation Chains",
            "Longest Chain (Clusters)",
            "Fragmented Chains",
            "Corrupt Chains",
            "Invalid Pointers",
            "Invalid Entries",
            "Boot Sector Source",
            "Source File",
        )

        report.write_artifact_data_table(headers, data_list, data_list[0][-1])

        report.end_artifact_report()

    else:
        logfunc("No analyzable DJI FAT32 data found")


__artifacts__ = {
    "dji_fat": (
        "Drone FAT Information",
        ("**/*FAT*"),
        get_dji_fat
    )
}