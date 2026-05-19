import hashlib
import re
import struct
import zipfile
import zlib
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Set, Tuple

from wiiu_constants import CEMU_PARTITION_FOLDERS, FST_MAGIC
from wiiu_crypto_nus import parse_tmd, wup_vwii_tid_to_slccmpt

SHF_RPL_ZLIB = 0x08000000
SHT_NOBITS = 8
XML_NAMES = ("app.xml", "cos.xml", "meta.xml")
MAX_REPORTED = 40

_VERIFIED: Dict[Tuple[str, str, int], Tuple[Tuple, Dict[str, int]]] = {}


def _entry_signature(names: List[str], sizes: Dict[str, int], crcs: Dict[str, int]) -> Tuple:
    return tuple(sorted((n, sizes[n], crcs[n]) for n in names if n in sizes))


def parse_fst_files(fst: bytes) -> List[Tuple[str, int]]:
    if len(fst) < 0x20 or fst[:4] != FST_MAGIC:
        raise ValueError("Not an FST")
    info_count = struct.unpack_from(">I", fst, 0x08)[0]
    entries_ptr = 0x20 + info_count * 0x20
    total_entries = struct.unpack_from(">I", fst, entries_ptr + 8)[0]
    name_table_off = entries_ptr + total_entries * 0x10
    if not (0 < total_entries < 100000) or name_table_off > len(fst):
        raise ValueError("Corrupt FST entry table bounds")

    files: List[Tuple[str, int]] = []
    path_stack: List[str] = []
    end_stack: List[int] = [total_entries]
    for i in range(1, total_entries):
        while i >= end_stack[-1]:
            path_stack.pop()
            end_stack.pop()
        off = entries_ptr + i * 0x10
        e_type = fst[off]
        e_name_off = (fst[off + 1] << 16) | (fst[off + 2] << 8) | fst[off + 3]
        e_off, e_len = struct.unpack_from(">II", fst, off + 4)
        name_start = name_table_off + e_name_off
        name_end = fst.find(b"\x00", name_start)
        if name_end == -1:
            raise ValueError("Unterminated FST filename")
        name = fst[name_start:name_end].decode("utf-8")
        if e_type & 0x01:
            path_stack.append(name)
            end_stack.append(e_len)
        elif not (e_type & 0x80):
            files.append(("/".join(path_stack + [name]), e_len))
    return files


def xml_is_readable(data: bytes) -> bool:
    text = data.rstrip(b"\x00").strip().decode("utf-8", errors="replace")
    try:
        ET.fromstring(text)
        return True
    except ET.ParseError:
        pass
    text = re.sub(r"<(/?)(\d)", r"<\1_\2", text)
    text = re.sub(r"&(?!(?:amp|lt|gt|quot|apos|#\d+|#x[0-9a-fA-F]+);)", "&amp;", text)
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", text)
    try:
        ET.fromstring(text)
        return True
    except ET.ParseError:
        return False


def rpl_problem(data: bytes) -> Optional[str]:
    if len(data) < 0x34 or data[:4] != b"\x7fELF":
        return "missing ELF header"
    if data[4] != 1 or data[5] != 2:
        return "not a 32-bit big-endian ELF"
    if struct.unpack_from(">H", data, 0x12)[0] != 20:
        return "not a PowerPC ELF"
    shoff = struct.unpack_from(">I", data, 0x20)[0]
    shentsize, shnum = struct.unpack_from(">HH", data, 0x2E)
    if shentsize != 0x28 or shoff + shnum * shentsize > len(data):
        return "invalid section table"
    for index in range(shnum):
        base = shoff + index * shentsize
        sh_type = struct.unpack_from(">I", data, base + 4)[0]
        flags, _addr, offset, size = struct.unpack_from(">IIII", data, base + 8)
        if sh_type == SHT_NOBITS or size == 0:
            continue
        if offset + size > len(data):
            return f"section {index} exceeds the file"
        if flags & SHF_RPL_ZLIB:
            section = data[offset:offset + size]
            expected = struct.unpack_from(">I", section, 0)[0]
            try:
                inflated = zlib.decompress(section[4:])
            except zlib.error as exc:
                return f"section {index} zlib error: {exc}"
            if len(inflated) != expected:
                return f"section {index} inflates to {len(inflated)} bytes, expected {expected}"
    return None


def _verify_wiiu_title(
    z: zipfile.ZipFile,
    sizes: Dict[str, int],
    crcs: Dict[str, int],
    base_names: List[str],
    base: str,
    tid: str,
    version: int,
    problems: List[str],
    stats: Dict[str, int],
) -> None:
    signature = _entry_signature(base_names, sizes, crcs)
    memo = _VERIFIED.get(("wiiu", tid, version))
    if memo is not None and memo[0] == signature:
        for key, value in memo[1].items():
            stats[key] += value
        return
    problems_before = len(problems)
    local = {"wiiu_files": 0, "xml": 0, "rpx": 0}
    _verify_wiiu_title_files(z, sizes, base, tid, version, problems, local)
    for key, value in local.items():
        stats[key] += value
    if len(problems) == problems_before:
        _VERIFIED[("wiiu", tid, version)] = (signature, local)


def _verify_wiiu_title_files(
    z: zipfile.ZipFile,
    sizes: Dict[str, int],
    base: str,
    tid: str,
    version: int,
    problems: List[str],
    stats: Dict[str, int],
) -> None:
    tmd_name = f"{base}/code/title.tmd"
    if tmd_name not in sizes:
        problems.append(f"{tid}: code/title.tmd missing")
        return
    tmd_raw = z.read(tmd_name)
    tmd = parse_tmd(tmd_raw)
    if f"{tmd.title_id:016x}" != tid:
        problems.append(f"{tid}: TMD title id is {tmd.title_id:016x}")
    if tmd.title_version != version:
        problems.append(f"{tid}: TMD version v{tmd.title_version} but expected v{version}")
    body_len = (0xB04 + tmd.content_count * 0x30) if tmd.version == 1 else (0x1E4 + tmd.content_count * 0x24)
    if len(tmd_raw) != body_len:
        problems.append(f"{tid}: title.tmd is {len(tmd_raw)} bytes, expected {body_len}")

    fst_name = f"{base}/code/title.fst"
    expected: Dict[str, int] = {}
    if fst_name in sizes:
        try:
            for rel, size in parse_fst_files(z.read(fst_name)):
                expected[f"{base}/{rel}"] = size
        except (ValueError, struct.error, UnicodeDecodeError) as exc:
            problems.append(f"{tid}: unreadable title.fst ({exc})")
            return
        for arc, size in expected.items():
            if arc not in sizes:
                problems.append(f"{tid}: {arc[len(base) + 1:]} listed in the FST but missing")
            elif sizes[arc] != size:
                problems.append(f"{tid}: {arc[len(base) + 1:]} is {sizes[arc]} bytes, FST says {size}")
        allowed = {tmd_name, fst_name}
        extras = [n for n in sizes if n.startswith(base + "/") and n not in expected and n not in allowed]
        for extra in extras[:3]:
            problems.append(f"{tid}: unexpected file {extra[len(base) + 1:]}")
    else:
        for c in tmd.contents:
            arc = f"{base}/content/{c.id:08x}.app"
            if arc not in sizes:
                problems.append(f"{tid}: content {c.id:08x}.app missing")
            elif hashlib.sha1(z.read(arc)[:c.size]).digest() != c.hash:
                problems.append(f"{tid}: content {c.id:08x}.app fails SHA-1")
    stats["wiiu_files"] += len(expected) or len(tmd.contents)

    for arc in list(expected) or [n for n in sizes if n.startswith(base + "/")]:
        lower = arc.lower()
        name = lower.rsplit("/", 1)[-1]
        if name in XML_NAMES:
            if not xml_is_readable(z.read(arc)):
                problems.append(f"{tid}: {arc[len(base) + 1:]} is not readable XML")
            stats["xml"] += 1
        elif lower.endswith((".rpx", ".rpl")):
            issue = rpl_problem(z.read(arc))
            if issue:
                problems.append(f"{tid}: {arc[len(base) + 1:]} is not a readable RPL/RPX ({issue})")
            stats["rpx"] += 1


def _verify_vwii(
    z: zipfile.ZipFile,
    sizes: Dict[str, int],
    crcs: Dict[str, int],
    expected_tids: List[str],
    problems: List[str],
    stats: Dict[str, int],
) -> None:
    prefix = f"{CEMU_PARTITION_FOLDERS['vWii']}/"
    for required in ("shared1/content.map", "sys/uid.sys", "sys/cert.sys"):
        if prefix + required not in sizes:
            problems.append(f"vWii: {required} missing")
            return
    map_raw = z.read(prefix + "shared1/content.map")
    content_map = {map_raw[i + 8:i + 28]: map_raw[i:i + 8].decode() for i in range(0, len(map_raw), 28)}
    uid_raw = z.read(prefix + "sys/uid.sys")
    uid_tids = {uid_raw[i:i + 8].hex() for i in range(0, len(uid_raw), 12)}

    expected_internal = set()
    for tid in expected_tids:
        hi, lo = wup_vwii_tid_to_slccmpt(int(tid[:8], 16), int(tid[8:], 16))
        expected_internal.add(f"{hi:08x}{lo:08x}")

    present = {
        n.split("/")[2] + n.split("/")[3]
        for n in sizes
        if n.startswith(prefix + "title/") and n.endswith("/content/title.tmd")
    }
    for tid in sorted(expected_internal - present):
        problems.append(f"vWii: title {tid} missing")
    for tid in sorted(present - expected_internal):
        problems.append(f"vWii: unexpected title {tid}")

    for internal in sorted(present & expected_internal):
        hi, lo = internal[:8], internal[8:]
        base = f"{prefix}title/{hi}/{lo}"
        tmd_raw = z.read(f"{base}/content/title.tmd")
        tmd = parse_tmd(tmd_raw)
        if len(tmd_raw) != 0x1E4 + tmd.content_count * 0x24:
            problems.append(f"vWii {internal}: title.tmd is not a bare TMD")
        tik_name = f"{prefix}ticket/{hi}/{lo}.tik"
        if tik_name not in sizes:
            problems.append(f"vWii {internal}: ticket missing")
        else:
            tik = z.read(tik_name)
            if len(tik) != 0x2A4 or tik[0x1DC:0x1E4].hex() != internal:
                problems.append(f"vWii {internal}: ticket invalid ({len(tik)} bytes)")
        if internal not in uid_tids:
            problems.append(f"vWii {internal}: missing from uid.sys")
        problems_before = len(problems)
        content_names: List[Tuple[str, Optional[object]]] = []
        for c in tmd.contents:
            if c.type & 0x8000:
                shared_id = content_map.get(c.hash)
                if shared_id is None:
                    problems.append(f"vWii {internal}: shared content {c.id:08x} not in content.map")
                    continue
                name = f"{prefix}shared1/{shared_id}.app"
            else:
                name = f"{base}/content/{c.id:08x}.app"
            if name not in sizes:
                problems.append(f"vWii {internal}: {name.rsplit('/', 1)[-1]} missing")
                continue
            content_names.append((name, c))
        signature = _entry_signature([n for n, _c in content_names], sizes, crcs)
        memo = _VERIFIED.get(("vwii", internal, tmd.title_version))
        if memo is not None and memo[0] == signature and len(problems) == problems_before:
            stats["vwii_contents"] += memo[1]["vwii_contents"]
            continue
        verified_here = 0
        for name, c in content_names:
            data = z.read(name)
            if len(data) < c.size or hashlib.sha1(data[:c.size]).digest() != c.hash:
                problems.append(f"vWii {internal}: content {c.id:08x} fails SHA-1")
            verified_here += 1
        stats["vwii_contents"] += verified_here
        if len(problems) == problems_before:
            _VERIFIED[("vwii", internal, tmd.title_version)] = (signature, {"vwii_contents": verified_here})

    shared_files = {n for n in sizes if n.startswith(prefix + "shared1/") and n.endswith(".app")}
    if len(shared_files) != len(content_map):
        problems.append(f"vWii: {len(shared_files)} shared1 files but {len(content_map)} content.map entries")


def verify_extracted_archive(
    zip_path: str,
    titles_by_part: Dict[str, List[Tuple[str, int, str]]],
    check_crc: bool = True,
) -> Dict[str, int]:
    problems: List[str] = []
    stats = {"wiiu_titles": 0, "wiiu_files": 0, "xml": 0, "rpx": 0, "vwii_titles": 0, "vwii_contents": 0}
    with zipfile.ZipFile(zip_path) as z:
        if check_crc:
            bad = z.testzip()
            if bad is not None:
                problems.append(f"CRC-32 error on {bad}")
        sizes: Dict[str, int] = {}
        crcs: Dict[str, int] = {}
        names_by_base: Dict[str, List[str]] = {}
        for info in z.infolist():
            if info.filename.endswith("/"):
                continue
            sizes[info.filename] = info.file_size
            crcs[info.filename] = info.CRC
            parts = info.filename.split("/")
            if len(parts) >= 6 and parts[1] == "sys" and parts[2] == "title":
                names_by_base.setdefault("/".join(parts[:5]), []).append(info.filename)

        for part in ("SLC", "MLC"):
            folder = CEMU_PARTITION_FOLDERS[part]
            for tid, version, _name in titles_by_part.get(part, []):
                base = f"{folder}/sys/title/{tid[:8]}/{tid[8:]}"
                _verify_wiiu_title(z, sizes, crcs, names_by_base.get(base, []), base, tid, version, problems, stats)
                stats["wiiu_titles"] += 1

        vwii_tids = [t for t, _v, _n in titles_by_part.get("vWii", [])]
        if vwii_tids:
            _verify_vwii(z, sizes, crcs, vwii_tids, problems, stats)
            stats["vwii_titles"] = len(vwii_tids)

    if problems:
        for line in problems[:MAX_REPORTED]:
            print(f"[EXTRACT ERROR] {line}", flush=True)
        raise RuntimeError(
            f"Extraction verification failed for {zip_path} ({len(problems)} problem(s)); first: {problems[0]}"
        )
    print(
        f"[extract-check] {zip_path}: {stats['wiiu_titles']} Wii U titles ({stats['wiiu_files']} files, "
        f"{stats['xml']} XML, {stats['rpx']} RPX/RPL decompressed), {stats['vwii_titles']} vWii titles "
        f"({stats['vwii_contents']} contents) verified",
        flush=True,
    )
    return stats
