import os
import re
import sys
import time
import json
import zlib
import uuid
import shutil
import hashlib
import xml.etree.ElementTree as ET
from os import makedirs, remove
from os.path import exists, getsize, join
from zipfile import ZipFile, ZIP_STORED, ZipInfo
from subprocess import run, PIPE
from typing import Dict, List, Optional, Set, Tuple

from wiiu_constants import (
    AUTHENTIC_BUILDS_BY_REGION,
    BASE_DIR,
    CHUNK_SIZE,
    DEFAULT_TITLES_DB,
    JPN_200_EXACT_FALLBACK,
    PRE_200_EXACT_VERSIONS,
    RE_APP_XML_SDK,
    RE_FW_TUPLE,
    REGION_SUFFIX,
    SUFFIX_TO_REGION,
    TMD_CONTENT_FLAG_HASHED,
    VERSION_DATA_TIDS,
    VWII_STATIC_VERSIONS,
    WAVE_METADATA,
    format_regional_tag,
    format_wave_tag,
    is_valid_tid,
    log_print,
    normalize_tid,
    parse_fw_tuple,
)
from wiiu_crypto_nus import (
    Content,
    TMD,
    decode_version_bin_bytes,
    extract_single_file_from_fst_in_ram,
    get_common_key,
    parse_tmd,
    read_tmd_and_title_key,
    verify_wup_title_cryptography,
)


def verify_zip_archive_integrity(
    zip_path: str,
    expected_entries: Optional[List[str]] = None,
    required_prefixes: Optional[List[str]] = None,
    check_crc: bool = True,
) -> int:
    if not os.path.isfile(zip_path) or os.path.getsize(zip_path) < 22:
        raise RuntimeError(f"ZIP archive missing or empty: {zip_path}")

    errors: List[str] = []
    with ZipFile(zip_path, "r") as zf:
        bad_entry = zf.testzip() if check_crc else None
        if bad_entry is not None:
            errors.append(f"CRC-32 corruption detected in {zip_path} on entry: {bad_entry}")

        names = zf.namelist()
        if not names:
            errors.append(f"ZIP archive contains zero entries: {zip_path}")

        name_set = set(names)
        if len(name_set) != len(names):
            errors.append(f"Duplicate entries detected in ZIP archive: {zip_path}")

        for n in names:
            if n.startswith("/") or ".." in n.split("/"):
                errors.append(f"Unsafe path entry '{n}' inside ZIP archive: {zip_path}")

        if expected_entries is not None:
            missing = [e for e in expected_entries if e not in name_set]
            if missing:
                errors.append(
                    f"ZIP archive {zip_path} is missing {len(missing)} expected file(s), first: {missing[0]}"
                )

        if required_prefixes:
            for pref in required_prefixes:
                if not any(n.startswith(pref) for n in names):
                    errors.append(f"ZIP archive {zip_path} is missing required tree prefix: {pref}")

        if errors:
            for err in errors:
                print(f"[ZIP ERROR] {err}", flush=True)
            raise RuntimeError(
                f"ZIP verification failed for {zip_path} with {len(errors)} error(s):\n"
                + "\n".join(f"  - {e}" for e in errors)
            )

        return len(names)


def zip_virtual_tree_single_pass(
    folder_mappings: List[Tuple[str, str]],
    out_zip_path: str,
    include_empty_dirs: bool = False,
) -> None:
    entries: List[Tuple[str, str]] = []
    empty_dirs: List[str] = []
    seen_arc_names = set()
    for src_folder, arc_prefix in folder_mappings:
        if not exists(src_folder):
            raise FileNotFoundError(f"Source folder for ZIP packing does not exist: {src_folder}")
        for root, dirs, files in os.walk(src_folder):
            dirs.sort()
            if include_empty_dirs and not dirs and not files:
                rel_dir = os.path.relpath(root, start=src_folder).replace("\\", "/")
                parts = [p for p in (arc_prefix, "" if rel_dir == "." else rel_dir) if p]
                empty_dirs.append("/".join(parts) + "/")
            for name in sorted(files):
                if name.endswith(".tmp") or name in (".vwii_ready", ".cafe_ready"):
                    continue
                full = os.path.join(root, name)
                rel = os.path.relpath(full, start=src_folder).replace("\\", "/")
                arc_name = f"{arc_prefix}/{rel}" if arc_prefix else rel
                if arc_name in seen_arc_names:
                    raise ValueError(f"Duplicate archive target path '{arc_name}' while building {out_zip_path}")
                seen_arc_names.add(arc_name)
                entries.append((arc_name, full))

    if not entries:
        raise ValueError(f"Refusing to create empty ZIP archive: {out_zip_path}")

    entries.sort(key=lambda item: item[0])
    out_dir = os.path.dirname(os.path.abspath(out_zip_path))
    if out_dir:
        makedirs(out_dir, exist_ok=True)

    with ZipFile(out_zip_path, "w", compression=ZIP_STORED) as zf:
        for arc_name, full_path in entries:
            zinfo = ZipInfo(filename=arc_name, date_time=(2026, 1, 1, 0, 0, 0))
            zinfo.create_system = 0
            zinfo.external_attr = 0
            zinfo.compress_type = ZIP_STORED
            zinfo.file_size = os.path.getsize(full_path)
            with open(full_path, "rb") as f, zf.open(zinfo, "w") as out:
                shutil.copyfileobj(f, out, CHUNK_SIZE)
            if zinfo.file_size != os.path.getsize(full_path):
                raise IOError(f"File changed while packing {full_path}")
        for dir_name in sorted(set(empty_dirs)):
            dinfo = ZipInfo(filename=dir_name, date_time=(2026, 1, 1, 0, 0, 0))
            dinfo.create_system = 0
            dinfo.external_attr = 0x10
            zf.writestr(dinfo, b"")

    verify_zip_archive_integrity(out_zip_path, expected_entries=[item[0] for item in entries])


def resolve_vwii_versions(region: str, target_tuple: Tuple[int, int, int], include_vwii_in_1x: bool = True) -> Dict[str, int]:
    reg = region.upper()
    if target_tuple < (2, 0, 0):
        if not include_vwii_in_1x:
            return {}
        fw = (2, 0, 0)
    else:
        fw = target_tuple

    vwii_map = dict(VWII_STATIC_VERSIONS)
    if reg == "JPN":
        vwii_map["0000000700000002"] = 512 if fw < (4, 0, 0) else (544 if fw < (5, 2, 0) else 608)
    elif reg == "USA":
        vwii_map["0000000700000002"] = 513 if fw < (4, 0, 0) else (545 if fw < (5, 2, 0) else 609)
    else:
        vwii_map["0000000700000002"] = 514 if fw < (4, 0, 0) else (546 if fw < (5, 2, 0) else 610)

    vwii_map["0000000700000200"] = 6 if target_tuple < (1, 0, 2) else 7
    vwii_map["000000070000003b"] = 7201 if fw < (5, 0, 0) else (8737 if fw < (5, 2, 0) else 9249)
    vwii_map["000000070000003e"] = 6430 if fw < (5, 0, 0) else (6686 if fw < (5, 2, 0) else 6942)

    if fw < (2, 1, 0):
        man_ju, man_eur = 0, 0
    elif fw < (3, 0, 0):
        man_ju, man_eur = 1, 1
    elif fw < (4, 0, 0):
        man_ju, man_eur = 2, 2
    elif fw < (5, 0, 0):
        man_ju, man_eur = 3, 3
    elif fw < (5, 2, 0):
        man_ju, man_eur = 5, 4
    else:
        man_ju, man_eur = 5, 5

    vwii_map["000700024843554a"] = man_ju
    vwii_map["0007000248435545"] = man_ju
    vwii_map["0007000248435550"] = man_eur

    if target_tuple >= (5, 1, 0):
        for wagon_tid in ("0007000848435a4a", "0007000848435a45", "0007000848435a50"):
            vwii_map[wagon_tid] = 31
    return vwii_map


def apply_pre_intermediate_overrides(
    title_versions: Dict[str, int],
    region_upper: str,
    target_tuple: Tuple[int, int, int],
    pre_prefix: str = "PRE_",
) -> None:
    reg_idx = {"JPN": "0", "USA": "1", "EUR": "2"}[region_upper]

    if target_tuple in ((1, 0, 3), (1, 0, 4), (1, 0, 5)):
        title_versions["0005001010000200"] = 5128
        title_versions["000500101000400a"] = 1099
        title_versions[f"0005003010010{reg_idx}0a"] = 0
        title_versions[f"0005003010011{reg_idx}0a"] = 0
        title_versions[f"0005003010017{reg_idx}0a"] = 0
    elif target_tuple == (2, 1, 2):
        title_versions["000500101000400a"] = 3904
        title_versions["00050010100040ff"] = 1064
    elif target_tuple == (2, 2, 0):
        title_versions["000500101000400a"] = 4825
    elif target_tuple == (3, 0, 3):
        title_versions["000500101000400a"] = 5039
    elif target_tuple == (3, 0, 4):
        title_versions["000500101000400a"] = 5059
    elif target_tuple == (3, 2, 0):
        title_versions["000500101000400a"] = 5614
        title_versions[f"0005001010040{reg_idx}00"] = 116
        title_versions[f"0005001010047{reg_idx}00"] = 116
        title_versions[f"0005001010048{reg_idx}00"] = 100
        title_versions[f"0005001010049{reg_idx}00"] = 100
        title_versions[f"000500101004d{reg_idx}00"] = 84
        title_versions[f"000500101005a{reg_idx}00"] = 51
        title_versions[f"0005001b10059{reg_idx}00"] = 67
        title_versions[f"0005003010010{reg_idx}0a"] = 116
        title_versions[f"0005003010012{reg_idx}0a"] = 84
        title_versions[f"0005003010014{reg_idx}0a"] = 83
        title_versions[f"0005003010015{reg_idx}0a"] = 84
        title_versions[f"0005003010016{reg_idx}0a"] = 83
    elif target_tuple == (4, 1, 0):
        title_versions["000500101000400a"] = 5867
        title_versions[f"0005003010012{reg_idx}0a"] = 100
        title_versions[f"0005003010019{reg_idx}0a"] = 85
    elif target_tuple == (5, 0, 0) and pre_prefix == "PRE0_":
        title_versions["000500101000400a"] = 8076
        title_versions["00050010100040ff"] = 2054
    elif target_tuple == (5, 0, 0):
        title_versions["000500101000400a"] = 8156
        title_versions["00050010100040ff"] = 2072
        title_versions[f"0005001010040{reg_idx}00"] = 151
        title_versions[f"0005001010047{reg_idx}00"] = 135
        title_versions[f"0005001010048{reg_idx}00"] = 119
        title_versions[f"000500101004e{reg_idx}00"] = 112
        title_versions["0005001010066000"] = 12
        title_versions["0005001b10063000"] = 20
        title_versions[f"0005003010010{reg_idx}0a"] = 151
        title_versions[f"0005003010015{reg_idx}0a"] = 103
        title_versions[f"0005003010016{reg_idx}0a"] = 103
        title_versions[f"0005003010019{reg_idx}0a"] = 100
    elif target_tuple == (5, 1, 0):
        title_versions["000500101000400a"] = 8760
        title_versions[f"000500101004b{reg_idx}00"] = 64
        if region_upper in ("EUR", "JPN"):
            title_versions[f"000500101004e{reg_idx}00"] = 128
        title_versions[f"0005001010062{reg_idx}00"] = 12
        title_versions[f"0005001b10059{reg_idx}00"] = 112
        title_versions[f"0005003010013{reg_idx}0a"] = 80
        title_versions[f"0005003010014{reg_idx}0a"] = 99
        title_versions[f"0005003010016{reg_idx}0a"] = 112
        title_versions["000500301001a10a"] = 8
    elif target_tuple == (5, 2, 0):
        title_versions["000500101000400a"] = 9764
        title_versions[f"0005001010040{reg_idx}00"] = 169
        if region_upper == "USA":
            title_versions["000500101004e100"] = 128
        title_versions["0005001b10068000"] = 3
        title_versions[f"0005003010011{reg_idx}0a"] = 98
    elif target_tuple == (5, 3, 0):
        title_versions["000500101000400a"] = 11310
        title_versions[f"0005001010040{reg_idx}00"] = 176
        title_versions[f"0005001010047{reg_idx}00"] = 163
        if region_upper in ("EUR", "USA"):
            title_versions[f"0005001010062{reg_idx}00"] = 40
        title_versions[f"000500301006d{reg_idx}0a"] = 23


def resolve_authentic_build_versions(
    region: str,
    fw_version: str,
    pre_prefix: str,
    expected_vdata_ver: int,
    yls8_csv_text: str,
    include_vwii_in_1x: bool = True,
) -> Dict[str, int]:
    target_tuple = parse_fw_tuple(fw_version)
    region_upper = region.upper()
    vdata_tid = VERSION_DATA_TIDS[region_upper]
    is_pre_special = bool(pre_prefix)

    if is_pre_special and target_tuple >= (4, 1, 0):
        base_cutoff = (
            (target_tuple[0], target_tuple[1], target_tuple[2] - 1)
            if target_tuple[2] > 0
            else (
                (target_tuple[0], target_tuple[1] - 1, 99)
                if target_tuple[1] > 0
                else (target_tuple[0] - 1, 99, 99)
            )
        )
    else:
        base_cutoff = target_tuple

    if base_cutoff[0] < 2:
        title_versions = dict(PRE_200_EXACT_VERSIONS)
        if base_cutoff <= (1, 0, 1):
            title_versions["0005001010004009"] = 1005
            title_versions["0005003010017009"] = 0
            title_versions["0005003010017109"] = 0
            title_versions["0005003010017209"] = 0
        else:
            title_versions["0005001010004009"] = 1006
            title_versions["0005003010017009"] = 16
            title_versions["0005003010017109"] = 16
            title_versions["0005003010017209"] = 16

        if base_cutoff >= (1, 0, 2):
            r_idx = {"JPN": "0", "USA": "1", "EUR": "2"}[region_upper]
            title_versions["000500101000400a"] = 1099
            title_versions[f"0005003010010{r_idx}0a"] = 0
            title_versions[f"0005003010011{r_idx}0a"] = 0
            title_versions[f"0005003010017{r_idx}0a"] = 0

        if include_vwii_in_1x:
            title_versions.update(resolve_vwii_versions(region_upper, base_cutoff, include_vwii_in_1x=True))
    else:
        title_versions = {}
        lines = yls8_csv_text.strip().replace("\r", "").split("\n")

        for line in lines[1:]:
            parts = line.split(",")
            if len(parts) >= 4:
                tid = parts[0].strip().lower()
                csv_region = parts[1].strip().upper()

                if csv_region in (region_upper, "ALL", ""):
                    t_vers = parts[2].strip().split(" ")
                    u_vers = parts[3].strip().split(" ")
                    best_ver = None

                    for tv, uv in zip(t_vers, u_vers):
                        uv_match = RE_FW_TUPLE.search(uv)
                        if uv_match:
                            uv_tuple = (
                                int(uv_match.group(1)),
                                int(uv_match.group(2)),
                                int(uv_match.group(3)) if uv_match.group(3) else 0,
                            )
                        else:
                            uv_tuple = (4, 0, 1) if "10-07-13" in uv else (0, 0, 0)

                        if uv_tuple <= base_cutoff:
                            best_ver = tv.replace("v", "")
                        else:
                            break

                    if best_ver and best_ver.isdigit():
                        title_versions[tid] = int(best_ver)

        if region_upper == "JPN" and base_cutoff < (2, 1, 0):
            for jpn_tid, jpn_ver in JPN_200_EXACT_FALLBACK.items():
                if jpn_tid not in title_versions:
                    title_versions[jpn_tid] = jpn_ver

        vwii_versions = resolve_vwii_versions(region_upper, base_cutoff, include_vwii_in_1x=include_vwii_in_1x)
        for vwii_tid, vwii_ver in vwii_versions.items():
            if vwii_tid not in title_versions:
                title_versions[vwii_tid] = vwii_ver

    title_versions[vdata_tid] = expected_vdata_ver

    if is_pre_special:
        apply_pre_intermediate_overrides(title_versions, region_upper, target_tuple, pre_prefix=pre_prefix)

    return title_versions


def build_all_waves_plan(
    yls8_csv_text: str,
    target_filter: str = "",
    regions_filter: Optional[List[str]] = None,
) -> List[dict]:
    entries_by_wave: Dict[Tuple[Tuple[int, int, int], int, str], List[dict]] = {}
    pre_order = {"PRE0_": 0, "PRE_": 1, "": 2}
    active_regions = [r.upper() for r in (regions_filter or ["EUR", "USA", "JPN"])]

    norm_target = target_filter.strip()
    if norm_target.upper().startswith("PRE0_"):
        norm_target = norm_target[5:] + "-pre0"
    elif norm_target.upper().startswith("PRE_"):
        norm_target = norm_target[4:] + "-pre"

    for reg_upper in active_regions:
        reg_letter = REGION_SUFFIX[reg_upper]
        reg_builds = AUTHENTIC_BUILDS_BY_REGION[reg_upper]

        for idx, (fw_str, pre_prefix, exp_vdata_ver) in enumerate(reg_builds):
            w_tag = format_wave_tag(fw_str, pre_prefix)
            r_tag = format_regional_tag(fw_str, reg_letter, pre_prefix)
            legacy_folder = f"{pre_prefix}{fw_str}{reg_letter}"

            if norm_target and norm_target.upper() != "ALL":
                if norm_target.lower() not in (
                    w_tag.lower(),
                    r_tag.lower(),
                    legacy_folder.lower(),
                ):
                    continue

            v_map = resolve_authentic_build_versions(
                reg_upper, fw_str, pre_prefix, exp_vdata_ver, yls8_csv_text, include_vwii_in_1x=True
            )

            prev_v_map: Dict[str, int] = {}
            if idx > 0:
                prev_fw_str, prev_pre_prefix, prev_exp_vdata_ver = reg_builds[idx - 1]
                prev_v_map = resolve_authentic_build_versions(
                    reg_upper, prev_fw_str, prev_pre_prefix, prev_exp_vdata_ver, yls8_csv_text, include_vwii_in_1x=True
                )

            partitions: Dict[str, List[Tuple[str, int]]] = {"SLC": [], "MLC": [], "vWii": []}
            for part_name in ("SLC", "MLC", "vWii"):
                part_dict = DEFAULT_TITLES_DB[part_name]
                raw_tids = list(part_dict.get(reg_upper, [])) + list(part_dict.get("All", []))
                seen = set()
                for t in raw_tids:
                    clean = normalize_tid(t)
                    if clean not in seen and clean in v_map:
                        seen.add(clean)
                        partitions[part_name].append((clean, v_map[clean]))

            if not partitions["SLC"] or not partitions["MLC"]:
                raise RuntimeError(f"Incomplete partition plan generated for {r_tag}")

            fw_tup = parse_fw_tuple(fw_str)
            sort_key = (fw_tup, pre_order[pre_prefix], w_tag)
            entries_by_wave.setdefault(sort_key, []).append({
                "region": reg_upper,
                "reg_letter": reg_letter,
                "fw_str": fw_str,
                "pre_prefix": pre_prefix,
                "wave_tag": w_tag,
                "reg_tag": r_tag,
                "expected_vdata_ver": exp_vdata_ver,
                "partitions": partitions,
                "prev_versions": prev_v_map,
            })

    waves = []
    for sk in sorted(entries_by_wave.keys()):
        w_entries = entries_by_wave[sk]
        waves.append({
            "wave_tag": sk[2],
            "fw_tuple": sk[0],
            "is_pre": (sk[1] < 2),
            "entries": w_entries,
        })
    return waves


def _expected_internal_tmd_tid(part: str, nus_tid: str) -> str:
    if part == "vWii":
        if nus_tid.startswith("00000007"):
            return "00000001" + nus_tid[8:]
        if nus_tid.startswith("00070002"):
            return "00010002" + nus_tid[8:]
        if nus_tid.startswith("00070008"):
            return "00010008" + nus_tid[8:]
    return nus_tid


def _collect_title_region_errors(
    part: str,
    tid: str,
    tmd: TMD,
    reg_upper: str,
    errors: List[str],
    raw_tmd: Optional[bytes] = None,
) -> None:
    reg_idx = {"JPN": "0", "USA": "1", "EUR": "2"}[reg_upper]
    vwii_reg_hex = {"JPN": "4a", "USA": "45", "EUR": "50"}[reg_upper]

    if part in ("SLC", "MLC"):
        if tid.startswith("00050010100") and tid[11:13] in (
            "40", "41", "43", "44", "45", "47", "48", "49", "4a", "4b", "4c", "4d", "4e", "5a", "62"
        ):
            if tid[13] != reg_idx:
                errors.append(f"Cross-region system title {tid} detected in {reg_upper} build!")
        elif tid.startswith("0005001b100") and tid[11:13] in ("59", "67", "69"):
            if tid[13] != reg_idx:
                errors.append(f"Cross-region shared title {tid} detected in {reg_upper} build!")
        elif tid.startswith("00050030100") and tid[11:13] in (
            "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "6d"
        ):
            if tid[13] != reg_idx:
                errors.append(f"Cross-region applet {tid} detected in {reg_upper} build!")
    elif part == "vWii":
        if tid == "0000000700000002":
            if (tmd.title_version % 16) != int(reg_idx):
                errors.append(
                    f"Cross-region vWii System Menu v{tmd.title_version} detected in {reg_upper} build!"
                )
        elif tid[:14] in ("00070002484355", "0007000848414c", "0007000848435a"):
            if tid[14:16] != vwii_reg_hex:
                errors.append(f"Cross-region vWii channel {tid} detected in {reg_upper} build!")

        if raw_tmd is not None and len(raw_tmd) >= 0x19E and tid.startswith(("00070002", "00070008")):
            tmd_region = int.from_bytes(raw_tmd[0x19C:0x19E], "big")
            is_reg_locked_channel = tid[14:16] in ("4a", "45", "50")
            if is_reg_locked_channel and tmd_region != int(reg_idx):
                errors.append(
                    f"Cross-region vWii channel TMD region field {tmd_region} (expected {reg_idx}) on vWii/{tid}!"
                )
            elif not is_reg_locked_channel and tmd_region not in (3, int(reg_idx)):
                errors.append(
                    f"Unexpected vWii channel TMD region field {tmd_region} on vWii/{tid}!"
                )


def _check_title_region_consistency(part: str, tid: str, tmd: TMD, reg_upper: str) -> None:
    errs: List[str] = []
    _collect_title_region_errors(part, tid, tmd, reg_upper, errs)
    if errs:
        raise RuntimeError("\n".join(errs))


def _is_slc_os_dependency_satisfied(
    req_os_tid: str,
    slc_tids: Set[str],
    part: str = "",
    tid: str = "",
) -> bool:
    if req_os_tid in slc_tids:
        return True

    mapped_os_tid = (
        "00050010100040" + req_os_tid[14:]
        if req_os_tid.startswith("00050010100080")
        else req_os_tid
    )
    if mapped_os_tid in slc_tids:
        return True

    if mapped_os_tid.startswith("00050010100040") and len(mapped_os_tid) == 16:
        try:
            req_slot = int(mapped_os_tid[14:16], 16)
        except ValueError:
            return False
        if 0 <= req_slot <= 0x0A:
            for slc_tid in slc_tids:
                if slc_tid.startswith("00050010100040") and len(slc_tid) == 16:
                    try:
                        avail_slot = int(slc_tid[14:16], 16)
                    except ValueError:
                        continue
                    if req_slot <= avail_slot <= 0x0A:
                        return True

        if (
            req_os_tid == "000500101000800a"
            and "000500101000400a" not in slc_tids
            and "0005001010004009" in slc_tids
            and part == "MLC"
            and (tid.startswith("0005001b") or tid.startswith("0005001010041"))
        ):
            return True

    return False


def _is_vwii_ios_dependency_satisfied(req_ios_tid: str, vwii_tids: Set[str]) -> bool:
    if req_ios_tid in vwii_tids:
        return True

    if req_ios_tid.startswith("00000001") and len(req_ios_tid) == 16:
        mapped_vwii_tid = "00000007" + req_ios_tid[8:]
        if mapped_vwii_tid in vwii_tids:
            return True

    return False


def audit_wiiu_wave_tmd_integrity(
    title_dirs_by_part_tid: Dict[Tuple[str, str], str],
    reg_upper: str,
    errors_out: Optional[List[str]] = None,
) -> dict:
    errors: List[str] = errors_out if errors_out is not None else []
    slc_tids: Set[str] = {tid for (part, tid) in title_dirs_by_part_tid if part == "SLC"}
    vwii_tids: Set[str] = {tid for (part, tid) in title_dirs_by_part_tid if part == "vWii"}
    tmd_v1_count = 0
    tmd_v0_count = 0
    total_contents = 0
    h3_contents = 0
    total_decrypted_bytes = 0
    total_encrypted_bytes = 0

    for (part, tid), t_dir in sorted(title_dirs_by_part_tid.items()):
        tmd_path = join(t_dir, "title.tmd")
        if not exists(tmd_path):
            errors.append(f"Missing title.tmd for {part}/{tid}")
            continue
        try:
            with open(tmd_path, "rb") as f_tmd:
                raw_tmd = f_tmd.read()
            if len(raw_tmd) < 0x1E4:
                errors.append(f"Truncated title.tmd ({len(raw_tmd)} bytes < 0x1E4) for {part}/{tid}")
                continue
            tmd = parse_tmd(raw_tmd)
        except Exception as exc:
            errors.append(f"Failed to parse title.tmd for {part}/{tid}: {exc}")
            continue

        expected_hdr_tid = _expected_internal_tmd_tid(part, tid)
        if f"{tmd.title_id:016x}" != expected_hdr_tid:
            errors.append(
                f"TMD Title ID mismatch on {part}/{tid}: expected {expected_hdr_tid}, header contains {tmd.title_id:016x}"
            )

        is_vwii_flag = raw_tmd[0x183]
        tmd_title_type = int.from_bytes(raw_tmd[0x194:0x198], "big")
        if part == "vWii":
            if tmd.version != 0:
                errors.append(f"Expected TMD v0 for vWii/{tid}, got v{tmd.version}")
            if is_vwii_flag != 1:
                errors.append(f"Expected TMD Is_vWii=1 at offset 0x183 for vWii/{tid}, got {is_vwii_flag}")
            if (tmd_title_type & 0x1) == 0:
                errors.append(
                    f"vWii TMD title_type 0x{tmd_title_type:08X} missing Default (0x1) flag on vWii/{tid}"
                )
        else:
            if tmd.version != 1:
                errors.append(f"Expected TMD v1 for {part}/{tid}, got v{tmd.version}")
            if is_vwii_flag != 0:
                errors.append(f"Expected TMD Is_vWii=0 at offset 0x183 for {part}/{tid}, got {is_vwii_flag}")
            if (tmd_title_type & 0x100) == 0:
                errors.append(
                    f"Wii U TMD title_type 0x{tmd_title_type:08X} missing Cafe (0x100) flag on {part}/{tid}"
                )

        if not tmd.contents or tmd.boot_index >= len(tmd.contents) or tmd.contents[tmd.boot_index].size == 0:
            errors.append(f"Invalid TMD boot_index {tmd.boot_index} on {part}/{tid}")

        _collect_title_region_errors(part, tid, tmd, reg_upper, errors, raw_tmd=raw_tmd)

        if part in ("SLC", "MLC") and tmd.system_version != 0 and slc_tids:
            req_os_tid = f"{tmd.system_version:016x}"
            if not _is_slc_os_dependency_satisfied(req_os_tid, slc_tids, part=part, tid=tid):
                errors.append(
                    f"TMD dependency check failed: {part}/{tid} requires OS {req_os_tid}, missing from SLC!"
                )
        elif part == "vWii" and vwii_tids:
            is_vwii_ios = (
                tid.startswith("00000007000000")
                and tid not in ("0000000700000002", "0000000700000200", "0000000700000201")
            )
            if tmd.system_version == 0:
                if tid == "0000000700000002" or tid.startswith(("00070002", "00070008")):
                    errors.append(
                        f"vWii TMD dependency check failed: {tid} has sys_version=0 (missing required IOS)"
                    )
            else:
                if is_vwii_ios:
                    errors.append(
                        f"vWii IOS {tid} has non-zero sys_version 0x{tmd.system_version:016x} (expected 0)"
                    )
                req_ios_tid = f"{tmd.system_version:016x}"
                if not _is_vwii_ios_dependency_satisfied(req_ios_tid, vwii_tids):
                    errors.append(
                        f"vWii TMD dependency check failed: {tid} requires IOS {req_ios_tid}, missing from vWii!"
                    )

        if tmd.version == 1:
            tmd_v1_count += 1
        else:
            tmd_v0_count += 1

        seen_cids: Set[int] = set()
        seen_cindices: Set[int] = set()
        for c in tmd.contents:
            total_contents += 1
            total_decrypted_bytes += c.size
            if c.id in seen_cids:
                errors.append(f"Duplicate content ID {c.id:08X} in TMD of {part}/{tid}")
            seen_cids.add(c.id)
            if c.index in seen_cindices:
                errors.append(f"Duplicate content index {c.index} in TMD of {part}/{tid}")
            seen_cindices.add(c.index)
            if c.size == 0:
                errors.append(f"Zero-byte content {c.id:08X} in TMD of {part}/{tid}")
            if (c.type & 0x0001) == 0:
                errors.append(f"Invalid content type 0x{c.type:04X} on {c.id:08X} of {part}/{tid}")

            app_p = join(t_dir, f"{c.id:08X}.app")
            if exists(app_p):
                app_sz = getsize(app_p)
                total_encrypted_bytes += app_sz
                if app_sz < c.size:
                    errors.append(
                        f"Truncated content {c.id:08X}.app for {part}/{tid}: {app_sz} bytes < TMD size {c.size}"
                    )
            else:
                errors.append(f"Missing encrypted content {c.id:08X}.app for {part}/{tid}")

            if tmd.version == 1 and (c.type & TMD_CONTENT_FLAG_HASHED):
                h3_contents += 1
                h3_p = join(t_dir, f"{c.id:08X}.h3")
                if not exists(h3_p):
                    errors.append(f"Missing .h3 hash table for content {c.id:08X} of {part}/{tid}")
                else:
                    h3_sz = getsize(h3_p)
                    total_encrypted_bytes += h3_sz
                    if h3_sz == 0 or (h3_sz % 20) != 0:
                        errors.append(
                            f"Corrupt .h3 hash table size ({h3_sz} bytes) for content {c.id:08X} of {part}/{tid}"
                        )

    if errors and errors_out is None:
        for err in errors:
            print(f"[AUDIT ERROR] {err}", flush=True)
        raise RuntimeError(
            f"TMD & content integrity audit failed for {reg_upper} ({len(errors)} error(s)):\n"
            + "\n".join(f"  - {e}" for e in errors)
        )

    return {
        "tmd_v1_count": tmd_v1_count,
        "tmd_v0_count": tmd_v0_count,
        "total_contents": total_contents,
        "h3_contents": h3_contents,
        "total_decrypted_bytes": total_decrypted_bytes,
        "total_encrypted_bytes": total_encrypted_bytes,
    }


def find_wiiu_firmware_identity_from_map(
    title_dirs_by_part_tid: Dict[Tuple[str, str], str],
    reg_tag: str,
    common_key: Optional[bytes],
    expected_vdata_ver: Optional[int] = None,
    pre_errors: Optional[List[str]] = None,
) -> dict:
    errors: List[str] = list(pre_errors) if pre_errors else []
    m_reg = re.search(r"\d+\.\d+\.\d+([EUJ])", reg_tag, re.IGNORECASE)
    if m_reg:
        reg_letter = m_reg.group(1).upper()
    else:
        reg_letter = "E"
        for ch in ("E", "U", "J"):
            if ch in reg_tag.upper():
                reg_letter = ch
                break
    reg_upper = SUFFIX_TO_REGION[reg_letter]
    reg_idx = {"JPN": "0", "USA": "1", "EUR": "2"}[reg_upper]
    is_pre = "-pre" in reg_tag.lower() or "pre_" in reg_tag.lower() or "pre0_" in reg_tag.lower()

    if expected_vdata_ver is None:
        for b_fw_str, b_pre_prefix, b_vdata_ver in AUTHENTIC_BUILDS_BY_REGION.get(reg_upper, []):
            cand_r_tag = format_regional_tag(b_fw_str, reg_letter, b_pre_prefix)
            cand_legacy = f"{b_pre_prefix}{b_fw_str}{reg_letter}"
            if reg_tag.lower() in (cand_r_tag.lower(), cand_legacy.lower()):
                expected_vdata_ver = b_vdata_ver
                break

    tmd_audit = audit_wiiu_wave_tmd_integrity(title_dirs_by_part_tid, reg_upper, errors_out=errors)

    def _get_tmd_ver(part: str, tid: str) -> Optional[int]:
        t_dir = title_dirs_by_part_tid.get((part, tid))
        if not t_dir:
            return None
        p = join(t_dir, "title.tmd")
        if not exists(p):
            return None
        try:
            with open(p, "rb") as f:
                return parse_tmd(f.read()).title_version
        except Exception as exc:
            errors.append(f"Failed to read title_version from {part}/{tid}/title.tmd: {exc}")
            return None

    def _read_fst_file(part: str, tid: str, fname: str) -> Optional[bytes]:
        if common_key is None:
            return None
        t_dir = title_dirs_by_part_tid.get((part, tid))
        if not t_dir or not exists(join(t_dir, "title.tmd")):
            return None
        try:
            tmd, tkey, _, _ = read_tmd_and_title_key(t_dir, common_key, tid)

            def _cb(c: Content) -> Optional[bytes]:
                ap = join(t_dir, f"{c.id:08X}.app")
                if not exists(ap):
                    return None
                with open(ap, "rb") as fa:
                    return fa.read()

            return extract_single_file_from_fst_in_ram(tmd, tkey, _cb, fname)
        except Exception as exc:
            errors.append(f"Failed to read '{fname}' from FST of {part}/{tid}: {exc}")
            return None

    vdata_tid = f"0005001010041{reg_idx}00"
    menu_tid = f"0005001010040{reg_idx}00"
    updater_tid = f"0005001010045{reg_idx}00"
    drc_tid = f"0005001010043{reg_idx}00"

    vdata_ver = _get_tmd_ver("MLC", vdata_tid)
    if vdata_ver is None:
        errors.append(f"Missing Version Data title ({vdata_tid}) for {reg_tag}")
    elif expected_vdata_ver is not None and vdata_ver != expected_vdata_ver:
        errors.append(
            f"Version Data TMD mismatch for {reg_tag}: expected v{expected_vdata_ver}, got v{vdata_ver}"
        )

    menu_ver_opt = _get_tmd_ver("MLC", menu_tid)
    if menu_ver_opt is None:
        errors.append(f"Missing Wii U Menu title ({menu_tid}) for {reg_tag}")
    menu_ver = menu_ver_opt or 0

    osv10_ver = _get_tmd_ver("SLC", "000500101000400a")
    osv9_ver = _get_tmd_ver("SLC", "0005001010004009")
    if osv10_ver is None and osv9_ver is None:
        errors.append(f"Missing Cafe OS kernel (neither OSv10 nor OSv9 found in SLC) for {reg_tag}")

    osv255_ver = _get_tmd_ver("SLC", "00050010100040ff")
    boot1_ver = _get_tmd_ver("SLC", "0005001010000100")
    drh_ver = _get_tmd_ver("SLC", "0005001010000200")
    drc_ver = _get_tmd_ver("MLC", drc_tid)
    updater_ver = _get_tmd_ver("MLC", updater_tid)

    clean_reg_tag = re.sub(r"^(PRE0_|PRE_)", "", reg_tag, flags=re.IGNORECASE)
    expected_base_fw = clean_reg_tag.replace("-pre0", "").replace("-pre", "")
    target_vdata_ver = expected_vdata_ver if expected_vdata_ver is not None else vdata_ver
    if is_pre and target_vdata_ver is not None:
        for b_fw_str, _b_pre_prefix, b_vdata_ver in AUTHENTIC_BUILDS_BY_REGION.get(reg_upper, []):
            if b_vdata_ver == target_vdata_ver:
                expected_base_fw = f"{b_fw_str}{reg_letter}"
                break

    vbin_fw_str = expected_base_fw
    vbin_tuple = parse_fw_tuple(vbin_fw_str)
    vbin_raw = _read_fst_file("MLC", vdata_tid, "version.bin")
    if common_key is not None and not vbin_raw:
        errors.append(f"Missing version.bin inside {vdata_tid} FST for {reg_tag}")
    elif vbin_raw:
        dec_vb = decode_version_bin_bytes(vbin_raw)
        if not dec_vb:
            errors.append(f"Corrupt version.bin payload inside {vdata_tid} for {reg_tag}")
        elif dec_vb["fw_str"].upper() != expected_base_fw.upper():
            errors.append(
                f"version.bin mismatch for {reg_tag}: expected {expected_base_fw}, decoded {dec_vb['fw_str']}"
            )
        else:
            vbin_fw_str = dec_vb["fw_str"]
            vbin_tuple = dec_vb["tuple"]

    menu_sdk = 0
    menu_xml = _read_fst_file("MLC", menu_tid, "app.xml")
    if menu_xml:
        m = RE_APP_XML_SDK.search(menu_xml)
        if m:
            menu_sdk = int(m.group(1).decode())
        else:
            errors.append(f"Missing SDK version tag in {menu_tid}/app.xml for {reg_tag}")
    elif common_key is not None:
        errors.append(f"Missing app.xml inside {menu_tid} FST for {reg_tag}")

    os_sdk = menu_sdk
    os_xml = None
    os_label = f"OSv9 v{osv9_ver}" if osv9_ver is not None else "OSv9"
    if osv10_ver is not None:
        os_label = f"OSv10 v{osv10_ver}"
        os_xml = _read_fst_file("SLC", "000500101000400a", "app.xml")
        if os_xml:
            m = RE_APP_XML_SDK.search(os_xml)
            if m:
                os_sdk = int(m.group(1).decode())
            else:
                errors.append(f"Missing SDK version tag in 000500101000400a/app.xml for {reg_tag}")
        elif common_key is not None:
            errors.append(f"Missing app.xml inside 000500101000400a FST for {reg_tag}")
    elif osv9_ver is not None:
        os_xml = _read_fst_file("SLC", "0005001010004009", "app.xml")
        if os_xml:
            m = RE_APP_XML_SDK.search(os_xml)
            if m:
                os_sdk = int(m.group(1).decode())
            else:
                errors.append(f"Missing SDK version tag in 0005001010004009/app.xml for {reg_tag}")
        elif common_key is not None:
            errors.append(f"Missing app.xml inside 0005001010004009 FST for {reg_tag}")

    max_sdk = max(os_sdk, menu_sdk)
    vdata_xml = _read_fst_file("MLC", vdata_tid, "app.xml")
    if vdata_xml:
        m = RE_APP_XML_SDK.search(vdata_xml)
        if m:
            max_sdk = max(max_sdk, int(m.group(1).decode()))
        else:
            errors.append(f"Missing SDK version tag in {vdata_tid}/app.xml for {reg_tag}")
    elif common_key is not None:
        errors.append(f"Missing app.xml inside {vdata_tid} FST for {reg_tag}")

    latest_build_date: Optional[str] = None
    for xml_blob in (menu_xml, vdata_xml, os_xml):
        if not xml_blob:
            continue
        m_bd = re.search(rb"<build_date[^>]*>\s*(\d{4})[-/](\d{2})[-/](\d{2})", xml_blob)
        if m_bd:
            cand = f"{m_bd.group(1).decode()}-{m_bd.group(2).decode()}-{m_bd.group(3).decode()}"
            if latest_build_date is None or cand > latest_build_date:
                latest_build_date = cand

    if latest_build_date is None:
        max_mtime = 0.0
        for t_dir in title_dirs_by_part_tid.values():
            tmd_p = join(t_dir, "title.tmd")
            if exists(tmd_p):
                mt = os.path.getmtime(tmd_p)
                if mt > max_mtime:
                    max_mtime = mt
        if max_mtime > 0:
            latest_build_date = time.strftime("%Y-%m-%d", time.gmtime(max_mtime))

    if errors:
        for err in errors:
            print(f"[ERROR][{reg_tag}] {err}", flush=True)
        raise RuntimeError(
            f"Firmware verification failed for {reg_tag} with {len(errors)} error(s):\n"
            + "\n".join(f"  - {e}" for e in errors)
        )

    suffix = " (Pre-Release)" if is_pre else ""
    raw_ver_quad = f"{vbin_tuple[0]}.{vbin_tuple[1]}.{vbin_tuple[2]}.{vdata_ver:04d}"

    dat_line = (
        f"Firmware {reg_tag} "
        f"(Cafe OS SDK {max_sdk} - Menu SDK {menu_sdk} - {os_label}) "
        f"({raw_ver_quad}){suffix}"
    )

    return {
        "reg": reg_upper,
        "reg_letter": reg_letter,
        "reg_tag": reg_tag,
        "vbin_fw_str": vbin_fw_str,
        "vdata_ver": vdata_ver,
        "menu_ver": menu_ver,
        "menu_sdk": menu_sdk,
        "os_sdk": os_sdk,
        "max_sdk": max_sdk,
        "osv10_ver": osv10_ver,
        "osv9_ver": osv9_ver,
        "osv255_ver": osv255_ver,
        "boot1_ver": boot1_ver,
        "drh_ver": drh_ver,
        "drc_ver": drc_ver,
        "updater_ver": updater_ver,
        "latest_build_date": latest_build_date,
        "tmd_audit": tmd_audit,
        "dat_line": dat_line,
    }


def hash_single_wup_title_cached(
    wup_dir: str, tid: str, ver: int, hash_cache: Dict[Tuple[str, int], List[dict]]
) -> List[dict]:
    key = (tid, ver)
    if key in hash_cache:
        return hash_cache[key]

    items = []
    for fname in sorted(os.listdir(wup_dir)):
        fpath = join(wup_dir, fname)
        if not os.path.isfile(fpath) or fname.endswith(".tmp"):
            continue
        md5_h = hashlib.md5()
        sha1_h = hashlib.sha1()
        crc_val = 0
        sz = getsize(fpath)
        with open(fpath, "rb") as f:
            for chunk in iter(lambda: f.read(1048576), b""):
                md5_h.update(chunk)
                sha1_h.update(chunk)
                crc_val = zlib.crc32(chunk, crc_val)
        items.append({
            "fname": fname,
            "size": str(sz),
            "crc": "%08x" % (crc_val & 0xFFFFFFFF),
            "md5": md5_h.hexdigest(),
            "sha1": sha1_h.hexdigest(),
        })
    if not items:
        raise RuntimeError(f"No files hashed for title {tid} v{ver} in {wup_dir}")
    hash_cache[key] = items
    return items


def _format_title_version_and_status(tid: str, ver: int, prev_versions: Optional[Dict[str, int]]) -> Tuple[str, str]:
    if prev_versions is None:
        return f"`v{ver}`", "-"
    if not prev_versions:
        return f"`v{ver}`", "Initial"
    if tid not in prev_versions:
        return f"`v{ver}`", "New!"
    prev_ver = prev_versions[tid]
    if prev_ver != ver:
        return f"`v{prev_ver} -> v{ver}`", "Updated!"
    return f"`v{ver}`", "Unchanged"


def _format_human_size(num_bytes: int) -> str:
    if num_bytes >= 1024 * 1024 * 1024:
        return f"{num_bytes / (1024 ** 3):.2f} GiB"
    return f"{num_bytes / (1024 ** 2):.2f} MiB"


_RE_REG_TAG = re.compile(r"^(\d+)\.(\d+)\.(\d+)([EUJ])(-pre0?)?$")


def _firmware_provenance_notes(reg_tags: List[str]) -> List[str]:
    verified = False
    unverified_102 = False
    possible = False
    latest_tags: List[str] = []
    ninupdates_tags: List[str] = []
    for reg_tag in reg_tags:
        if reg_tag in ("5.5.5E", "5.5.5J", "5.5.6U"):
            latest_tags.append(reg_tag)
        elif reg_tag == "5.5.5U":
            ninupdates_tags.append(reg_tag)
        m = _RE_REG_TAG.match(reg_tag)
        if not m or int(m.group(1)) != 1:
            continue
        fw = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
        if fw == (1, 0, 2) and m.group(4) == "U":
            verified = True
        elif fw == (1, 0, 2):
            unverified_102 = True
        else:
            possible = True

    notes: List[str] = []
    if verified:
        text = "> **Verified** against an authentic 1.0.2U console dump (DRH and Bluetooth firmware cannot be confirmed)."
        if unverified_102:
            text += " 1.0.2E reuses this list and is not verified."
        notes.append(text)
    elif unverified_102:
        notes.append("> **Not verified:** this build reuses the 1.0.2U title list.")
    if possible:
        notes.append(
            "> **Possible, not confirmed:** this firmware exists, but its titles are only based on "
            "the oldest versions available on the NUS."
        )
    if latest_tags and ninupdates_tags:
        notes.append(
            f"> **Latest versions:** {', '.join(f'`{t}`' for t in latest_tags)} use the latest versions available on the "
            f"Nintendo servers. `{ninupdates_tags[0]}` is based on ninupdates."
        )
    elif latest_tags:
        notes.append("> **Latest versions** available on the Nintendo servers.")
    elif ninupdates_tags:
        notes.append(f"> `{ninupdates_tags[0]}` is based on ninupdates.")
    return notes


def build_wave_release_notes(wave_tag: str, build_results: List[dict]) -> Tuple[str, str]:
    reg_order = {"EUR": 0, "USA": 1, "JPN": 2}
    ordered_results = sorted(build_results, key=lambda b: reg_order.get(b["region"], 9))

    present_regs = {b["region"] for b in ordered_results}
    all_regs = [("EUR", "E"), ("USA", "U"), ("JPN", "J")]
    missing_regs = [(r_name, r_let) for r_name, r_let in all_regs if r_name not in present_regs]

    disp_ver = ordered_results[0]["reg_tag"] if len(ordered_results) == 1 else wave_tag
    release_title = f"Firmware {disp_ver}"

    meta = WAVE_METADATA.get(wave_tag, {})
    official_date = meta.get("date")

    if official_date:
        date_line = f"Official Release Date: {official_date}"
    else:
        comp_dates = [
            b["identity"].get("latest_build_date")
            for b in ordered_results
            if b["identity"].get("latest_build_date")
        ]
        latest_comp = max(comp_dates) if comp_dates else time.strftime("%Y-%m-%d")
        date_line = f"Compilation Date: {latest_comp}"

    lines = [
        date_line,
        "",
    ]

    if missing_regs:
        base_v = wave_tag.replace("-pre0", "").replace("-pre", "")
        pre_suf = "-pre0" if "-pre0" in wave_tag else ("-pre" if "-pre" in wave_tag else "")
        missing_str = ", ".join(f"{r_name} (`{base_v}{r_let}{pre_suf}`)" for r_name, r_let in missing_regs)
        present_str = ", ".join(f"{b['region']} (`{b['reg_tag']}`)" for b in ordered_results)
        lines.append(
            f"> **Note:** Firmware `{wave_tag}` was only released for {present_str}. "
            f"It was never released for {missing_str}."
        )
        lines.append("")

    for prov in _firmware_provenance_notes([b["reg_tag"] for b in ordered_results]):
        lines.append(prov)
        lines.append("")

    lines.append("### Titles")
    lines.append("")

    for b in ordered_results:
        t_map = b.get("titles_by_part", {})
        prev_versions = b.get("prev_versions", {})
        slc_list = t_map.get("SLC", [])
        mlc_list = t_map.get("MLC", [])
        vwii_list = t_map.get("vWii", [])
        total_t = len(slc_list) + len(mlc_list) + len(vwii_list)
        reg_label = b["region"]

        lines.append("<details>")
        lines.append(
            f"<summary>{reg_label} ({b['reg_tag']}) : {total_t} Titles "
            f"({len(slc_list)} SLC | {len(mlc_list)} MLC | {len(vwii_list)} vWii)</summary>"
        )
        lines.append("")
        lines.append("| Partition | Title ID | Title Name | Version | Status |")
        lines.append("| :--- | :--- | :--- | :--- | :--- |")
        for part_name in ("SLC", "MLC", "vWii"):
            for tid, ver, tname in t_map.get(part_name, []):
                ver_cell, status_cell = _format_title_version_and_status(tid, ver, prev_versions)
                lines.append(f"| {part_name} | `{tid}` | {tname} | {ver_cell} | {status_cell} |")
        lines.append("")
        lines.append("</details>")
        lines.append("")

    return release_title, "\n".join(lines)


def extract_wiiu_version_order(game_data: dict):
    name = game_data.get("name", "")
    m = re.search(r"Firmware\s+(\d+)\.(\d+)\.(\d+)([EUJ])?(-pre0|-pre)?", name, re.IGNORECASE)
    if m:
        maj, mino, pat = int(m.group(1)), int(m.group(2)), int(m.group(3))
        reg_ch = (m.group(4) or "E").upper()
        pre_tag = (m.group(5) or "").lower()
    else:
        maj, mino, pat, reg_ch, pre_tag = 0, 0, 0, "E", ""

    pre_rank = -2 if pre_tag == "-pre0" else (-1 if pre_tag == "-pre" else 0)
    reg_rank = {"E": 0, "U": 1, "J": 2}.get(reg_ch, 9)
    return (maj, mino, pat, pre_rank, reg_rank, name)


def validate_dat_rom_entries(game_name: str, roms: List[dict]) -> None:
    if not roms:
        raise ValueError(f"DAT entry '{game_name}' contains zero ROM records")
    seen_names = set()
    errors: List[str] = []
    for rom in roms:
        r_name = rom.get("name", "")
        r_size = rom.get("size", "")
        r_crc = rom.get("crc", "")
        r_md5 = rom.get("md5", "")
        r_sha1 = rom.get("sha1", "")
        if not r_name or r_name in seen_names:
            errors.append(f"Duplicate or empty ROM name '{r_name}' in DAT entry '{game_name}'")
        seen_names.add(r_name)
        if not str(r_size).isdigit() or int(r_size) <= 0:
            errors.append(f"Invalid ROM size '{r_size}' for '{r_name}' in '{game_name}'")
        if not re.match(r"^[0-9a-f]{8}$", r_crc):
            errors.append(f"Invalid CRC32 '{r_crc}' for '{r_name}' in '{game_name}'")
        if not re.match(r"^[0-9a-f]{32}$", r_md5):
            errors.append(f"Invalid MD5 '{r_md5}' for '{r_name}' in '{game_name}'")
        if not re.match(r"^[0-9a-f]{40}$", r_sha1):
            errors.append(f"Invalid SHA1 '{r_sha1}' for '{r_name}' in '{game_name}'")
    if errors:
        for err in errors:
            print(f"[DAT ERROR] {err}", flush=True)
        raise ValueError(
            f"DAT validation failed for '{game_name}' with {len(errors)} error(s):\n"
            + "\n".join(f"  - {e}" for e in errors)
        )


def load_existing_dat_games(base_dir: str) -> Dict[str, dict]:
    existing_games: Dict[str, dict] = {}
    for f in sorted(os.listdir(base_dir)):
        if f.startswith("Nintendo") and "Wii U Firmware" in f and f.endswith(".dat"):
            fpath = join(base_dir, f)
            tree = ET.parse(fpath)
            for g in tree.getroot().findall("game"):
                gname = g.get("name")
                if not gname:
                    raise ValueError(f"DAT file '{f}' contains a <game> element without a name attribute")
                roms = []
                for r in g.findall("rom"):
                    roms.append({
                        "name": r.get("name"),
                        "size": r.get("size"),
                        "crc": r.get("crc"),
                        "md5": r.get("md5"),
                        "sha1": r.get("sha1"),
                    })
                validate_dat_rom_entries(gname, roms)
                existing_games[gname] = {"name": gname, "roms": roms}
    return existing_games


def write_logiqx_dat(games_dict: Dict[str, dict], base_dir: str) -> str:
    if not games_dict:
        raise RuntimeError("Refusing to write an empty Logiqx DAT file")

    sorted_games = sorted(games_dict.values(), key=extract_wiiu_version_order)

    def escape_xml(s: str) -> str:
        amp = chr(38)
        return (
            s.replace(amp, f"{amp}amp;")
            .replace("<", f"{amp}lt;")
            .replace(">", f"{amp}gt;")
            .replace('"', f"{amp}quot;")
            .replace("'", f"{amp}apos;")
        )

    timestamp_disp = time.strftime("%Y%m%d%H%M%S")
    xml_lines = [
        '<?xml version="1.0"?>',
        '<!DOCTYPE datafile PUBLIC "-//Logiqx//DTD ROM Management Datafile//EN" "http://www.logiqx.com/Dats/datafile.dtd">',
        '<datafile>',
        '    <header>',
        '        <name>Nintendo - Nintendo Wii U Firmware</name>',
        '        <description>Nintendo - Nintendo Wii U Firmware</description>',
        f'        <version>{timestamp_disp}</version>',
        '        <author>Twitter: @JeremKOYTB</author>',
        '        <comment>DAT generated by firmware_downloader.py for Cafe_Firmware preservation.</comment>',
        '        <homepage>github.com/JeremKOYTB/Cafe_Firmware</homepage>',
        '        <url>https://github.com/JeremKOYTB/Cafe_Firmware</url>',
        '    </header>',
    ]

    for game in sorted_games:
        validate_dat_rom_entries(game["name"], game["roms"])
        game_name = escape_xml(game["name"])
        xml_lines.append(f'    <game name="{game_name}">')
        xml_lines.append('        <category>Games</category>')
        xml_lines.append(f'        <description>{game_name}</description>')
        for rom in game["roms"]:
            r_name = escape_xml(rom["name"])
            xml_lines.append(
                f'        <rom name="{r_name}" size="{rom["size"]}" crc="{rom["crc"]}" md5="{rom["md5"]}" sha1="{rom["sha1"]}"/>'
            )
        xml_lines.append('    </game>')

    xml_lines.append('</datafile>')

    new_dat_name = f"Nintendo - Nintendo Wii U Firmware ({len(sorted_games)}) ({timestamp_disp}).dat"
    out_path = join(base_dir, new_dat_name)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(xml_lines) + "\n")

    parsed_tree = ET.parse(out_path)
    parsed_games = parsed_tree.getroot().findall("game")
    if len(parsed_games) != len(sorted_games):
        raise RuntimeError(
            f"Written DAT XML verification failed: expected {len(sorted_games)} games, parsed {len(parsed_games)}"
        )

    for fname in os.listdir(base_dir):
        if fname.startswith("Nintendo") and "Wii U Firmware" in fname and fname.endswith(".dat") and fname != new_dat_name:
            try:
                remove(join(base_dir, fname))
            except Exception:
                pass

    print(f"\n[+] DATfile successfully generated and verified: {new_dat_name} ({len(sorted_games)} registered regional firmwares).", flush=True)
    return new_dat_name


def consolidate_dat_from_cache(base_dir: str):
    existing_games = load_existing_dat_games(base_dir)
    cache_dir = join(base_dir, ".dat_cache")
    if exists(cache_dir):
        for jf in sorted(os.listdir(cache_dir)):
            if not jf.endswith(".json"):
                continue
            with open(join(cache_dir, jf), "r", encoding="utf-8") as f:
                payload = json.load(f)
            entries = payload.get("entries", [payload] if "name" in payload else [])
            for item in entries:
                name = item["name"]
                reg_tag = item.get("reg_tag", "")
                validate_dat_rom_entries(name, item["roms"])
                for k in list(existing_games.keys()):
                    if reg_tag and k.startswith(f"Firmware {reg_tag} "):
                        del existing_games[k]
                existing_games[name] = {"name": name, "roms": item["roms"]}
    write_logiqx_dat(existing_games, base_dir)


def _inspect_local_extracted_wup_tree(root_dir: str, reg_tag: str, common_key: Optional[bytes], hash_cache: dict):
    effective_key = common_key if common_key is not None else get_common_key()
    title_dirs_map: Dict[Tuple[str, str], str] = {}
    roms = []
    errors: List[str] = []
    for part_name in ("SLC", "MLC", "vWii"):
        p_dir = join(root_dir, part_name)
        if not exists(p_dir):
            continue
        for tid in sorted(os.listdir(p_dir)):
            t_dir = join(p_dir, tid)
            if not os.path.isdir(t_dir):
                continue
            clean_tid = tid.lower()
            if not is_valid_tid(clean_tid):
                errors.append(f"Invalid Title ID directory '{tid}' in {p_dir}")
                continue
            title_dirs_map[(part_name, clean_tid)] = t_dir
            try:
                verified_tmd, _ = verify_wup_title_cryptography(t_dir, effective_key, clean_tid)
                t_ver = verified_tmd.title_version
                for item in hash_single_wup_title_cached(t_dir, clean_tid, t_ver, hash_cache):
                    roms.append({
                        "name": f"{part_name}/{clean_tid}/{item['fname']}",
                        "size": item["size"],
                        "crc": item["crc"],
                        "md5": item["md5"],
                        "sha1": item["sha1"],
                    })
            except Exception as exc:
                errors.append(f"{part_name}/{clean_tid}: {exc}")

    ident = find_wiiu_firmware_identity_from_map(
        title_dirs_map, reg_tag, effective_key, pre_errors=errors
    )
    validate_dat_rom_entries(ident["dat_line"], roms)
    return ident, roms


def generate_dat_from_local_zips(common_key: Optional[bytes]):
    existing_games = load_existing_dat_games(BASE_DIR)
    hash_cache: Dict[Tuple[str, int], List[dict]] = {}
    zip_candidates = [
        f for f in sorted(os.listdir(BASE_DIR))
        if f.lower().endswith(".zip")
        and f.lower().startswith("firmware.")
        and not f.lower().startswith("extracted.")
    ]
    if not zip_candidates:
        print("INFO: No 'Firmware.*.zip' archives found in the directory.", flush=True)
        return

    for zname in zip_candidates:
        zpath = join(BASE_DIR, zname)
        verify_zip_archive_integrity(zpath, required_prefixes=["SLC/", "MLC/"])
        m = re.match(r"^Firmware\.(.+)\.zip$", zname, re.IGNORECASE)
        reg_tag = m.group(1) if m else zname.replace(".zip", "")
        tmp_dir = join(BASE_DIR, f"tmp_zip_dat_{uuid.uuid4().hex[:8]}")
        makedirs(tmp_dir, exist_ok=True)
        try:
            with ZipFile(zpath, "r") as zf:
                zf.extractall(tmp_dir)
            ident, roms = _inspect_local_extracted_wup_tree(tmp_dir, reg_tag, common_key, hash_cache)
            for k in list(existing_games.keys()):
                if k.startswith(f"Firmware {reg_tag} "):
                    del existing_games[k]
            existing_games[ident["dat_line"]] = {"name": ident["dat_line"], "roms": roms}
            print(f"[DAT] Registered '{ident['dat_line']}' ({len(roms)} files)", flush=True)
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    write_logiqx_dat(existing_games, BASE_DIR)


def sync_datfile_from_releases(common_key: Optional[bytes], latest_only: bool = False):
    existing_games = load_existing_dat_games(BASE_DIR)
    hash_cache: Dict[Tuple[str, int], List[dict]] = {}
    limit = "1" if latest_only else "1000"
    res = run(["gh", "release", "list", "-L", limit, "--json", "tagName", "--jq", ".[].tagName"], stdout=PIPE, stderr=PIPE, text=True)
    if res.returncode != 0:
        print(f"ERROR: Failed to list releases via gh CLI: {res.stderr.strip()}", flush=True)
        sys.exit(1)

    release_tags = [t.strip() for t in res.stdout.splitlines() if t.strip()]
    for tag in release_tags:
        tmp_dl = join(BASE_DIR, f"tmp_gh_dat_{uuid.uuid4().hex[:8]}")
        makedirs(tmp_dl, exist_ok=True)
        try:
            dl_res = run(["gh", "release", "download", tag, "-p", "Firmware.*.zip", "--dir", tmp_dl, "--clobber"], stdout=PIPE, stderr=PIPE, text=True)
            if dl_res.returncode != 0:
                raise RuntimeError(f"Failed to download archives for release {tag}: {dl_res.stderr.strip()}")
            zips = [f for f in sorted(os.listdir(tmp_dl)) if f.startswith("Firmware.") and f.endswith(".zip")]
            if not zips:
                raise RuntimeError(f"Release {tag} has no Firmware.*.zip assets attached")
            for zname in zips:
                zpath = join(tmp_dl, zname)
                verify_zip_archive_integrity(zpath, required_prefixes=["SLC/", "MLC/"])
                m = re.match(r"^Firmware\.(.+)\.zip$", zname, re.IGNORECASE)
                reg_tag = m.group(1) if m else zname.replace(".zip", "")
                if any(k.startswith(f"Firmware {reg_tag} ") for k in existing_games):
                    log_print(f"{reg_tag} already present in DAT. Skipping.")
                    continue
                ext_dir = join(tmp_dl, reg_tag)
                makedirs(ext_dir, exist_ok=True)
                with ZipFile(zpath, "r") as zf:
                    zf.extractall(ext_dir)
                ident, roms = _inspect_local_extracted_wup_tree(ext_dir, reg_tag, common_key, hash_cache)
                existing_games[ident["dat_line"]] = {"name": ident["dat_line"], "roms": roms}
                print(f"[DAT] Synced '{ident['dat_line']}' ({len(roms)} files)", flush=True)
        finally:
            shutil.rmtree(tmp_dl, ignore_errors=True)

    write_logiqx_dat(existing_games, BASE_DIR)
