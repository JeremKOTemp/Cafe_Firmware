import os
import sys
import json
import time
import shutil
import warnings
import argparse
import subprocess
from os import makedirs, remove
from os.path import exists, join
from zipfile import ZipFile
from typing import Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from tqdm import tqdm
except ImportError:
    print("Module(s) missing. Install with: pip install cryptography requests tqdm")
    sys.exit(1)

warnings.filterwarnings("ignore")

from wiiu_constants import (
    BASE_DIR,
    CEMU_PARTITION_FOLDERS,
    get_friendly_title_name,
    is_valid_tid,
    load_title_names_map,
    log_print,
    set_verbose,
)
from wiiu_crypto_nus import (
    VWIISlccmptBuilder,
    create_optimized_session,
    download_title_wup,
    extract_title_from_wup,
    fetch_yls8_csv_online,
    get_common_key,
    get_default_cert,
    is_vwii_wup_title,
    parse_tmd,
    verify_wup_title_cryptography,
)
from wiiu_manifests import finalize_wave_notes, write_build_manifest
from wiiu_verify_extract import verify_extracted_archive
from wiiu_latest import (
    build_nus_direct_waves,
    latest_wave_tags,
    nus_direct_request,
    verify_latest_builds,
    warn_ninupdates_differences,
)
from wiiu_packager_dat import (
    build_all_waves_plan,
    build_wave_release_notes,
    consolidate_dat_from_cache,
    find_wiiu_firmware_identity_from_map,
    generate_dat_from_local_zips,
    hash_single_wup_title_cached,
    load_existing_dat_games,
    sync_datfile_from_releases,
    verify_zip_archive_integrity,
    write_logiqx_dat,
    zip_virtual_tree_single_pass,
)


def main():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        description="firmware_downloader.py: Nintendo Wii U (Cafe OS) firmware downloader, verifier, extractor & Logiqx DAT manager.",
    )
    parser.add_argument("version", nargs="*", default=[], help="One or more firmware waves or regional versions processed in order (e.g. 5.5.5 5.5.6 5.0.0-pre 5.5.5E). Empty = 5.5.6.")
    parser.add_argument("--after-wave-command", default="", help="Shell command run after each wave is built and verified (WAVE_TAG is set); it can publish and delete that wave's archives to bound disk usage.")
    parser.add_argument("--region", nargs="+", default=["EUR", "USA", "JPN"], choices=["EUR", "USA", "JPN"], help="Regions to process (default: EUR USA JPN).")
    parser.add_argument("--allversion", action="store_true", help="Process all 51 firmware waves (145 regional builds).")
    parser.add_argument("--latest", action="store_true", help="Download the latest firmware of every region without naming a version (5.5.5 first, then 5.5.6 last), verified against the NUS latest TMDs and the yls8 list.")
    parser.add_argument("--verify-latest", action="store_true", help="Before downloading, verify that each region's final build matches the NUS latest TMDs and the yls8 list.")
    parser.add_argument("--local", action="store_true", help="Process existing local 'Firmware <REG_TAG>' folders or 'Firmware.<REG_TAG>.zip' without downloading from NUS.")
    parser.add_argument("--extract-data", action="store_true", help="Extract decrypted system files (slc01, mlc01, slccmpt01) into Extracted.Firmware.<REG_TAG>.zip.")
    parser.add_argument("--extract-zip", action="store_true", help="Alias for --extract-data.")
    parser.add_argument("--datfile", action="store_true", help="Generate or update the Logiqx XML DAT file.")
    parser.add_argument("--dat-from-zips", action="store_true", help="Scan local 'Firmware.*.zip' archives to build the Logiqx XML DAT file.")
    parser.add_argument("--sync-releases", action="store_true", help="Sync all GitHub releases into the Logiqx XML DAT file.")
    parser.add_argument("--sync-latest", action="store_true", help="Sync the latest GitHub release into the Logiqx XML DAT file.")
    parser.add_argument("--export-dat-cache", action="store_true", help="Export .dat_cache/<WAVE_TAG>.json for parallel CI matrix consolidation.")
    parser.add_argument("--consolidate-dat-cache", action="store_true", help="Consolidate .dat_cache/*.json into a single clean Logiqx XML DAT file.")
    parser.add_argument("--print-release-notes", default="release_notes.md", help="Output path for generated GitHub release notes Markdown.")
    parser.add_argument("--manifests-dir", default="build_manifests", help="Directory holding one JSON manifest per regional build (real TMD versions of every title).")
    parser.add_argument("--finalize-notes", action="store_true", help="Regenerate the release notes of a wave from the build manifests, computing every title status by comparing each build with the previous one.")
    parser.add_argument("--otp", default="otp.bin", help="Path to otp.bin or 32-char hex Wii U Common Key.")
    parser.add_argument("--workers", type=int, default=24, help="Concurrent title download & decryption workers (default: 24).")
    parser.add_argument("--logs", action="store_true", help="Enable verbose logging.")
    args, _ = parser.parse_known_args()

    set_verbose(args.logs)

    manifests_dir = args.manifests_dir if os.path.isabs(args.manifests_dir) else join(BASE_DIR, args.manifests_dir)

    if args.consolidate_dat_cache:
        consolidate_dat_from_cache(BASE_DIR)
        sys.exit(0)

    if args.finalize_notes:
        final_tag = args.version[0].strip() if args.version else ""
        final_title, final_notes = finalize_wave_notes(manifests_dir, final_tag)
        with open(join(BASE_DIR, args.print_release_notes), "w", encoding="utf-8") as f:
            f.write(final_notes)
        with open(join(BASE_DIR, "release_title.txt"), "w", encoding="utf-8") as f:
            f.write(final_title + "\n")
        print(f"Release notes of {final_tag} regenerated from the build manifests.", flush=True)
        sys.exit(0)

    common_key = get_common_key(args.otp)
    log_print("Wii U Common Key loaded and verified (SHA-1 match).")

    title_names_map = load_title_names_map(BASE_DIR)

    if args.dat_from_zips:
        generate_dat_from_local_zips(common_key)
        sys.exit(0)

    if args.sync_releases:
        sync_datfile_from_releases(common_key, latest_only=False)
        sys.exit(0)

    if args.sync_latest:
        sync_datfile_from_releases(common_key, latest_only=True)
        sys.exit(0)

    local_only = (os.environ.get("LOCAL_ONLY") == "true") or bool(args.local)
    do_extract = (
        (os.environ.get("EXTRACT_DATA") == "true")
        or (os.environ.get("EXTRACT_ZIP") == "true")
        or bool(args.extract_data)
        or bool(args.extract_zip)
    )

    session = create_optimized_session()

    versions = [v.strip() for v in args.version if v.strip()]
    wants_latest = bool(args.latest) or any(v.upper() == "LATEST" for v in versions)
    verify_latest = bool(args.verify_latest)
    yls8_state: Dict[str, Optional[str]] = {"text": None, "loaded": False}

    def ninupdates_csv(required: bool) -> Optional[str]:
        if not yls8_state["loaded"]:
            try:
                yls8_state["text"] = fetch_yls8_csv_online(session)
                yls8_state["loaded"] = True
            except Exception as exc:
                if required:
                    raise
                yls8_state["loaded"] = True
                print(f"[warning] ninupdates is unavailable ({exc}); continuing with the Nintendo servers only.", flush=True)
        return yls8_state["text"]

    waves: List[dict] = []
    direct_waves: List[dict] = []
    if wants_latest:
        target_ver = "LATEST"
        latest_tags = latest_wave_tags(args.region)
        if local_only:
            waves = [
                w for w in build_all_waves_plan(ninupdates_csv(True), target_filter="ALL", regions_filter=args.region)
                if w["wave_tag"] in set(latest_tags)
            ]
        else:
            direct_waves = build_nus_direct_waves(session, args.region, latest_tags, None)
            waves = list(direct_waves)
    elif args.allversion:
        target_ver = "ALL"
        waves = build_all_waves_plan(ninupdates_csv(True), target_filter="ALL", regions_filter=args.region)
    else:
        targets = versions or ["5.5.6"]
        target_ver = " ".join(targets)
        for tag in targets:
            single = None if local_only else nus_direct_request(tag)
            if single:
                found = build_nus_direct_waves(session, args.region, [single[0]], single[1])
                direct_waves.extend(found)
                waves.extend(found)
            else:
                waves.extend(build_all_waves_plan(ninupdates_csv(True), target_filter=tag, regions_filter=args.region))
    if direct_waves:
        verify_latest = True
        csv_text = ninupdates_csv(False)
        if csv_text:
            warn_ninupdates_differences(direct_waves, csv_text, args.region)
    yls8_csv_text = yls8_state["text"]
    if not waves:
        print(f"[!] No matching Wii U firmware wave found for '{target_ver}'.", flush=True)
        sys.exit(1)

    if verify_latest and not local_only:
        verify_latest_builds(session, waves, yls8_csv_text, args.region)

    if not local_only:
        wave_sys_tids = [
            tid
            for w in waves
            for e in w["entries"]
            for plist in e["partitions"].values()
            for tid, _ in plist
            if tid.lower().startswith("00050010")
        ][:6]
        get_default_cert(session, candidate_tids=wave_sys_tids)

    cache_root = join(BASE_DIR, ".wup_cache")
    makedirs(cache_root, exist_ok=True)
    cached_tid_vers: Dict[Tuple[str, int], Tuple[str, Optional[str]]] = {}
    cached_dat_hashes: Dict[Tuple[str, int], List[dict]] = {}
    existing_dat_games = load_existing_dat_games(BASE_DIR) if args.datfile else {}

    last_needed: Dict[Tuple[str, int], int] = {}
    for wave_index, planned_wave in enumerate(waves):
        for planned_entry in planned_wave["entries"]:
            for planned_list in planned_entry["partitions"].values():
                for planned_tid, planned_ver in planned_list:
                    last_needed[(planned_tid, planned_ver)] = wave_index

    try:
        for wave_index, wave in enumerate(waves):
            w_tag = wave["wave_tag"]
            w_entries = wave["entries"]
            print(f"Processing {w_tag} ({', '.join(e['reg_tag'] for e in w_entries)})", flush=True)

            if not local_only:
                unique_needed: Dict[Tuple[str, int], str] = {}
                for e in w_entries:
                    for part_name, plist in e["partitions"].items():
                        for tid, ver in plist:
                            if (tid, ver) not in cached_tid_vers:
                                unique_needed[(tid, ver)] = part_name

                if unique_needed:
                    def _dl_and_ext_item(item):
                        (tid, ver), _ = item
                        c_wup = join(cache_root, "WUP", f"{tid}_v{ver}")
                        c_ext = join(cache_root, "EXT", f"{tid}_v{ver}") if do_extract else None
                        downloaded = False
                        for download_attempt in range(3):
                            try:
                                downloaded = download_title_wup(session, tid, ver, c_wup, common_key=common_key)
                                break
                            except RuntimeError as exc:
                                if download_attempt == 2 or "404" in str(exc) or "STOPPED" in str(exc):
                                    raise
                                time.sleep(2 * (download_attempt + 1))
                        if not downloaded:
                            raise RuntimeError(f"Failed to download and verify {tid} v{ver}")
                        if c_ext is not None:
                            if not extract_title_from_wup(tid, c_wup, c_ext, common_key):
                                raise RuntimeError(f"Failed to extract {tid} v{ver}")
                        if args.datfile or args.export_dat_cache:
                            hash_single_wup_title_cached(c_wup, tid, ver, cached_dat_hashes)
                        return (tid, ver, c_wup, c_ext)

                    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
                        futs = [pool.submit(_dl_and_ext_item, it) for it in unique_needed.items()]
                        with tqdm(total=len(futs), unit="title", desc=f"Downloading Wave {w_tag}") as pbar:
                            for fut in as_completed(futs):
                                tid, ver, cw, ce = fut.result()
                                cached_tid_vers[(tid, ver)] = (cw, ce)
                                pbar.update(1)

            wave_build_results = []
            dat_cache_entries = []

            for e in w_entries:
                r_tag = e["reg_tag"]
                zip_name = f"Firmware.{r_tag}.zip"
                zip_path = join(BASE_DIR, zip_name)
                ext_zip_name = f"Extracted.Firmware.{r_tag}.zip"
                ext_zip_path = join(BASE_DIR, ext_zip_name)
                temp_local_unpack = None
                temp_slccmpt_dir = None

                try:
                    title_dirs_map: Dict[Tuple[str, str], str] = {}
                    titles_by_part: Dict[str, List[Tuple[str, int, str]]] = {"SLC": [], "MLC": [], "vWii": []}
                    wup_zip_mappings: List[Tuple[str, str]] = []
                    ext_zip_mappings: List[Tuple[str, str]] = []
                    vwii_builder = VWIISlccmptBuilder()
                    has_vwii_titles = False
                    roms: List[dict] = []
                    expected_tids_by_part = {
                        p_name: {tid: ver for tid, ver in plist}
                        for p_name, plist in e["partitions"].items()
                    }

                    if local_only:
                        wup_build_dir = join(BASE_DIR, f"Firmware {r_tag}")
                        if not exists(wup_build_dir):
                            if not exists(zip_path):
                                raise FileNotFoundError(f"Neither folder 'Firmware {r_tag}' nor archive '{zip_name}' found in local mode")
                            verify_zip_archive_integrity(zip_path, required_prefixes=["SLC/", "MLC/"])
                            temp_local_unpack = join(cache_root, f"local_{r_tag}")
                            makedirs(temp_local_unpack, exist_ok=True)
                            with ZipFile(zip_path, "r") as zf:
                                zf.extractall(temp_local_unpack)
                            wup_build_dir = temp_local_unpack
                            local_zip_checked = True
                        else:
                            local_zip_checked = False

                        if exists(zip_path) and not local_zip_checked:
                            verify_zip_archive_integrity(zip_path, required_prefixes=["SLC/", "MLC/"])
                        zip_sha256 = ""

                        for part_name in ("SLC", "MLC", "vWii"):
                            p_dir = join(wup_build_dir, part_name)
                            if not exists(p_dir):
                                continue
                            for tid in sorted(os.listdir(p_dir)):
                                t_wup = join(p_dir, tid)
                                if not os.path.isdir(t_wup):
                                    continue
                                clean_t = tid.lower()
                                if not is_valid_tid(clean_t):
                                    raise ValueError(f"Invalid Title ID folder '{tid}' in {p_dir}")
                                exp_ver = expected_tids_by_part.get(part_name, {}).get(clean_t)
                                verify_wup_title_cryptography(t_wup, common_key, clean_t, expected_version=exp_ver)

                                title_dirs_map[(part_name, clean_t)] = t_wup
                                with open(join(t_wup, "title.tmd"), "rb") as f_tmd:
                                    t_ver = parse_tmd(f_tmd.read()).title_version
                                t_friendly = get_friendly_title_name(clean_t, title_names_map)
                                titles_by_part[part_name].append((clean_t, t_ver, t_friendly))

                                if do_extract:
                                    c_ext = join(cache_root, "EXT", f"{clean_t}_v{t_ver}")
                                    extract_title_from_wup(clean_t, t_wup, c_ext, common_key)
                                    if part_name == "vWii" or is_vwii_wup_title(clean_t):
                                        vwii_builder.add_staged_title(clean_t, c_ext)
                                        has_vwii_titles = True
                                    else:
                                        cemu_folder = CEMU_PARTITION_FOLDERS[part_name]
                                        ext_zip_mappings.append((c_ext, f"{cemu_folder}/sys/title/{clean_t[:8]}/{clean_t[8:]}"))
                                if args.datfile or args.export_dat_cache:
                                    for item in hash_single_wup_title_cached(t_wup, clean_t, t_ver, cached_dat_hashes):
                                        roms.append({
                                            "name": f"{part_name}/{clean_t}/{item['fname']}",
                                            "size": item["size"],
                                            "crc": item["crc"],
                                            "md5": item["md5"],
                                            "sha1": item["sha1"],
                                        })

                        for part_name, exp_map in expected_tids_by_part.items():
                            found_tids = {t for t, _, _ in titles_by_part[part_name]}
                            missing_tids = set(exp_map.keys()) - found_tids
                            if missing_tids:
                                raise RuntimeError(
                                    f"Local build {r_tag} is missing {len(missing_tids)} expected {part_name} title(s): {sorted(missing_tids)[:5]}"
                                )
                    else:
                        for part_name in ("SLC", "MLC", "vWii"):
                            cemu_folder = CEMU_PARTITION_FOLDERS[part_name]
                            for tid, ver in sorted(e["partitions"][part_name]):
                                src_wup, src_ext = cached_tid_vers[(tid, ver)]
                                title_dirs_map[(part_name, tid)] = src_wup
                                t_friendly = get_friendly_title_name(tid, title_names_map)
                                titles_by_part[part_name].append((tid, ver, t_friendly))

                                wup_zip_mappings.append((src_wup, f"{part_name}/{tid}"))
                                if do_extract and src_ext:
                                    if part_name == "vWii" or is_vwii_wup_title(tid):
                                        vwii_builder.add_staged_title(tid, src_ext)
                                        has_vwii_titles = True
                                    else:
                                        ext_zip_mappings.append((src_ext, f"{cemu_folder}/sys/title/{tid[:8]}/{tid[8:]}"))
                                if args.datfile or args.export_dat_cache:
                                    for item in hash_single_wup_title_cached(src_wup, tid, ver, cached_dat_hashes):
                                        roms.append({
                                            "name": f"{part_name}/{tid}/{item['fname']}",
                                            "size": item["size"],
                                            "crc": item["crc"],
                                            "md5": item["md5"],
                                            "sha1": item["sha1"],
                                        })

                        if exists(zip_path):
                            remove(zip_path)
                        zip_virtual_tree_single_pass(wup_zip_mappings, zip_path)
                        zip_sha256 = ""
                        required_wup_prefixes = [f"{p}/" for p in ("SLC", "MLC", "vWii") if e["partitions"][p]]
                        verify_zip_archive_integrity(zip_path, required_prefixes=required_wup_prefixes, check_crc=False)

                    if do_extract and has_vwii_titles:
                        temp_slccmpt_dir = join(cache_root, f"slccmpt_{r_tag}")
                        if exists(temp_slccmpt_dir):
                            shutil.rmtree(temp_slccmpt_dir, ignore_errors=True)
                        vwii_builder.build_tree(temp_slccmpt_dir)
                        ext_zip_mappings.append((temp_slccmpt_dir, CEMU_PARTITION_FOLDERS["vWii"]))

                    ext_zip_built = False
                    if do_extract and ext_zip_mappings:
                        if exists(ext_zip_path):
                            remove(ext_zip_path)
                        zip_virtual_tree_single_pass(ext_zip_mappings, ext_zip_path, include_empty_dirs=True)
                        ext_zip_built = True
                        required_ext_prefixes = ["slc01/sys/title/", "mlc01/sys/title/"]
                        if has_vwii_titles:
                            required_ext_prefixes.extend(["slccmpt01/sys/uid.sys", "slccmpt01/shared1/content.map"])
                        verify_zip_archive_integrity(ext_zip_path, required_prefixes=required_ext_prefixes, check_crc=False)
                        verify_extracted_archive(ext_zip_path, titles_by_part, check_crc=False)

                    ident = find_wiiu_firmware_identity_from_map(
                        title_dirs_map,
                        r_tag,
                        common_key,
                        expected_vdata_ver=e["expected_vdata_ver"],
                    )

                    write_build_manifest(manifests_dir, e, titles_by_part, ident.get("latest_build_date"))

                    if args.datfile and roms:
                        existing_dat_games[ident["dat_line"]] = {"name": ident["dat_line"], "roms": roms}
                    if args.export_dat_cache and roms:
                        dat_cache_entries.append({
                            "reg_tag": r_tag,
                            "name": ident["dat_line"],
                            "roms": roms,
                        })

                    wave_build_results.append({
                        "region": e["region"],
                        "reg_tag": r_tag,
                        "zip_name": zip_name,
                        "zip_sha256": zip_sha256,
                        "ext_zip_name": ext_zip_name if ext_zip_built else "",
                        "ext_zip_sha256": "",
                        "identity": ident,
                        "titles_by_part": titles_by_part,
                        "prev_versions": e.get("prev_versions", {}),
                    })
                finally:
                    if temp_local_unpack and exists(temp_local_unpack):
                        shutil.rmtree(temp_local_unpack, ignore_errors=True)
                    if temp_slccmpt_dir and exists(temp_slccmpt_dir):
                        shutil.rmtree(temp_slccmpt_dir, ignore_errors=True)

            if args.export_dat_cache and dat_cache_entries:
                makedirs(join(BASE_DIR, ".dat_cache"), exist_ok=True)
                cache_file = join(BASE_DIR, ".dat_cache", f"{w_tag}.json")
                with open(cache_file, "w", encoding="utf-8") as f:
                    json.dump({"wave_tag": w_tag, "entries": dat_cache_entries}, f)

            rel_title, rel_notes = build_wave_release_notes(w_tag, wave_build_results)
            if args.print_release_notes:
                with open(join(BASE_DIR, args.print_release_notes), "w", encoding="utf-8") as f:
                    f.write(rel_notes)
                with open(join(BASE_DIR, "release_title.txt"), "w", encoding="utf-8") as f:
                    f.write(rel_title + "\n")

            print("\nDOWNLOAD COMPLETE!\n", flush=True)
            print(f"Release Title: {rel_title}\n", flush=True)
            print(rel_notes, flush=True)

            if args.after_wave_command:
                subprocess.run(
                    args.after_wave_command,
                    shell=True,
                    check=True,
                    cwd=BASE_DIR,
                    env=dict(os.environ, WAVE_TAG=w_tag),
                )

            if not local_only:
                for cache_key in [k for k in cached_tid_vers if last_needed.get(k, -1) <= wave_index]:
                    for cached_dir in cached_tid_vers.pop(cache_key):
                        if cached_dir and exists(cached_dir):
                            shutil.rmtree(cached_dir, ignore_errors=True)

        if args.datfile and existing_dat_games:
            write_logiqx_dat(existing_dat_games, BASE_DIR)

    finally:
        session.close()
        shutil.rmtree(cache_root, ignore_errors=True)


if __name__ == "__main__":
    main()
