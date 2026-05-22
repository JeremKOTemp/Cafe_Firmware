from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Set, Tuple

import requests

from wiiu_constants import (
    AUTHENTIC_BUILDS_BY_REGION,
    CDN_HOSTS,
    CDN_PATH,
    DEFAULT_TITLES_DB,
    REGION_SUFFIX,
    VERSION_DATA_TIDS,
    format_regional_tag,
    format_wave_tag,
    normalize_tid,
    parse_fw_tuple,
)
from wiiu_crypto_nus import parse_tmd

VWII_SYSTEM_MENU_TID = "0000000700000002"
REGION_MENU_REMAINDER = {"JPN": 0, "USA": 1, "EUR": 2}
MENU_VERSION_MODULUS = 32

NUS_DIRECT_WAVES = ("5.5.5", "5.5.6")
UPDATED_BY_NEXT_WAVE = {
    ("5.5.5", "USA"): ("0005001010040100", "0005001010041100", "0005001010049100"),
}
PRE_ORDER = {"PRE0_": 0, "PRE_": 1, "": 2}


def _fetch(session: requests.Session, path: str) -> bytes:
    last_err = "no CDN host answered"
    for host in CDN_HOSTS:
        try:
            r = session.get(f"http://{host}{CDN_PATH}/{path}", timeout=30)
        except requests.RequestException as exc:
            last_err = f"{host}: {exc}"
            continue
        if r.status_code == 200:
            return r.content
        if r.status_code == 404:
            raise RuntimeError(f"NUS has no {path} (HTTP 404)")
        last_err = f"{host}: HTTP {r.status_code}"
    raise RuntimeError(f"NUS request failed for {path} ({last_err})")


def fetch_latest_version(session: requests.Session, tid: str) -> int:
    return parse_tmd(_fetch(session, f"{normalize_tid(tid)}/tmd")).title_version


def region_system_menu_version(session: requests.Session, region: str, nus_latest: int) -> int:
    wanted = REGION_MENU_REMAINDER[region]
    version = nus_latest - ((nus_latest - wanted) % MENU_VERSION_MODULUS)
    _fetch(session, f"{VWII_SYSTEM_MENU_TID}/tmd.{version}")
    return version


def discover_latest_versions(session: requests.Session, region: str, tids: List[str]) -> Dict[str, int]:
    def one(tid: str) -> Tuple[str, int]:
        latest = fetch_latest_version(session, tid)
        if tid == VWII_SYSTEM_MENU_TID:
            latest = region_system_menu_version(session, region, latest)
        return tid, latest

    with ThreadPoolExecutor(max_workers=16) as pool:
        return dict(pool.map(one, tids))


def previous_existing_version(session: requests.Session, tid: str, below: int) -> int:
    def exists(version: int) -> bool:
        try:
            _fetch(session, f"{tid}/tmd.{version}")
            return True
        except RuntimeError:
            return False

    candidates = list(range(below - 1, -1, -1))
    with ThreadPoolExecutor(max_workers=16) as pool:
        for version, found in zip(candidates, pool.map(exists, candidates)):
            if found:
                return version
    raise RuntimeError(f"No version of {tid} older than v{below} exists on the NUS")


def region_database_tids(region: str) -> Set[str]:
    tids: Set[str] = set()
    for partition in DEFAULT_TITLES_DB.values():
        tids.update(normalize_tid(t) for t in partition.get(region, []))
        tids.update(normalize_tid(t) for t in partition.get("All", []))
    return tids


def region_tids_in_yls8(yls8_csv_text: str, region: str) -> Set[str]:
    found: Set[str] = set()
    for line in yls8_csv_text.strip().replace("\r", "").split("\n")[1:]:
        parts = line.split(",")
        if len(parts) >= 2 and parts[1].strip().upper() in (region, "ALL", ""):
            found.add(parts[0].strip().lower())
    return found


def _builds_by_wave(regions: List[str]) -> List[Tuple[str, List[Tuple[str, str, str, int]]]]:
    waves: Dict[Tuple[Tuple[int, int, int], int, str], List[Tuple[str, str, str, int]]] = {}
    for region in regions:
        for fw_str, pre_prefix, vdata in AUTHENTIC_BUILDS_BY_REGION[region]:
            key = (parse_fw_tuple(fw_str), PRE_ORDER[pre_prefix], format_wave_tag(fw_str, pre_prefix))
            waves.setdefault(key, []).append((region, fw_str, pre_prefix, str(vdata)))
    return [(key[2], waves[key]) for key in sorted(waves)]


def latest_wave_tags(regions: List[str]) -> List[str]:
    all_waves = _builds_by_wave(regions)
    needed = set(regions)
    chosen: List[str] = []
    for tag, builds in reversed(all_waves):
        wave_regions = {b[0] for b in builds}
        if not (wave_regions & needed):
            continue
        chosen.append(tag)
        needed -= wave_regions
        if not needed:
            break
    full_waves = _builds_by_wave(list(REGION_MENU_REMAINDER))
    final_tag, final_builds = full_waves[-1]
    if len(chosen) == 1 and chosen[0] == final_tag and len(final_builds) < len(REGION_MENU_REMAINDER):
        for tag, _builds in reversed(all_waves):
            if tag != chosen[0]:
                chosen.append(tag)
                break
    return list(reversed(chosen))


def nus_direct_request(version: str) -> Optional[Tuple[str, Optional[str]]]:
    wanted = version.strip().lower()
    for wave_tag in NUS_DIRECT_WAVES:
        if wanted == wave_tag:
            return wave_tag, None
        if len(wanted) == len(wave_tag) + 1 and wanted.startswith(wave_tag) and wanted[-1] in "euj":
            return wave_tag, wanted[-1].upper()
    return None


def _plan_partitions(session: requests.Session, region: str, wave_tag: str) -> Dict[str, List[Tuple[str, int]]]:
    older = set(UPDATED_BY_NEXT_WAVE.get((wave_tag, region), ()))
    partitions: Dict[str, List[Tuple[str, int]]] = {}
    for part_name in ("SLC", "MLC", "vWii"):
        raw = list(DEFAULT_TITLES_DB[part_name].get(region, [])) + list(DEFAULT_TITLES_DB[part_name]["All"])
        tids = list(dict.fromkeys(normalize_tid(t) for t in raw))
        latest = discover_latest_versions(session, region, tids)
        partitions[part_name] = [
            (t, previous_existing_version(session, t, latest[t]) if t in older else latest[t])
            for t in tids
        ]
    return partitions


def build_nus_direct_waves(
    session: requests.Session,
    regions: List[str],
    wave_tags: List[str],
    letter_filter: Optional[str] = None,
) -> List[dict]:
    builds = dict(_builds_by_wave(regions))
    waves: List[dict] = []
    previous_plans: Dict[str, Dict[str, int]] = {}

    for wave_tag in wave_tags:
        entries: List[dict] = []
        for region, fw_str, pre_prefix, vdata in builds.get(wave_tag, []):
            letter = REGION_SUFFIX[region]
            if letter_filter and letter != letter_filter:
                continue
            partitions = _plan_partitions(session, region, wave_tag)
            plan = {t: v for plist in partitions.values() for t, v in plist}
            if previous_plans.get(region) is None and wave_tag in NUS_DIRECT_WAVES:
                position = NUS_DIRECT_WAVES.index(wave_tag)
                if position > 0:
                    earlier_tag = NUS_DIRECT_WAVES[position - 1]
                    if any(b[0] == region for b in builds.get(earlier_tag, [])):
                        earlier = _plan_partitions(session, region, earlier_tag)
                        previous_plans[region] = {t: v for plist in earlier.values() for t, v in plist}
            vdata_tid = VERSION_DATA_TIDS[region]
            if plan[vdata_tid] != int(vdata):
                raise RuntimeError(
                    f"{format_regional_tag(fw_str, letter, pre_prefix)}: Version Data is v{plan[vdata_tid]} on the "
                    f"Nintendo servers but v{vdata} was expected (a newer firmware may exist; update AUTHENTIC_BUILDS_BY_REGION)"
                )
            entries.append({
                "region": region,
                "reg_letter": letter,
                "fw_str": fw_str,
                "pre_prefix": pre_prefix,
                "wave_tag": wave_tag,
                "reg_tag": format_regional_tag(fw_str, letter, pre_prefix),
                "expected_vdata_ver": int(vdata),
                "partitions": partitions,
                "prev_versions": previous_plans.get(region),
            })
            previous_plans[region] = plan
            print(
                f"[nus-direct] {entries[-1]['reg_tag']}: {len(plan)} titles taken straight from the Nintendo servers",
                flush=True,
            )
        if entries:
            waves.append({
                "wave_tag": wave_tag,
                "fw_tuple": parse_fw_tuple(wave_tag),
                "is_pre": False,
                "entries": entries,
            })
    return waves


def final_build_tags(regions: List[str]) -> Dict[str, str]:
    last: Dict[str, str] = {}
    for region in regions:
        fw_str, pre_prefix, _vdata = AUTHENTIC_BUILDS_BY_REGION[region][-1]
        last[region] = format_regional_tag(fw_str, REGION_SUFFIX[region], pre_prefix)
    return last


def warn_ninupdates_differences(waves: List[dict], yls8_csv_text: str, regions: List[str]) -> None:
    from wiiu_packager_dat import build_all_waves_plan

    table: Dict[str, Dict[str, int]] = {}
    for wave in build_all_waves_plan(yls8_csv_text, target_filter="ALL", regions_filter=regions):
        for entry in wave["entries"]:
            table[entry["reg_tag"]] = {t: v for plist in entry["partitions"].values() for t, v in plist}
    for wave in waves:
        for entry in wave["entries"]:
            plan = {t: v for plist in entry["partitions"].values() for t, v in plist}
            reference = table.get(entry["reg_tag"])
            if reference is None:
                continue
            differences = {t: (reference.get(t), v) for t, v in plan.items() if reference.get(t) != v}
            print(
                f"[ninupdates-check] {entry['reg_tag']}: {len(differences)} title(s) differ from the ninupdates table"
                + (f": {differences}" if differences else ""),
                flush=True,
            )


def verify_latest_builds(
    session: requests.Session,
    waves: List[dict],
    yls8_csv_text: Optional[str],
    regions: List[str],
) -> None:
    final_tags = final_build_tags(regions)
    problems: List[str] = []
    warnings: List[str] = []
    checked = 0

    for wave in waves:
        for entry in wave["entries"]:
            region = entry["region"]
            if entry["reg_tag"] != final_tags.get(region):
                continue
            checked += 1
            plan = {t: v for plist in entry["partitions"].values() for t, v in plist}
            latest = discover_latest_versions(session, region, sorted(plan))
            for tid in sorted(plan):
                if plan[tid] != latest[tid]:
                    problems.append(
                        f"{entry['reg_tag']} {tid}: plan v{plan[tid]} but NUS latest is v{latest[tid]}"
                    )
            for tid in sorted(region_database_tids(region) - set(plan)):
                try:
                    version = fetch_latest_version(session, tid)
                except RuntimeError:
                    continue
                problems.append(f"{entry['reg_tag']} {tid}: exists on the NUS (v{version}) but absent from the plan")
            if yls8_csv_text:
                for tid in sorted(region_tids_in_yls8(yls8_csv_text, region) - set(plan)):
                    warnings.append(f"{entry['reg_tag']} {tid}: listed by ninupdates but absent from the plan")
            print(f"[latest-check] {entry['reg_tag']}: {len(plan)} titles compared with the NUS latest TMDs", flush=True)

    for line in warnings:
        print(f"[warning] {line}", flush=True)
    if problems:
        raise RuntimeError(
            "Latest-build verification failed (a newer firmware may exist; update AUTHENTIC_BUILDS_BY_REGION):\n"
            + "\n".join(problems)
        )
    if checked == 0:
        print("[latest-check] no final build in the selected waves; nothing to compare.", flush=True)
