import json
import os
from typing import Dict, List, Optional, Tuple

from wiiu_constants import AUTHENTIC_BUILDS_BY_REGION, REGION_SUFFIX, format_regional_tag, format_wave_tag
from wiiu_packager_dat import build_wave_release_notes

PARTS = ("SLC", "MLC", "vWii")


def manifest_path(directory: str, reg_tag: str) -> str:
    return os.path.join(directory, f"{reg_tag}.json")


def write_build_manifest(
    directory: str,
    entry: dict,
    titles_by_part: Dict[str, List[Tuple[str, int, str]]],
    build_date: Optional[str],
) -> str:
    os.makedirs(directory, exist_ok=True)
    data = {
        "reg_tag": entry["reg_tag"],
        "wave_tag": entry["wave_tag"],
        "region": entry["region"],
        "fw_str": entry["fw_str"],
        "pre_prefix": entry["pre_prefix"],
        "build_date": build_date,
        "titles": {
            part: [[tid, int(version), name] for tid, version, name in titles_by_part.get(part, [])]
            for part in PARTS
        },
    }
    path = manifest_path(directory, entry["reg_tag"])
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=1, sort_keys=True)
    return path


def load_build_manifest(directory: str, reg_tag: str) -> Optional[dict]:
    path = manifest_path(directory, reg_tag)
    if not os.path.isfile(path):
        return None
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def manifest_versions(manifest: dict) -> Dict[str, int]:
    return {tid: int(version) for part in PARTS for tid, version, _name in manifest["titles"][part]}


def previous_build_tag(region: str, fw_str: str, pre_prefix: str) -> Optional[str]:
    builds = AUTHENTIC_BUILDS_BY_REGION[region]
    for index, (fw, pre, _vdata) in enumerate(builds):
        if fw == fw_str and pre == pre_prefix:
            if index == 0:
                return None
            prev_fw, prev_pre, _ = builds[index - 1]
            return format_regional_tag(prev_fw, REGION_SUFFIX[region], prev_pre)
    raise KeyError(f"{fw_str} {pre_prefix} is not a known build for {region}")


def finalize_wave_notes(directory: str, wave_tag: str) -> Tuple[str, str]:
    results: List[dict] = []
    for name in sorted(os.listdir(directory)):
        if not name.endswith(".json"):
            continue
        manifest = load_build_manifest(directory, name[:-5])
        if manifest is None or manifest["wave_tag"] != wave_tag:
            continue
        previous_tag = previous_build_tag(manifest["region"], manifest["fw_str"], manifest["pre_prefix"])
        if previous_tag is None:
            prev_versions: Optional[Dict[str, int]] = {}
        else:
            previous = load_build_manifest(directory, previous_tag)
            prev_versions = manifest_versions(previous) if previous else None
        results.append({
            "region": manifest["region"],
            "reg_tag": manifest["reg_tag"],
            "zip_name": "",
            "zip_sha256": "",
            "ext_zip_name": "",
            "ext_zip_sha256": "",
            "identity": {"latest_build_date": manifest.get("build_date")},
            "titles_by_part": {
                part: [(tid, int(version), title_name) for tid, version, title_name in manifest["titles"][part]]
                for part in PARTS
            },
            "prev_versions": prev_versions,
        })
    if not results:
        raise FileNotFoundError(f"No build manifest found for wave {wave_tag} in {directory}")
    return build_wave_release_notes(wave_tag, results)
