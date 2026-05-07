import argparse
import hashlib
import json
import os
import sys

import requests

from wiiu_constants import CDN_HOSTS, CDN_PATH, REGION_SUFFIX, normalize_tid
from wiiu_crypto_nus import parse_tmd
from wiiu_packager_dat import build_all_waves_plan

PARTS = (("MLC", os.path.join("MLC", "sys", "title")), ("SLC", os.path.join("SLC", "sys", "title")),
         ("vWii", os.path.join("SLCCMPT", "title")))
VWII_DUMP_TO_NUS = (("00000001", "00000007"), ("00010002", "00070002"), ("00010008", "00070008"))
NUS_ONLY_UNPROVABLE = {"0005001010000200", "0005001010000400"}
FACTORY_ONLY = {"0007000248435445"}


def nus_tid(part, tid):
    if part == "vWii":
        for a, b in VWII_DUMP_TO_NUS:
            if tid.startswith(a):
                return b + tid[8:]
    return tid


def scan_dump(root):
    titles = {}
    for part, sub in PARTS:
        for dp, _dn, fn in os.walk(os.path.join(root, sub)):
            if "title.tmd" not in fn:
                continue
            raw = open(os.path.join(dp, "title.tmd"), "rb").read()
            tmd = parse_tmd(raw)
            tid = nus_tid(part, f"{tmd.title_id:016x}")
            titles[f"{part}/{tid}"] = {
                "version": tmd.title_version,
                "tmd_sha256": hashlib.sha256(raw).hexdigest(),
                "contents": [{"id": c.id, "index": c.index, "type": c.type, "size": c.size, "sha1": c.hash.hex()}
                             for c in tmd.contents],
            }
    return titles


def scan_versions_bin(root):
    path = os.path.join(root, "SLC", "sys", "security", "versions.bin")
    if not os.path.isfile(path):
        return {}
    b = open(path, "rb").read()
    out = {}
    for off in range(0x40, len(b) - 15, 16):
        e = b[off:off + 16]
        if e == b"\xff" * 16:
            continue
        tid = e[:8].hex()
        if tid[:8] in ("00050010", "0005001b", "00050030"):
            out[tid] = int.from_bytes(e[12:14], "big")
    return out


def cmd_build(a):
    data = {"tag": a.tag, "source": "authentic console dump (TMDs only; no console-unique data)",
            "versions_bin": dict(sorted(scan_versions_bin(a.dump).items())),
            "titles": dict(sorted(scan_dump(a.dump).items()))}
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=1)
    print(f"Manifest written: {a.out} ({len(data['titles'])} titles)")


def plan_for_tag(tag):
    head = tag.split("-")[0]
    suffix = head[-1].upper() if head[-1].isalpha() else "U"
    region = {"E": "EUR", "U": "USA", "J": "JPN"}[suffix]
    waves = build_all_waves_plan("tid,region,t,u\n", target_filter=tag, regions_filter=[region])
    plan = {}
    for e in waves[0]["entries"]:
        for part, lst in e["partitions"].items():
            for tid, ver in lst:
                plan[f"{part}/{normalize_tid(tid)}"] = ver
    return plan


def cmd_check(a):
    man = json.load(open(a.manifest, encoding="utf-8"))
    truth = {k: v["version"] for k, v in man["titles"].items()}
    plan = plan_for_tag(man["tag"])
    errors = 0

    for tid, ver in sorted(man.get("versions_bin", {}).items()):
        k = f"SLC/{tid}"
        if k in truth:
            if truth[k] != ver:
                print(f"[VBIN ] {k}: TMD v{truth[k]} != versions.bin v{ver}"); errors += 1
        elif k in plan:
            if plan[k] == ver:
                print(f"[PROOF] {k} v{ver} confirmed by the console's versions.bin")
                truth[k] = ver
            else:
                print(f"[VBIN ] {k}: plan v{plan[k]} != versions.bin v{ver}"); errors += 1
    for k in sorted(set(plan) - set(truth)):
        if k.split("/")[1] in NUS_ONLY_UNPROVABLE:
            print(f"[NOTE ] {k} v{plan[k]} is planned but cannot be proven by a dump (not installed under sys/title)")
        else:
            print(f"[EXTRA] {k} v{plan[k]} would be downloaded but is NOT in the authentic dump"); errors += 1
    for k in sorted(set(truth) - set(plan)):
        if k.split("/")[1] in FACTORY_ONLY:
            print(f"[NOTE ] {k} v{truth[k]} is in the dump but not on NUS (factory-only)")
        else:
            print(f"[MISS ] {k} v{truth[k]} is in the authentic dump but missing from the plan"); errors += 1
    for k in sorted(set(plan) & set(truth)):
        if plan[k] != truth[k]:
            print(f"[VER  ] {k}: plan v{plan[k]} != dump v{truth[k]}"); errors += 1

    if a.nus:
        s = requests.Session()
        ok = 0
        for k, v in sorted(man["titles"].items()):
            tid = k.split("/")[1]
            if tid in FACTORY_ONLY:
                continue
            tmd = None
            for host in CDN_HOSTS:
                try:
                    r = s.get(f"http://{host}{CDN_PATH}/{tid}/tmd.{v['version']}", timeout=20)
                    if r.status_code == 200:
                        tmd = r.content
                        break
                except requests.RequestException:
                    continue
            if tmd is None:
                print(f"[NUS  ] {k} v{v['version']} not downloadable"); errors += 1
                continue
            body = tmd[: len(tmd)]
            if hashlib.sha256(body[: _tmd_len(body)]).hexdigest() != v["tmd_sha256"]:
                print(f"[NUS  ] {k} v{v['version']} TMD differs from the dump"); errors += 1
            else:
                ok += 1
        print(f"NUS check: {ok} TMD(s) byte-identical to Nintendo's")

    print("RESULT:", "OK - plan matches the authentic dump" if errors == 0 else f"{errors} problem(s)")
    sys.exit(1 if errors else 0)


def _tmd_len(b):
    ver = b[0x180]
    n = int.from_bytes(b[0x1DE:0x1E0], "big")
    return (0xB04 + n * 0x30) if ver == 1 else (0x1E4 + n * 0x24)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build"); b.add_argument("--dump", required=True); b.add_argument("--tag", required=True)
    b.add_argument("--out", required=True); b.set_defaults(fn=cmd_build)
    c = sub.add_parser("check"); c.add_argument("--manifest", required=True)
    c.add_argument("--nus", action="store_true"); c.set_defaults(fn=cmd_check)
    a = p.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()

