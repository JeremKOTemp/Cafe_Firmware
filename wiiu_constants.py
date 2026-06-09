import os
import re
import json
import struct
import hashlib
import threading
from os.path import abspath, dirname, exists, join
from typing import Dict, List, Optional, Tuple

BASE_DIR = dirname(abspath(__file__))

STRUCT_Q = struct.Struct(">Q")
STRUCT_I = struct.Struct(">I")
STRUCT_H = struct.Struct(">H")
STRUCT_II = struct.Struct(">II")
STRUCT_HH = struct.Struct(">HH")
STRUCT_HHH = struct.Struct(">HHH")
STRUCT_CONTENT = struct.Struct(">IHHQ")
STRUCT_VERSION_BIN = struct.Struct(">4sIIIB")

STOP_EVENT = threading.Event()
VERBOSE_LOGS = False

YLS8_CSV_URL = "https://yls8.mtheall.com/ninupdates/titlelist.php?sys=wup&csv=1"
YLS8_VWII_CSV_URL = "https://yls8.mtheall.com/ninupdates/titlelist.php?sys=wupv&csv=1"

WIIU_COMMON_KEY_SHA1 = "6a0b87fc98b306ae3366f0e0a88d0b06a2813313"
EXTRA_KEY_ENV_SHA1 = {
    "VWII_COMMON_KEY": "2b30b703c6676c8124c7347b30c7972ffeae2b39",
    "WII_COMMON_KEY": "ebeae6d2762d4d3ea160a6d8327fac9a25f8062b",
    "WII_KOREAN_KEY": "5bacdb63dd28a1cc1b509a93712032befb9eadb5",
}
OTP_COMMON_KEY_OFFSET = 0x0E0

VWII_IOS_INSTALL_ORDER = (
    0x00000002, 0x00000050, 0x00000009, 0x0000000C, 0x0000000D, 0x0000000E, 0x0000000F, 0x00000011,
    0x00000015, 0x00000016, 0x0000001C, 0x0000001F, 0x00000021, 0x00000022, 0x00000023, 0x00000024,
    0x00000025, 0x00000026, 0x00000029, 0x0000002B, 0x0000002D, 0x0000002E, 0x00000030, 0x00000035,
    0x00000037, 0x00000038, 0x00000039, 0x0000003A, 0x00000200, 0x00000201, 0x0000003B, 0x0000003E,
)
VWII_CHANNEL_INSTALL_ORDER = ("HAB", "HAC", "HCT", "HCV", "HAL", "HCU", "HCZ")
VWII_CERT_SYS_ORDER = ("XS", "CA", "CP")


def load_key_from_env(name: str) -> Optional[bytes]:
    raw = os.environ.get(name, "").strip().strip('"').strip("'")
    if not raw:
        return None
    try:
        key = bytes.fromhex(raw)
    except ValueError:
        raise ValueError(f"Environment variable {name} is not a 32-character hexadecimal key.")
    expected = EXTRA_KEY_ENV_SHA1.get(name)
    if len(key) != 16 or (expected is not None and hashlib.sha1(key).hexdigest() != expected):
        raise ValueError(f"Environment variable {name} does not contain the expected key (SHA-1 mismatch).")
    return key


def load_extra_common_keys() -> List[bytes]:
    keys: List[bytes] = []
    for name in EXTRA_KEY_ENV_SHA1:
        key = load_key_from_env(name)
        if key is not None:
            keys.append(key)
    return keys

CDN_HOSTS = [
    "ccs.cdn.c.shop.nintendowifi.net",
    "ccs.cdn.wup.shop.nintendo.net",
    "nus.cdn.c.shop.nintendowifi.net",
    "nus.cdn.wup.shop.nintendo.net",
]
CDN_PATH = "/ccs/download"
OSV10_TID = "000500101000400a"
FST_MAGIC = b"FST\x00"
VER_BIN_MAGIC = b"VER\x00"

NINTENDO_GROUP_ID = 0x0001
TMD_CONTENT_FLAG_ENCRYPTED = 0x0001
TMD_CONTENT_FLAG_HASHED = 0x0002
TMD_CONTENT_FLAG_CAFE = 0x2000
TMD_CONTENT_FLAG_SHARED_VWII = 0x8000

VWII_WUP_TID_HIGHS = {0x00000007, 0x00070002, 0x00070008}

VERSION_DATA_TIDS = {"JPN": "0005001010041000", "USA": "0005001010041100", "EUR": "0005001010041200"}
WIIU_MENU_TIDS = {"JPN": "0005001010040000", "USA": "0005001010040100", "EUR": "0005001010040200"}
CEMU_PARTITION_FOLDERS = {"MLC": "mlc01", "SLC": "slc01", "vWii": "slccmpt01"}

REGION_SUFFIX = {"EUR": "E", "USA": "U", "JPN": "J"}
SUFFIX_TO_REGION = {"E": "EUR", "U": "USA", "J": "JPN"}

MAX_RETRIES = 5
CHUNK_SIZE = 4 * 1024 * 1024
IN_MEMORY_MAX_SIZE = 4 * 1024 * 1024
FAST_REQ_TIMEOUT = (3.05, 8.0)

RE_FW_TUPLE = re.compile(r"(\d+)\.(\d+)\.?(\d+)?")
RE_APP_XML_VER = re.compile(rb"<title_version[^>]*>([0-9a-fA-F]+)</title_version>")
RE_APP_XML_SDK = re.compile(rb"<sdk_version[^>]*>(\d+)</sdk_version>")

WAVE_METADATA: Dict[str, Dict[str, str]] = {
    "1.0.0":      {"date": "2012-11-01"},
    "1.0.1":      {"date": "2012-11-18"},
    "1.0.2":      {"date": "2012-11-18"},
    "1.0.3-pre":  {"date": "2012-11-18"},
    "1.0.4-pre":  {"date": "2012-11-18"},
    "1.0.5-pre":  {"date": "2012-11-18"},
    "2.0.0":      {"date": "2012-11-18"},
    "2.0.1-pre":  {"date": "2012-11-26"},
    "2.0.2-pre":  {"date": "2012-11-26"},
    "2.1.0":      {"date": "2012-12-04"},
    "2.1.1-pre":  {"date": "2012-12-15"},
    "2.1.2-pre":  {"date": "2013-01-15"},
    "2.1.3":      {"date": "2013-03-05"},
    "2.1.4-pre":  {"date": "2013-03-15"},
    "2.1.5-pre":  {"date": "2013-04-01"},
    "2.2.0-pre":  {"date": "2013-04-15"},
    "3.0.0":      {"date": "2013-04-25"},
    "3.0.1":      {"date": "2013-05-13"},
    "3.0.2-pre":  {"date": "2013-05-25"},
    "3.0.3-pre":  {"date": "2013-06-10"},
    "3.0.4-pre":  {"date": "2013-06-25"},
    "3.1.0":      {"date": "2013-07-10"},
    "3.1.1-pre":  {"date": "2013-08-01"},
    "3.2.0-pre":  {"date": "2013-09-15"},
    "4.0.0":      {"date": "2013-09-30"},
    "4.0.1":      {"date": "2013-10-08"},
    "4.0.2":      {"date": "2013-11-18"},
    "4.0.3":      {"date": "2014-02-24"},
    "4.1.0-pre":  {"date": "2014-03-20"},
    "4.1.0":      {"date": "2014-03-31"},
    "5.0.0-pre0": {"date": "2014-05-15"},
    "5.0.0-pre":  {"date": "2014-05-25"},
    "5.0.0":      {"date": "2014-06-02"},
    "5.1.0-pre":  {"date": "2014-07-10"},
    "5.1.0":      {"date": "2014-07-21"},
    "5.1.1":      {"date": "2014-08-04"},
    "5.1.2":      {"date": "2014-08-25"},
    "5.2.0-pre":  {"date": "2014-09-15"},
    "5.2.0":      {"date": "2014-09-29"},
    "5.3.0-pre":  {"date": "2014-10-25"},
    "5.3.0":      {"date": "2014-11-10"},
    "5.3.1":      {"date": "2014-12-01"},
    "5.3.2":      {"date": "2014-12-04"},
    "5.4.0":      {"date": "2015-06-08"},
    "5.5.0":      {"date": "2015-08-17"},
    "5.5.1":      {"date": "2016-01-11"},
    "5.5.2":      {"date": "2017-07-17"},
    "5.5.3":      {"date": "2018-09-03"},
    "5.5.4":      {"date": "2019-06-24"},
    "5.5.5":      {"date": "2021-03-01"},
    "5.5.6":      {"date": "2022-08-29"},
}

_COMMON_TAIL_BUILDS: List[Tuple[str, str, int]] = [
    ("2.0.1", "PRE_", 112), ("2.0.2", "PRE_", 128), ("2.1.0", "", 144),
    ("2.1.1", "PRE_", 160), ("2.1.2", "PRE_", 176), ("2.1.3", "", 178),
    ("2.1.4", "PRE_", 180), ("2.1.5", "PRE_", 182), ("2.2.0", "PRE_", 184),
    ("3.0.0", "", 192), ("3.0.1", "", 195), ("3.0.2", "PRE_", 198),
    ("3.0.3", "PRE_", 201), ("3.0.4", "PRE_", 204), ("3.1.0", "", 208),
    ("3.1.1", "PRE_", 224), ("3.2.0", "PRE_", 272), ("4.0.0", "", 288),
    ("4.0.2", "", 320), ("4.0.3", "", 336), ("4.1.0", "PRE_", 336),
    ("4.1.0", "", 352), ("5.0.0", "PRE0_", 352), ("5.0.0", "PRE_", 352),
    ("5.0.0", "", 368), ("5.1.0", "PRE_", 368), ("5.1.0", "", 384),
    ("5.1.1", "", 400), ("5.1.2", "", 432), ("5.2.0", "PRE_", 432),
    ("5.2.0", "", 448), ("5.3.0", "PRE_", 448), ("5.3.0", "", 464),
    ("5.3.1", "", 480), ("5.3.2", "", 496), ("5.4.0", "", 512),
    ("5.5.0", "", 528), ("5.5.1", "", 544), ("5.5.2", "", 560),
    ("5.5.3", "", 576),
]

AUTHENTIC_BUILDS_BY_REGION: Dict[str, List[Tuple[str, str, int]]] = {
    "EUR": [
        ("1.0.0", "", 0), ("1.0.1", "", 17), ("1.0.2", "", 32),
        ("1.0.3", "PRE_", 49), ("1.0.4", "PRE_", 64), ("1.0.5", "PRE_", 80),
        ("2.0.0", "", 96), *_COMMON_TAIL_BUILDS,
        ("5.5.4", "", 592), ("5.5.5", "", 608),
    ],
    "JPN": [
        ("1.0.0", "", 0), ("1.0.1", "", 17),
        ("1.0.3", "PRE_", 49), ("1.0.4", "PRE_", 64), ("1.0.5", "PRE_", 80),
        *[b for b in _COMMON_TAIL_BUILDS[:18]],
        ("4.0.1", "", 304),
        *[b for b in _COMMON_TAIL_BUILDS[18:]],
        ("5.5.5", "", 608),
    ],
    "USA": [
        ("1.0.0", "", 0), ("1.0.1", "", 17), ("1.0.2", "", 32),
        ("1.0.3", "PRE_", 49), ("1.0.4", "PRE_", 64), ("1.0.5", "PRE_", 80),
        ("2.0.0", "", 96), *_COMMON_TAIL_BUILDS,
        ("5.5.5", "", 608), ("5.5.6", "", 624),
    ],
}


def _build_default_titles_db() -> dict:
    mlc_by_reg = {}
    vwii_by_reg = {}
    for reg, idx, v_hex in (("JPN", "0", "4a"), ("USA", "1", "45"), ("EUR", "2", "50")):
        mlc_by_reg[reg] = (
            [f"00050010100{p}{idx}00" for p in ("40", "41", "43", "44", "45", "47", "48", "49", "4a", "4b", "4c", "4d", "4e", "5a", "62")]
            + [f"0005001b100{p}{idx}00" for p in ("59", "67", "69")]
            + [
                f"0005003010010{idx}09", f"0005003010010{idx}0a",
                f"0005003010011{idx}09", f"0005003010011{idx}0a", f"0005003010011{idx}ff",
                f"0005003010012{idx}0a", f"0005003010013{idx}0a", f"0005003010014{idx}0a",
                f"0005003010015{idx}0a", f"0005003010016{idx}0a",
                f"0005003010017{idx}09", f"0005003010017{idx}0a",
                f"0005003010018{idx}0a", f"0005003010019{idx}0a", f"000500301006d{idx}0a",
            ]
        )
        vwii_by_reg[reg] = [
            f"00070002484355{v_hex}",
            f"0007000848414c{v_hex}",
            f"0007000848435a{v_hex}",
        ]
    return {
        "MLC": {
            **mlc_by_reg,
            "All": [
                "0005001010066000", "0005001b10042300", "0005001b10042400",
                "0005001b1004f000", "0005001b10050000", "0005001b10051000",
                "0005001b10052000", "0005001b10053000", "0005001b10054000",
                "0005001b10056000", "0005001b10057000", "0005001b10058000",
                "0005001b1005c000", "0005001b1005f000", "0005001b10063000",
                "0005001b10065000", "0005001b10068000", "0005001b1006c000",
                "000500301001a10a",
            ],
        },
        "SLC": {
            "EUR": [], "USA": [], "JPN": [],
            "All": [
                "0005001010000100", "0005001010000200", "0005001010000400",
                "0005001010004000", "0005001010004001", "0005001010004009",
                "000500101000400a", "00050010100040ff",
            ],
        },
        "vWii": {
            **vwii_by_reg,
            "All": [
                *[f"00000007000000{s}" for s in (
                    "02", "09", "0c", "0d", "0e", "0f", "11", "15", "16", "1c",
                    "1f", "21", "22", "23", "24", "25", "26", "29", "2b", "2d",
                    "2e", "30", "35", "37", "38", "39", "3a", "3b", "3e", "50",
                )],
                "0000000700000200", "0000000700000201",
                "0007000248414241", "0007000248414341", "0007000248435641",
            ],
        },
    }


DEFAULT_TITLES_DB = _build_default_titles_db()

BUILTIN_TITLE_NAMES: Dict[str, str] = {
    "0005001010000100": "boot1",
    "0005001010000200": "DRH-Firmware",
    "0005001010000400": "Bluetooth-Firmware",
    "0005001010004000": "OSv0-cafe2wii",
    "0005001010004001": "OSv1-HAI-IOS",
    "0005001010004009": "OSv9-CafeOS",
    "000500101000400a": "OSv10-CafeOS",
    "00050010100040ff": "OSv255-UpdaterOS",
    "0005001010066000": "ECO Process",
    "0005001b10042300": "Shared-memoryclear_exceptions",
    "0005001b10042400": "Shared-SystemFonts",
    "0005001b1004f000": "Shared-SWKBD",
    "0005001b10050000": "Shared-DeviceEula",
    "0005001b10051000": "Shared-ErrEula",
    "0005001b10052000": "Shared-CountryData",
    "0005001b10053000": "Shared-NGWord",
    "0005001b10054000": "Shared-SSL-Certs",
    "0005001b10056000": "Shared-mii_resource",
    "0005001b10057000": "Shared-startup_data",
    "0005001b10058000": "Shared-DRMApp",
    "0005001b1005c000": "Shared-iso_resource",
    "0005001b1005f000": "Shared-OS-Patch-Map",
    "0005001b10063000": "Shared-wagonu_specification",
    "0005001b10065000": "Shared-live_dat",
    "0005001b10068000": "Shared-sl_list",
    "0005001b1006c000": "Shared-trial_list",
    "000500301001a10a": "AOC Overlay App",
    "0000000700000002": "vWii-System-Menu",
    "0000000700000200": "vWii-BC-NAND",
    "0000000700000201": "vWii-BC-WFS",
    "0007000248414241": "vWii-Shop-Channel",
    "0007000248414341": "vWii-Mii-Channel",
    "0007000248435641": "vWii-Return-to-WiiU-Menu",
}
for _r_name, _idx, _vh in (("JPN", "0", "4a"), ("USA", "1", "45"), ("EUR", "2", "50")):
    for _p, _lbl in (
        ("40", "Wii U Menu"), ("41", "Version Data"), ("43", "DRC GamePad Firmware"),
        ("44", "DRC Language Atlas"), ("45", "System Updater"), ("47", "System Settings"),
        ("48", "Parental Controls"), ("49", "User Settings"), ("4a", "Mii Maker"),
        ("4b", "Account Settings"), ("4c", "Daily Log"), ("4d", "Notifications"),
        ("4e", "Health and Safety"), ("5a", "Wii U Chat"), ("62", "Software Data Transfer"),
    ):
        BUILTIN_TITLE_NAMES[f"00050010100{_p}{_idx}00"] = f"{_lbl} {_r_name}"
    for _p, _lbl in (("59", "Shared-E-Manual-Data"), ("67", "Shared-layout_default"), ("69", "Shared-pclkey")):
        BUILTIN_TITLE_NAMES[f"0005001b100{_p}{_idx}00"] = f"{_lbl} {_r_name}"
    for _s, _lbl in (
        ("10" + _idx + "09", "HOME Menu OSv9"), ("10" + _idx + "0a", "HOME Menu OSv10"),
        ("11" + _idx + "09", "Fatal Error Viewer OSv9"), ("11" + _idx + "0a", "Fatal Error Viewer OSv10"),
        ("11" + _idx + "ff", "Fatal Error Viewer OSv255"), ("12" + _idx + "0a", "Internet Browser"),
        ("13" + _idx + "0a", "Nintendo TVii"), ("14" + _idx + "0a", "Nintendo eShop"),
        ("15" + _idx + "0a", "Friend List"), ("16" + _idx + "0a", "Miiverse"),
        ("17" + _idx + "09", "E-Manual OSv9"), ("17" + _idx + "0a", "E-Manual OSv10"),
        ("18" + _idx + "0a", "Download Management"), ("19" + _idx + "0a", "Miiverse Post App"),
        ("6d" + _idx + "0a", "amiibo Settings"),
    ):
        BUILTIN_TITLE_NAMES[f"00050030100{_s}"] = f"{_lbl} {_r_name}"
    BUILTIN_TITLE_NAMES[f"00070002484355{_vh}"] = f"vWii-E-Manual {_r_name}"
    BUILTIN_TITLE_NAMES[f"0007000848414c{_vh}"] = f"vWii-rgnsel {_r_name}"
    BUILTIN_TITLE_NAMES[f"0007000848435a{_vh}"] = f"vWii-WagonCompat {_r_name}"

PRE_200_EXACT_VERSIONS: Dict[str, int] = {
    "0005001010000100": 8296, "0005001010000200": 5127, "0005001010000400": 517,
    "0005001010004000": 0,    "0005001010004009": 1006, "00050010100040ff": 771,
    **{f"0005001010043{r}00": 5126 for r in ("0", "1", "2")},
    **{f"0005001010044{r}00": 4864 for r in ("0", "1", "2")},
    **{
        f"00050010100{p}{r}00": 0
        for p in ("40", "41", "45", "47", "48", "49", "4a", "4c", "4d", "4e")
        for r in ("0", "1", "2")
    },
    **{f"0005001b10059{r}00": 0 for r in ("0", "1", "2")},
    **{f"00050030100{s}{r}09": 0 for s in ("10", "11", "17") for r in ("0", "1", "2")},
    **{f"0005003010011{r}ff": 0 for r in ("0", "1", "2")},
    "0005001b10042300": 0, "0005001b10042400": 0, "0005001b1004f000": 0,
    "0005001b10050000": 0, "0005001b10051000": 0, "0005001b10052000": 0,
    "0005001b10053000": 0, "0005001b10054000": 0, "0005001b10056000": 1,
    "0005001b10057000": 0, "0005001b10058000": 0, "0005001b1005c000": 0,
}

JPN_200_EXACT_FALLBACK: Dict[str, int] = {
    "0005001010000100": 8325, "0005001010000200": 5382, "0005001010000400": 517,
    "0005001010004000": 0,    "0005001010004009": 1006, "000500101000400a": 3733,
    "00050010100040ff": 1054, "0005001010040000": 24,   "0005001010043000": 5382,
    "0005001010044000": 4864, "0005001010045000": 22,   "0005001010047000": 24,
    "0005001010048000": 24,   "0005001010049000": 24,   "000500101004a000": 22,
    "000500101004b000": 6,    "000500101004c000": 24,   "000500101004d000": 24,
    "000500101004e000": 25,   "000500101005a000": 9,    "0005001b10059000": 18,
    "0005003010010009": 0,    "000500301001000a": 24,   "0005003010011009": 0,
    "000500301001100a": 16,   "00050030100110ff": 0,    "000500301001200a": 8,
    "000500301001300a": 8,    "000500301001400a": 10,   "000500301001500a": 8,
    "000500301001600a": 9,    "0005003010017009": 16,   "000500301001700a": 23,
    "000500301001800a": 6,    "000500301001900a": 9,    "0005001b10042300": 0,
    "0005001b10042400": 0,    "0005001b1004f000": 16,   "0005001b10050000": 0,
    "0005001b10051000": 17,   "0005001b10052000": 16,   "0005001b10053000": 0,
    "0005001b10054000": 5,    "0005001b10056000": 1,    "0005001b10057000": 0,
    "0005001b10058000": 21,   "0005001b1005c000": 0,    "0005001b1005f000": 0,
}

VWII_STATIC_VERSIONS: Dict[str, int] = {
    "0000000700000009": 1290, "000000070000000c": 782,  "000000070000000d": 1288,
    "000000070000000e": 1288, "000000070000000f": 1288, "0000000700000011": 1288,
    "0000000700000015": 1295, "0000000700000016": 1550, "000000070000001c": 2063,
    "000000070000001f": 3864, "0000000700000021": 3864, "0000000700000022": 3864,
    "0000000700000023": 3864, "0000000700000024": 3864, "0000000700000025": 5919,
    "0000000700000026": 4380, "0000000700000029": 3863, "000000070000002b": 3863,
    "000000070000002d": 3863, "000000070000002e": 3863, "0000000700000030": 4380,
    "0000000700000035": 5919, "0000000700000037": 5919, "0000000700000038": 5918,
    "0000000700000039": 6175, "000000070000003a": 6432, "0000000700000050": 7200,
    "0000000700000201": 1,    "0007000248414241": 21,   "0007000248414341": 6,
    "0007000248435641": 0,    "0007000848414c45": 2,    "0007000848414c4a": 2,
    "0007000848414c50": 2,
}


def set_verbose(enabled: bool) -> None:
    global VERBOSE_LOGS
    VERBOSE_LOGS = bool(enabled)


def log_print(msg: str) -> None:
    if VERBOSE_LOGS:
        print(f"[LOG] {msg}", flush=True)


def normalize_tid(title_id: str) -> str:
    return title_id.replace("-", "").replace("/", "").replace("\\", "").strip().lower()


def is_valid_tid(title_id: str) -> bool:
    clean = normalize_tid(title_id)
    if len(clean) != 16:
        return False
    try:
        int(clean, 16)
        return True
    except ValueError:
        return False


def parse_fw_tuple(fw_version: str) -> Tuple[int, int, int]:
    match = RE_FW_TUPLE.search(fw_version)
    if not match:
        raise ValueError(f"Invalid firmware version format: {fw_version}")
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)) if match.group(3) else 0)


def format_wave_tag(fw_str: str, pre_prefix: str) -> str:
    if pre_prefix == "PRE0_":
        return f"{fw_str}-pre0"
    if pre_prefix == "PRE_":
        return f"{fw_str}-pre"
    return fw_str


def format_regional_tag(fw_str: str, reg_letter: str, pre_prefix: str) -> str:
    if pre_prefix == "PRE0_":
        return f"{fw_str}{reg_letter}-pre0"
    if pre_prefix == "PRE_":
        return f"{fw_str}{reg_letter}-pre"
    return f"{fw_str}{reg_letter}"


def load_title_names_map(base_dir: str = BASE_DIR) -> Dict[str, str]:
    names = dict(BUILTIN_TITLE_NAMES)
    json_path = join(base_dir, "all_titles.json")
    if exists(json_path):
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            entries = data.get("all_titles", data)
            if isinstance(entries, dict):
                for tid, info in entries.items():
                    clean_t = tid.strip().lower()
                    if not is_valid_tid(clean_t):
                        continue
                    if isinstance(info, dict) and info.get("name"):
                        names[clean_t] = str(info["name"])
                    elif isinstance(info, str) and info:
                        names[clean_t] = info
        except Exception as e:
            log_print(f"Could not parse all_titles.json ({e}), using built-in title map.")
    return names


def get_friendly_title_name(tid: str, title_names_map: Dict[str, str]) -> str:
    clean_t = tid.strip().lower()
    if clean_t in title_names_map:
        return title_names_map[clean_t]
    if clean_t.startswith("00000007"):
        return f"vWii-IOS{int(clean_t[8:], 16)}"
    return clean_t.upper()


def validate_database_integrity() -> None:
    if OSV10_TID not in DEFAULT_TITLES_DB["SLC"]["All"]:
        raise RuntimeError(f"Missing core OSv10 Title ID ({OSV10_TID}) in SLC database.")

    for reg, builds in AUTHENTIC_BUILDS_BY_REGION.items():
        if reg not in REGION_SUFFIX:
            raise RuntimeError(f"Unknown region in AUTHENTIC_BUILDS_BY_REGION: {reg}")
        if VERSION_DATA_TIDS[reg] not in DEFAULT_TITLES_DB["MLC"][reg]:
            raise RuntimeError(f"Missing Version Data TID for {reg} in MLC database.")
        if WIIU_MENU_TIDS[reg] not in DEFAULT_TITLES_DB["MLC"][reg]:
            raise RuntimeError(f"Missing Wii U Menu TID for {reg} in MLC database.")
        prev_vdata = -1
        for fw_str, pre_prefix, vdata_ver in builds:
            parse_fw_tuple(fw_str)
            w_tag = format_wave_tag(fw_str, pre_prefix)
            meta = WAVE_METADATA.get(w_tag)
            if not meta or not re.match(r"^\d{4}-\d{2}-\d{2}$", meta.get("date", "")):
                raise RuntimeError(f"Missing or invalid metadata date for wave {w_tag}")
            if vdata_ver < prev_vdata:
                raise RuntimeError(f"Non-monotonic version.bin value in {reg} ({w_tag}): {vdata_ver} < {prev_vdata}")
            prev_vdata = vdata_ver

    for part_name, reg_dict in DEFAULT_TITLES_DB.items():
        for reg_key, tids in reg_dict.items():
            for tid in tids:
                if not is_valid_tid(tid):
                    raise RuntimeError(f"Invalid Title ID in DEFAULT_TITLES_DB[{part_name}][{reg_key}]: {tid}")

    for table_name, table in (
        ("PRE_200_EXACT_VERSIONS", PRE_200_EXACT_VERSIONS),
        ("JPN_200_EXACT_FALLBACK", JPN_200_EXACT_FALLBACK),
        ("VWII_STATIC_VERSIONS", VWII_STATIC_VERSIONS),
    ):
        for tid, ver in table.items():
            if not is_valid_tid(tid) or ver < 0:
                raise RuntimeError(f"Invalid entry in {table_name}: {tid} -> {ver}")


validate_database_integrity()
