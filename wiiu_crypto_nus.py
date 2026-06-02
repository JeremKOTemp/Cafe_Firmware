import os
import time
import stat
import shutil
import socket
import struct
import hashlib
import binascii
import threading
from os.path import join
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set, Tuple

import requests
from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPConnection
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from wiiu_constants import (
    BASE_DIR,
    CDN_HOSTS,
    CDN_PATH,
    CHUNK_SIZE,
    FAST_REQ_TIMEOUT,
    FST_MAGIC,
    IN_MEMORY_MAX_SIZE,
    MAX_RETRIES,
    OSV10_TID,
    OTP_COMMON_KEY_OFFSET,
    STOP_EVENT,
    STRUCT_CONTENT,
    STRUCT_H,
    STRUCT_HH,
    STRUCT_HHH,
    STRUCT_I,
    STRUCT_II,
    STRUCT_Q,
    STRUCT_VERSION_BIN,
    VER_BIN_MAGIC,
    VWII_CERT_SYS_ORDER,
    VWII_CHANNEL_INSTALL_ORDER,
    VWII_IOS_INSTALL_ORDER,
    VWII_WUP_TID_HIGHS,
    WIIU_COMMON_KEY_SHA1,
    YLS8_CSV_URL,
    YLS8_VWII_CSV_URL,
    is_valid_tid,
    load_extra_common_keys,
    load_key_from_env,
    log_print,
    normalize_tid,
)

_BACKEND = default_backend()
cdn_lock = threading.Lock()
cert_lock = threading.Lock()

_FALLBACK_CDN_HOSTS = (
    "ccs.cdn.c.shop.nintendowifi.net",
    "ccs.cdn.wup.shop.nintendo.net",
    "nus.cdn.wup.shop.nintendo.net",
)
_EFFECTIVE_CDN_HOSTS: List[str] = list(dict.fromkeys(list(CDN_HOSTS) + list(_FALLBACK_CDN_HOSTS)))
_ACTIVE_CDN_SCHEME = "http"
active_cdn_idx = 0
DEFAULT_CERT_DATA = b""

_DEFAULT_CERT_FALLBACK_TIDS = (
    "000500101000400a",
    "0005001010004009",
    "0005001010004001",
    "0005001010040000",
    "0005001010040100",
    "0005001010040200",
)


@dataclass(slots=True)
class Content:
    id: int = 0
    index: int = 0
    type: int = 0
    size: int = 0
    hash: bytes = b""


@dataclass(slots=True)
class TMD:
    title_id: int = 0
    title_id_bin: bytes = b""
    version: int = 0
    system_version: int = 0
    title_type: int = 0
    group_id: int = 0
    access_rights: int = 0
    title_version: int = 0
    content_count: int = 0
    boot_index: int = 0
    contents: List[Content] = field(default_factory=list)


@dataclass(slots=True)
class _ParsedCert:
    raw: bytes
    sig_type: int
    signature: bytes
    signed_body: bytes
    issuer: str
    key_type: int
    name: str
    public_key: Optional[rsa.RSAPublicKey]


class _FastTCPAdapter(HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        sock_opts = list(HTTPConnection.default_socket_options) + [
            (socket.IPPROTO_TCP, socket.TCP_NODELAY, 1),
            (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1),
        ]
        pool_kwargs["socket_options"] = sock_opts
        super().init_poolmanager(connections, maxsize, block=block, **pool_kwargs)


def create_optimized_session() -> requests.Session:
    session = requests.Session()
    adapter = _FastTCPAdapter(pool_connections=96, pool_maxsize=96, max_retries=1, pool_block=False)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({
        "Connection": "keep-alive",
        "User-Agent": "WiiUDownloader/1.0",
        "Accept-Encoding": "identity",
    })
    return session


def _fetch_yls8_single_csv(session: requests.Session, url: str) -> str:
    log_print(f"Downloading title version list from {url}...")
    last_err = ""
    for attempt in range(MAX_RETRIES):
        try:
            r = session.get(
                url,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
                timeout=(5.0, 15.0),
            )
            r.raise_for_status()
            text = r.text
            if "TitleID,Region" in text and len(text.splitlines()) > 50:
                return text
            raise RuntimeError("Invalid or truncated CSV received from yls8.mtheall.com")
        except Exception as e:
            last_err = str(e)
            if attempt < MAX_RETRIES - 1:
                time.sleep(0.5)
    raise RuntimeError(f"Failed to download yls8 CSV from {url}: {last_err}")


def fetch_yls8_csv_online(session: requests.Session) -> str:
    wup_text = _fetch_yls8_single_csv(session, YLS8_CSV_URL)
    vwii_text = _fetch_yls8_single_csv(session, YLS8_VWII_CSV_URL)
    vwii_rows = vwii_text.replace("\r", "").strip().split("\n")[1:]
    return wup_text.replace("\r", "").rstrip("\n") + "\n" + "\n".join(vwii_rows) + "\n"


def apply_sticky_cdn(url: str) -> str:
    with cdn_lock:
        current_host = _EFFECTIVE_CDN_HOSTS[active_cdn_idx]
        current_scheme = _ACTIVE_CDN_SCHEME
    if url.startswith("/"):
        return f"{current_scheme}://{current_host}{url}"
    for host in _EFFECTIVE_CDN_HOSTS:
        if host in url:
            replaced = url.replace(host, current_host)
            if current_scheme == "https" and replaced.startswith("http://"):
                replaced = "https://" + replaced[7:]
            return replaced
    return url


def _switch_cdn_host_on_error(sticky_url: str):
    global active_cdn_idx
    with cdn_lock:
        current = _EFFECTIVE_CDN_HOSTS[active_cdn_idx]
        if current in sticky_url:
            active_cdn_idx = (active_cdn_idx + 1) % len(_EFFECTIVE_CDN_HOSTS)


def is_vwii_wup_title(tid: str) -> bool:
    clean = normalize_tid(tid)
    if not is_valid_tid(clean):
        return False
    return int(clean[:8], 16) in VWII_WUP_TID_HIGHS


def wup_vwii_tid_to_slccmpt(tid_high: int, tid_low: int) -> Tuple[int, int]:
    if tid_high == 0x00000007:
        return (0x00000001, tid_low)
    return (tid_high & ~0x00060000, tid_low)


def _get_allowed_tid_ints(clean_tid: str) -> Set[int]:
    if not is_valid_tid(clean_tid):
        raise ValueError(f"Malformed Title ID: {clean_tid}")
    allowed = {int(clean_tid, 16)}
    high, low = clean_tid[:8], clean_tid[8:]
    if high == "00000007":
        allowed.add(int("00000001" + low, 16))
    elif high == "00070002":
        allowed.add(int("00010002" + low, 16))
    elif high == "00070008":
        allowed.add(int("00010008" + low, 16))
    return allowed


def _validate_manifest_pair_for_tid(clean_tid: str, raw_tmd: bytes, raw_tik: bytes) -> bool:
    if not raw_tmd or not raw_tik or len(raw_tmd) < 0x208 or len(raw_tik) < 0x2A4:
        return False
    try:
        allowed_tids = _get_allowed_tid_ints(clean_tid)
    except ValueError:
        return False
    tmd_tid_int = STRUCT_Q.unpack_from(raw_tmd, 0x18C)[0]
    tik_tid_int = STRUCT_Q.unpack_from(raw_tik, 0x1DC)[0]
    if tik_tid_int not in allowed_tids:
        return False
    return tmd_tid_int in allowed_tids


def _verify_tmd_v1_cmd_groups(data: bytes, content_count: int) -> None:
    expected_root_sha256 = data[0x1E4:0x204]
    actual_root_sha256 = hashlib.sha256(data[0x204:0xB04]).digest()
    if actual_root_sha256 != expected_root_sha256:
        raise ValueError("TMD v1 root SHA-256 mismatch over 64 CMD groups (0x1E4 vs 0x204..0xB04)")

    covered_cmds = 0
    for grp_idx in range(64):
        grp_off = 0x204 + (grp_idx * 0x24)
        cmd_offset, cmd_num = STRUCT_HH.unpack_from(data, grp_off)
        grp_sha256 = data[grp_off + 4 : grp_off + 36]
        if cmd_num == 0:
            continue
        if cmd_offset + cmd_num > content_count:
            raise ValueError(
                f"TMD v1 CMD group {grp_idx} out of bounds: offset={cmd_offset}, count={cmd_num}, total={content_count}"
            )
        slice_start = 0xB04 + (cmd_offset * 0x30)
        slice_end = 0xB04 + ((cmd_offset + cmd_num) * 0x30)
        if hashlib.sha256(data[slice_start:slice_end]).digest() != grp_sha256:
            raise ValueError(f"TMD v1 CMD group {grp_idx} SHA-256 verification failed")
        covered_cmds += cmd_num

    if covered_cmds != content_count:
        raise ValueError(f"TMD v1 CMD groups cover {covered_cmds} entries, expected {content_count}")


def parse_tmd(data: bytes) -> TMD:
    data_len = len(data)
    if data_len < 0x208:
        raise ValueError(f"Invalid TMD size ({data_len} bytes)")

    sig_type = STRUCT_I.unpack_from(data, 0x000)[0]
    if sig_type not in (0x00010000, 0x00010001, 0x00010003, 0x00010004):
        raise ValueError(f"Unsupported TMD signature type: 0x{sig_type:08X}")

    issuer_raw = data[0x140:0x180].split(b"\x00", 1)[0]
    if not issuer_raw or not issuer_raw.startswith(b"Root"):
        raise ValueError(f"Invalid TMD issuer field: {issuer_raw!r}")

    version = data[0x180]
    if version not in (0, 1):
        raise ValueError(f"Unsupported TMD version: {version}")

    system_version = STRUCT_Q.unpack_from(data, 0x184)[0]
    title_id_bin = data[0x18C:0x194]
    title_id = STRUCT_Q.unpack_from(data, 0x18C)[0]
    title_type = STRUCT_I.unpack_from(data, 0x194)[0]
    group_id = STRUCT_H.unpack_from(data, 0x198)[0]
    access_rights = STRUCT_I.unpack_from(data, 0x1D8)[0]
    title_version, content_count, boot_index = STRUCT_HHH.unpack_from(data, 0x1DC)

    if content_count <= 0 or content_count > 4096:
        raise ValueError(f"Invalid TMD content_count: {content_count}")
    if boot_index >= content_count:
        raise ValueError(f"Invalid TMD boot_index {boot_index} >= content_count {content_count}")

    content_offset = 0xB04 if version == 1 else 0x1E4
    entry_size = 0x30 if version == 1 else 0x24
    min_required = content_offset + (content_count * entry_size)
    if data_len < min_required:
        raise ValueError(f"Truncated TMD: got {data_len} bytes, need at least {min_required} bytes")

    if version == 1:
        _verify_tmd_v1_cmd_groups(data, content_count)

    tmd = TMD(
        title_id=title_id,
        title_id_bin=title_id_bin,
        version=version,
        system_version=system_version,
        title_type=title_type,
        group_id=group_id,
        access_rights=access_rights,
        title_version=title_version,
        content_count=content_count,
        boot_index=boot_index,
    )

    seen_cids: Set[int] = set()
    seen_indices: Set[int] = set()
    unpack_content = STRUCT_CONTENT.unpack_from
    for i in range(content_count):
        off = content_offset + (i * entry_size)
        c_id, c_index, c_type, c_size = unpack_content(data, off)
        c_hash = data[off + 16 : off + 36]
        if version == 1 and data[off + 36 : off + 48] != b"\x00" * 12:
            raise ValueError(f"Non-zero SHA-1 padding in TMD v1 CMD record {i} ({c_id:08X})")
        if c_id in seen_cids or c_index in seen_indices:
            raise ValueError(f"Duplicate content entry in TMD (id={c_id:08X}, index={c_index})")
        if c_size == 0 or len(c_hash) != 20:
            raise ValueError(f"Corrupt content record {i} in TMD")
        seen_cids.add(c_id)
        seen_indices.add(c_index)
        tmd.contents.append(Content(c_id, c_index, c_type, c_size, c_hash))

    return tmd


def aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes, aes_algo=None) -> bytes:
    algo = aes_algo if aes_algo is not None else algorithms.AES(key)
    decryptor = Cipher(algo, modes.CBC(iv), backend=_BACKEND).decryptor()
    return decryptor.update(data) + decryptor.finalize()


def get_common_key(otp_input: str = "") -> bytes:
    candidates = [
        otp_input,
        os.environ.get("WIIU_COMMON_KEY", ""),
        join(BASE_DIR, "otp.bin"),
    ]
    for cand in candidates:
        c = str(cand).strip().strip('"').strip("'")
        if not c:
            continue
        if len(c) == 32:
            try:
                key = binascii.unhexlify(c)
                if hashlib.sha1(key).hexdigest() == WIIU_COMMON_KEY_SHA1:
                    return key
            except (binascii.Error, ValueError):
                pass
        if os.path.isfile(c):
            file_size = os.path.getsize(c)
            with open(c, "rb") as f:
                if file_size == 16:
                    key = f.read(16)
                elif file_size in (32, 33, 34):
                    txt = f.read().decode("ascii", errors="ignore").strip()
                    key = binascii.unhexlify(txt) if len(txt) == 32 else b""
                elif file_size >= OTP_COMMON_KEY_OFFSET + 0x10:
                    f.seek(OTP_COMMON_KEY_OFFSET)
                    key = f.read(0x10)
                else:
                    key = b""
            if len(key) == 16 and hashlib.sha1(key).hexdigest() == WIIU_COMMON_KEY_SHA1:
                return key
    raise ValueError(
        "Wii U Common Key not found: set the WIIU_COMMON_KEY secret / environment variable, "
        "or pass --otp with an otp.bin or a 32-character hexadecimal key."
    )


def _sig_type_params(sig_type: int) -> Optional[Tuple[int, int, Optional[hashes.HashAlgorithm]]]:
    if sig_type == 0x00010000:
        return (0x200, 0x240, hashes.SHA1())
    if sig_type == 0x00010001:
        return (0x100, 0x140, hashes.SHA1())
    if sig_type == 0x00010002:
        return (0x3C, 0x80, hashes.SHA1())
    if sig_type == 0x00010003:
        return (0x200, 0x240, hashes.SHA256())
    if sig_type == 0x00010004:
        return (0x100, 0x140, hashes.SHA256())
    if sig_type == 0x00010005:
        return (0x3C, 0x80, hashes.SHA256())
    return None


def _parse_cert_records(cert_bytes: bytes) -> List[_ParsedCert]:
    records: List[_ParsedCert] = []
    pos = 0
    while pos + 4 <= len(cert_bytes):
        sig_type = struct.unpack_from(">I", cert_bytes, pos)[0]
        params = _sig_type_params(sig_type)
        if params is None:
            break
        sig_len, sig_pad, _ = params

        body_off = pos + sig_pad
        if body_off + 0x88 > len(cert_bytes):
            break

        key_type = struct.unpack_from(">I", cert_bytes, body_off + 0x40)[0]
        if key_type == 0:
            key_len = 0x238
            mod_len = 0x200
        elif key_type == 1:
            key_len = 0x138
            mod_len = 0x100
        elif key_type == 2:
            key_len = 0x78
            mod_len = 0
        else:
            break

        end = body_off + 0x88 + key_len
        if end > len(cert_bytes):
            break

        issuer = cert_bytes[body_off : body_off + 0x40].split(b"\x00", 1)[0].decode("ascii", errors="ignore")
        name = cert_bytes[body_off + 0x44 : body_off + 0x84].split(b"\x00", 1)[0].decode("ascii", errors="ignore")
        pub_key = None
        if mod_len > 0:
            mod_int = int.from_bytes(cert_bytes[body_off + 0x88 : body_off + 0x88 + mod_len], "big")
            exp_int = int.from_bytes(cert_bytes[body_off + 0x88 + mod_len : body_off + 0x8C + mod_len], "big")
            if mod_int > 0 and exp_int > 0:
                pub_key = rsa.RSAPublicNumbers(exp_int, mod_int).public_key(_BACKEND)

        records.append(
            _ParsedCert(
                raw=cert_bytes[pos:end],
                sig_type=sig_type,
                signature=cert_bytes[pos + 4 : pos + 4 + sig_len],
                signed_body=cert_bytes[body_off:end],
                issuer=issuer,
                key_type=key_type,
                name=name,
                public_key=pub_key,
            )
        )
        pos = end
    return records


def _parse_cert_chain(cert_bytes: bytes) -> List[bytes]:
    return [rec.raw for rec in _parse_cert_records(cert_bytes)]


def _validate_cert_chain_bytes(cert_bytes: bytes, min_certs: int = 3) -> bool:
    if not cert_bytes:
        return False
    certs = _parse_cert_records(cert_bytes)
    if len(certs) < min_certs:
        return False
    return sum(len(c.raw) for c in certs) == len(cert_bytes)


def _verify_rsa_blob_signature(
    pub_key: rsa.RSAPublicKey,
    sig_type: int,
    signature: bytes,
    signed_data: bytes,
    label: str,
) -> None:
    params = _sig_type_params(sig_type)
    if params is None or params[2] is None:
        raise ValueError(f"Unsupported RSA signature type 0x{sig_type:08X} for {label}")
    hash_alg = params[2]
    try:
        pub_key.verify(signature, signed_data, padding.PKCS1v15(), hash_alg)
    except InvalidSignature as exc:
        raise ValueError(f"Cryptographic RSA signature verification failed for {label}") from exc


def _get_ticket_signed_end(raw_tik: bytes, label: str) -> int:
    if len(raw_tik) < 0x2A4:
        raise ValueError(f"Truncated Ticket ({len(raw_tik)} bytes) for {label}")

    tik_version = raw_tik[0x1BC]
    if tik_version == 0:
        return 0x2A4
    if tik_version != 1:
        raise ValueError(f"Unsupported Ticket version {tik_version} for {label}")

    if len(raw_tik) < 0x2B8:
        raise ValueError(f"Truncated v1 Ticket header ({len(raw_tik)} bytes) for {label}")

    v1_hdr_ver, v1_hdr_len = STRUCT_HH.unpack_from(raw_tik, 0x2A4)
    if v1_hdr_ver != 1 or v1_hdr_len < 0x14:
        raise ValueError(f"Invalid v1 Ticket header (ver={v1_hdr_ver}, len=0x{v1_hdr_len:X}) for {label}")

    v1_total_size = STRUCT_I.unpack_from(raw_tik, 0x2A8)[0]
    sect_hdr_off = STRUCT_I.unpack_from(raw_tik, 0x2AC)[0]
    num_sect_hdrs, sect_entry_sz = STRUCT_HH.unpack_from(raw_tik, 0x2B0)

    if v1_total_size >= v1_hdr_len:
        tik_signed_end = 0x2A4 + v1_total_size
    else:
        tik_signed_end = 0x2A4 + sect_hdr_off + (num_sect_hdrs * sect_entry_sz)

    if tik_signed_end < 0x2B8 or tik_signed_end > len(raw_tik):
        raise ValueError(
            f"v1 Ticket signed boundary 0x{tik_signed_end:X} out of bounds (total=0x{len(raw_tik):X}) for {label}"
        )
    return tik_signed_end


def _verify_signed_manifests_with_certs(
    cert_bytes: bytes,
    raw_tmd: bytes,
    tmd: TMD,
    raw_tik: bytes,
    clean_tid: str,
) -> None:
    records = _parse_cert_records(cert_bytes)
    if len(records) < 3 or sum(len(r.raw) for r in records) != len(cert_bytes):
        raise ValueError(f"Malformed certificate chain for {clean_tid}")

    certs_by_name: Dict[str, _ParsedCert] = {rec.name: rec for rec in records if rec.name}

    for rec in records:
        if rec.issuer == "Root":
            continue
        parent_name = rec.issuer.rsplit("-", 1)[-1] if "-" in rec.issuer else rec.issuer
        parent_cert = certs_by_name.get(parent_name)
        if parent_cert is None or parent_cert.public_key is None:
            raise ValueError(f"Missing parent CA certificate '{parent_name}' for '{rec.name}' in {clean_tid}")
        _verify_rsa_blob_signature(
            parent_cert.public_key,
            rec.sig_type,
            rec.signature,
            rec.signed_body,
            f"certificate {rec.name}",
        )

    tmd_issuer = raw_tmd[0x140:0x180].split(b"\x00", 1)[0].decode("ascii", errors="ignore")
    tmd_signer_name = tmd_issuer.rsplit("-", 1)[-1] if "-" in tmd_issuer else tmd_issuer
    tmd_signer = certs_by_name.get(tmd_signer_name)
    if tmd_signer is None or tmd_signer.public_key is None:
        raise ValueError(f"Missing TMD signing certificate '{tmd_signer_name}' for {clean_tid}")

    tmd_sig_type = STRUCT_I.unpack_from(raw_tmd, 0x000)[0]
    tmd_params = _sig_type_params(tmd_sig_type)
    if tmd_params is None:
        raise ValueError(f"Invalid TMD signature type 0x{tmd_sig_type:08X} for {clean_tid}")
    tmd_sig_len, tmd_sig_pad, _ = tmd_params
    tmd_sig = raw_tmd[4 : 4 + tmd_sig_len]
    tmd_signed_end = 0x204 if tmd.version == 1 else (0x1E4 + tmd.content_count * 0x24)
    _verify_rsa_blob_signature(
        tmd_signer.public_key,
        tmd_sig_type,
        tmd_sig,
        raw_tmd[tmd_sig_pad:tmd_signed_end],
        f"TMD {clean_tid}",
    )

    tik_issuer = raw_tik[0x140:0x180].split(b"\x00", 1)[0].decode("ascii", errors="ignore")
    tik_signer_name = tik_issuer.rsplit("-", 1)[-1] if "-" in tik_issuer else tik_issuer
    tik_signer = certs_by_name.get(tik_signer_name)
    if tik_signer is None or tik_signer.public_key is None:
        raise ValueError(f"Missing Ticket signing certificate '{tik_signer_name}' for {clean_tid}")

    tik_sig_type = STRUCT_I.unpack_from(raw_tik, 0x000)[0]
    tik_params = _sig_type_params(tik_sig_type)
    if tik_params is None:
        raise ValueError(f"Invalid Ticket signature type 0x{tik_sig_type:08X} for {clean_tid}")
    tik_sig_len, tik_sig_pad, _ = tik_params
    tik_sig = raw_tik[4 : 4 + tik_sig_len]
    tik_signed_end = _get_ticket_signed_end(raw_tik, clean_tid)

    _verify_rsa_blob_signature(
        tik_signer.public_key,
        tik_sig_type,
        tik_sig,
        raw_tik[tik_sig_pad:tik_signed_end],
        f"Ticket {clean_tid}",
    )


def _extract_xs_cert_from_cetk(cetk_bytes: bytes) -> Optional[bytes]:
    if not cetk_bytes or len(cetk_bytes) < 0x2A4 + 0x300:
        return None

    candidate_offsets: List[int] = [0x350, 0x2A4]
    try:
        dyn_end = _get_ticket_signed_end(cetk_bytes, "cetk")
        if dyn_end not in candidate_offsets:
            candidate_offsets.insert(0, dyn_end)
    except ValueError:
        pass

    for offset in candidate_offsets:
        if len(cetk_bytes) >= offset + 0x300:
            candidate = cetk_bytes[offset : offset + 0x300]
            if _validate_cert_chain_bytes(candidate, min_certs=1):
                return candidate

    scan_limit = len(cetk_bytes) - 0x300
    for offset in range(0x2A4, scan_limit + 1, 4):
        sig_val = struct.unpack_from(">I", cetk_bytes, offset)[0]
        if sig_val in (0x00010000, 0x00010001, 0x00010003, 0x00010004):
            parsed = _parse_cert_chain(cetk_bytes[offset:])
            if parsed and len(parsed[0]) == 0x300:
                return parsed[0]

    return None


def get_default_cert(session: requests.Session, candidate_tids: Optional[List[str]] = None) -> bytes:
    global DEFAULT_CERT_DATA, active_cdn_idx, _ACTIVE_CDN_SCHEME
    with cert_lock:
        if DEFAULT_CERT_DATA:
            return DEFAULT_CERT_DATA

    raw_tid_list = [normalize_tid(OSV10_TID)] + list(_DEFAULT_CERT_FALLBACK_TIDS)
    if candidate_tids:
        for tid in candidate_tids:
            clean = normalize_tid(tid)
            if is_valid_tid(clean):
                raw_tid_list.append(clean)
    tids_to_try = list(dict.fromkeys(t for t in raw_tid_list if is_valid_tid(t)))

    if isinstance(FAST_REQ_TIMEOUT, tuple) and len(FAST_REQ_TIMEOUT) == 2:
        req_timeout = (max(10.0, float(FAST_REQ_TIMEOUT[0])), max(20.0, float(FAST_REQ_TIMEOUT[1])))
    else:
        base_to = float(FAST_REQ_TIMEOUT) if FAST_REQ_TIMEOUT else 10.0
        req_timeout = (max(10.0, base_to), max(20.0, base_to * 2.0))

    last_err = "no CDN host responded"
    for scheme in ("http", "https"):
        verify_ssl = scheme == "http"
        for host_idx, host in enumerate(_EFFECTIVE_CDN_HOSTS):
            for tid in tids_to_try:
                if STOP_EVENT.is_set():
                    raise RuntimeError("STOPPED")
                url = f"{scheme}://{host}{CDN_PATH}/{tid}/cetk"
                try:
                    r = session.get(url, timeout=req_timeout, verify=verify_ssl)
                    r.raise_for_status()
                    xs_cert = _extract_xs_cert_from_cetk(r.content)
                    if xs_cert is not None:
                        with cdn_lock:
                            active_cdn_idx = host_idx
                            _ACTIVE_CDN_SCHEME = scheme
                        with cert_lock:
                            DEFAULT_CERT_DATA = xs_cert
                        log_print(f"Default NUS XS certificate chain loaded from {tid}/cetk ({scheme}://{host}).")
                        return DEFAULT_CERT_DATA
                    last_err = f"{url} returned cetk without XS cert (size={len(r.content)} bytes)"
                except Exception as e:
                    last_err = f"{url} -> {e}"
                    break

    raise RuntimeError(f"Failed to download and verify default certificate chain from NUS ({last_err}).")


def _write_bytes_fast(dst_path: str, data):
    mv = data if isinstance(data, memoryview) else memoryview(data)
    total = len(mv)
    try:
        with open(dst_path, "wb", buffering=0) as f:
            written = 0
            while written < total:
                n = f.write(mv[written:])
                if not n:
                    break
                written += n
    except PermissionError:
        if os.path.exists(dst_path):
            try:
                os.chmod(dst_path, stat.S_IWRITE | stat.S_IREAD)
                os.remove(dst_path)
            except Exception:
                pass
        with open(dst_path, "wb", buffering=0) as f:
            written = 0
            while written < total:
                n = f.write(mv[written:])
                if not n:
                    break
                written += n
    if os.path.getsize(dst_path) != total:
        raise IOError(f"Short write on {dst_path}: expected {total} bytes, got {os.path.getsize(dst_path)}")


def force_remove(path: str):
    try:
        os.remove(path)
    except FileNotFoundError:
        return
    except PermissionError:
        try:
            os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
            os.remove(path)
        except Exception:
            pass
    except OSError:
        pass


def force_replace(src: str, dst: str):
    try:
        os.replace(src, dst)
        return
    except PermissionError:
        if os.path.exists(dst):
            try:
                os.chmod(dst, stat.S_IWRITE | stat.S_IREAD)
                os.remove(dst)
            except Exception:
                pass
        os.replace(src, dst)


def _is_valid_app_disk_size(actual_len: int, tmd_size: int) -> bool:
    if actual_len < tmd_size or tmd_size <= 0:
        return False
    return actual_len in (tmd_size, (tmd_size + 15) & ~15, (tmd_size + 63) & ~63) or (actual_len - tmd_size) < 64


def _is_h3_hashed_content(tmd: TMD, c: Content) -> bool:
    return (tmd.version == 1) and bool(c.type & 0x02)


def _get_max_content_data_size(tmd: TMD, c: Content) -> int:
    if not _is_h3_hashed_content(tmd, c):
        return c.size
    full_blocks, rem = divmod(c.size, 0x10000)
    usable = full_blocks * 0xFC00
    if rem > 0x400:
        usable += rem - 0x400
    return usable


def _download_small_in_memory(
    session: requests.Session,
    url: str,
    dst_path: str,
    tmd_size: Optional[int] = None,
    expected_sha1: Optional[bytes] = None,
    return_bytes: bool = False,
):
    last_error_msg = ""
    for attempt in range(MAX_RETRIES):
        if STOP_EVENT.is_set():
            raise RuntimeError("STOPPED")
        sticky_url = apply_sticky_cdn(url)
        try:
            r = session.get(sticky_url, timeout=FAST_REQ_TIMEOUT, verify=sticky_url.startswith("http://"))
            r.raise_for_status()
            data = r.content
            actual_len = len(data)
            content_length = int(r.headers.get("Content-Length", actual_len))

            if actual_len == 0:
                raise RuntimeError(f"Empty response received from {sticky_url}")
            if content_length > 0 and actual_len != content_length:
                raise RuntimeError(f"Truncated download ({actual_len}/{content_length} bytes)")
            if tmd_size is not None and not _is_valid_app_disk_size(actual_len, tmd_size):
                raise RuntimeError(f"Size mismatch for {os.path.basename(dst_path)}: got {actual_len}, expected {tmd_size}")
            if expected_sha1 is not None and hashlib.sha1(data).digest() != expected_sha1:
                raise RuntimeError(f"SHA-1 mismatch for {os.path.basename(dst_path)}")

            _write_bytes_fast(dst_path, data)
            return (True, data) if return_bytes else True
        except Exception as e:
            last_error_msg = str(e)
            if isinstance(e, requests.exceptions.HTTPError) and e.response is not None and e.response.status_code == 404:
                raise RuntimeError(f"404: {sticky_url}")
            _switch_cdn_host_on_error(sticky_url)
            if attempt < MAX_RETRIES - 1:
                time.sleep(0.1)

    raise RuntimeError(f"Download failed after {MAX_RETRIES} retries: {last_error_msg}")


def download_file(
    session: requests.Session,
    url: str,
    dst_path: str,
    tmd_size: Optional[int] = None,
    expected_sha1: Optional[bytes] = None,
) -> bool:
    if tmd_size is None or tmd_size <= IN_MEMORY_MAX_SIZE:
        return _download_small_in_memory(
            session, url, dst_path, tmd_size=tmd_size, expected_sha1=expected_sha1, return_bytes=False
        )

    tmp_path = dst_path + ".tmp"
    last_error_msg = ""
    max_aligned_expected = (tmd_size + 63) & ~63

    for attempt in range(MAX_RETRIES):
        if STOP_EVENT.is_set():
            raise RuntimeError("STOPPED")
        sticky_url = apply_sticky_cdn(url)
        try:
            try:
                total_downloaded = os.path.getsize(tmp_path)
            except OSError:
                total_downloaded = 0

            if total_downloaded > max_aligned_expected:
                force_remove(tmp_path)
                total_downloaded = 0

            headers = {"User-Agent": "WiiUDownloader/1.0", "Accept-Encoding": "identity"}
            if total_downloaded > 0:
                headers["Range"] = f"bytes={total_downloaded}-"

            verify_ssl = sticky_url.startswith("http://")
            r = session.get(sticky_url, headers=headers, stream=True, timeout=FAST_REQ_TIMEOUT, verify=verify_ssl)
            if r.status_code == 416:
                r.close()
                force_remove(tmp_path)
                total_downloaded = 0
                headers.pop("Range", None)
                r = session.get(sticky_url, headers=headers, stream=True, timeout=FAST_REQ_TIMEOUT, verify=verify_ssl)

            try:
                r.raise_for_status()
                content_length = int(r.headers.get("Content-Length", 0))
                mode = "ab" if r.status_code == 206 else "wb"
                if mode == "wb":
                    total_downloaded = 0
                target_size = total_downloaded + content_length if mode == "ab" else content_length

                if target_size > 0 and total_downloaded == target_size:
                    if not _is_valid_app_disk_size(total_downloaded, tmd_size):
                        force_remove(tmp_path)
                        raise RuntimeError(f"Invalid cached stream size ({total_downloaded}) for {os.path.basename(dst_path)}")
                    force_replace(tmp_path, dst_path)
                    return True

                with open(tmp_path, mode, buffering=CHUNK_SIZE) as f:
                    for chunk in r.iter_content(chunk_size=128 * 1024):
                        if chunk:
                            f.write(chunk)
                            total_downloaded += len(chunk)
            finally:
                r.close()

            if target_size > 0 and total_downloaded != target_size:
                if total_downloaded > target_size:
                    force_remove(tmp_path)
                raise RuntimeError(f"Incomplete stream ({total_downloaded}/{target_size} bytes)")
            if not _is_valid_app_disk_size(total_downloaded, tmd_size):
                force_remove(tmp_path)
                raise RuntimeError(f"Streamed file size mismatch ({total_downloaded} vs {tmd_size}) for {os.path.basename(dst_path)}")

            force_replace(tmp_path, dst_path)
            return True
        except Exception as e:
            last_error_msg = str(e)
            if isinstance(e, requests.exceptions.HTTPError) and e.response is not None and e.response.status_code == 404:
                raise RuntimeError(f"404: {sticky_url}")
            _switch_cdn_host_on_error(sticky_url)
            if attempt < MAX_RETRIES - 1:
                time.sleep(0.1)

    raise RuntimeError(f"Stream download failed: {last_error_msg}")


def _verify_linear_content_sha1(app_path: str, c: Content, aes_algo) -> None:
    iv = STRUCT_H.pack(c.index) + b"\x00" * 14
    decryptor = Cipher(aes_algo, modes.CBC(iv), backend=_BACKEND).decryptor()
    sha1 = hashlib.sha1()
    remaining = c.size
    buf = bytearray(CHUNK_SIZE)
    mv = memoryview(buf)

    with open(app_path, "rb", buffering=CHUNK_SIZE) as f:
        while remaining > 0:
            n_read = f.readinto(mv)
            if not n_read:
                break
            rem = n_read & 0xF
            if rem != 0:
                padded = bytes(mv[:n_read]) + b"\x00" * (16 - rem)
                dec = decryptor.update(padded)
            else:
                dec = decryptor.update(mv[:n_read])
            take = min(remaining, len(dec))
            sha1.update(dec[:take])
            remaining -= take

    if remaining != 0:
        raise ValueError(f"Truncated linear content {c.id:08X}.app: missing {remaining} bytes")
    if sha1.digest() != c.hash:
        raise ValueError(
            f"SHA-1 verification failed for content {c.id:08X}.app: "
            f"expected {c.hash.hex()}, got {sha1.hexdigest()}"
        )


def _verify_h3_content_tree(app_path: str, h3_path: str, c: Content, aes_algo) -> None:
    with open(h3_path, "rb") as fh3:
        h3_data = fh3.read()
    if len(h3_data) == 0 or (len(h3_data) % 20) != 0:
        raise ValueError(f"Invalid H3 table size ({len(h3_data)} bytes) for {c.id:08X}.h3")
    if hashlib.sha1(h3_data).digest() != c.hash:
        raise ValueError(f"H3 root SHA-1 mismatch for {c.id:08X}.h3")

    TOTAL_BLOCK = 0x10000
    expected_blocks = (c.size + TOTAL_BLOCK - 1) // TOTAL_BLOCK
    app_size = os.path.getsize(app_path)
    if app_size < expected_blocks * TOTAL_BLOCK:
        raise ValueError(
            f"Truncated H3 content {c.id:08X}.app: got {app_size} bytes, need {expected_blocks * TOTAL_BLOCK} bytes"
        )

    h_iv = STRUCT_H.pack(c.index) + b"\x00" * 14
    idx_hi, idx_lo = (c.index >> 8) & 0xFF, c.index & 0xFF
    blk_buf = bytearray(TOTAL_BLOCK)
    blk_mv = memoryview(blk_buf)
    c_iv = bytearray(16)

    with open(app_path, "rb", buffering=CHUNK_SIZE) as f:
        for blk_idx in range(expected_blocks):
            n_read = f.readinto(blk_mv)
            if n_read != TOTAL_BLOCK:
                raise ValueError(f"Short block {blk_idx} in {c.id:08X}.app ({n_read} bytes)")

            hdr_dec = Cipher(aes_algo, modes.CBC(h_iv), backend=_BACKEND).decryptor()
            hashes = hdr_dec.update(blk_mv[:0x400]) + hdr_dec.finalize()

            block_num = blk_idx & 0xF
            h0_off = block_num * 20
            c_iv[:] = hashes[h0_off : h0_off + 16]
            expected_h0 = bytearray(hashes[h0_off : h0_off + 20])
            if block_num == 0:
                c_iv[0] ^= idx_hi
                c_iv[1] ^= idx_lo
                expected_h0[0] ^= idx_hi
                expected_h0[1] ^= idx_lo

            body_dec = Cipher(aes_algo, modes.CBC(bytes(c_iv)), backend=_BACKEND).decryptor()
            dec_payload = body_dec.update(blk_mv[0x400:TOTAL_BLOCK]) + body_dec.finalize()
            if hashlib.sha1(dec_payload).digest() != bytes(expected_h0):
                raise ValueError(f"H0 block {blk_idx} SHA-1 mismatch in {c.id:08X}.app")

            if block_num == 0:
                h1_slot = (blk_idx >> 4) & 0xF
                expected_h1 = hashes[320 + h1_slot * 20 : 320 + (h1_slot + 1) * 20]
                true_h0_table = bytearray(hashes[0:320])
                true_h0_table[0] ^= idx_hi
                true_h0_table[1] ^= idx_lo
                if hashlib.sha1(true_h0_table).digest() != expected_h1:
                    raise ValueError(f"H1 group {blk_idx >> 4} SHA-1 mismatch in {c.id:08X}.app")

            if (blk_idx & 0xFF) == 0:
                h2_slot = (blk_idx >> 8) & 0xF
                expected_h2 = hashes[640 + h2_slot * 20 : 640 + (h2_slot + 1) * 20]
                if hashlib.sha1(hashes[320:640]).digest() != expected_h2:
                    raise ValueError(f"H2 group {blk_idx >> 8} SHA-1 mismatch in {c.id:08X}.app")

            if (blk_idx & 0xFFF) == 0:
                h3_slot = blk_idx >> 12
                if (h3_slot + 1) * 20 > len(h3_data):
                    raise ValueError(f"H3 table too short for group {h3_slot} in {c.id:08X}.h3")
                expected_h3 = h3_data[h3_slot * 20 : (h3_slot + 1) * 20]
                if hashlib.sha1(hashes[640:960]).digest() != expected_h3:
                    raise ValueError(f"H3 group {h3_slot} SHA-1 mismatch in {c.id:08X}.app")


def verify_wup_title_cryptography(
    wup_dir: str,
    common_key: bytes,
    expected_tid: str,
    expected_version: Optional[int] = None,
) -> Tuple[TMD, bytes]:
    clean_tid = normalize_tid(expected_tid)
    tmd_path = os.path.join(wup_dir, "title.tmd")
    tik_path = os.path.join(wup_dir, "title.tik")
    cert_path = os.path.join(wup_dir, "title.cert")

    if not os.path.isfile(tmd_path) or not os.path.isfile(tik_path) or not os.path.isfile(cert_path):
        raise FileNotFoundError(f"Missing TMD, Ticket, or Certificate in {wup_dir}")

    with open(cert_path, "rb") as fc:
        cert_bytes = fc.read()
    if not _validate_cert_chain_bytes(cert_bytes, min_certs=3):
        raise ValueError(f"Invalid or incomplete certificate chain in {cert_path}")

    tmd, title_key, raw_tmd, raw_tik = read_tmd_and_title_key(wup_dir, common_key, clean_tid)
    if expected_version is not None and tmd.title_version != expected_version:
        raise ValueError(
            f"TMD version mismatch for {clean_tid}: expected v{expected_version}, got v{tmd.title_version}"
        )

    _verify_signed_manifests_with_certs(cert_bytes, raw_tmd, tmd, raw_tik, clean_tid)

    aes_algo = algorithms.AES(title_key)
    for c in tmd.contents:
        cid_str = f"{c.id:08X}"
        app_path = os.path.join(wup_dir, f"{cid_str}.app")
        if not os.path.isfile(app_path):
            raise FileNotFoundError(f"Missing content {cid_str}.app for {clean_tid}")
        if not _is_valid_app_disk_size(os.path.getsize(app_path), c.size):
            raise ValueError(f"Invalid size for {cid_str}.app of {clean_tid}")

        if _is_h3_hashed_content(tmd, c):
            h3_path = os.path.join(wup_dir, f"{cid_str}.h3")
            if not os.path.isfile(h3_path):
                raise FileNotFoundError(f"Missing H3 table {cid_str}.h3 for {clean_tid}")
            _verify_h3_content_tree(app_path, h3_path, c, aes_algo)
        else:
            _verify_linear_content_sha1(app_path, c, aes_algo)

    return tmd, title_key


def _verify_all_downloaded_files_present(work_dir: str, parsed_tmd: TMD) -> bool:
    existing_sizes = {}
    try:
        with os.scandir(work_dir) as it:
            for entry in it:
                if entry.is_file(follow_symlinks=False):
                    if entry.name.endswith(".tmp"):
                        return False
                    existing_sizes[entry.name] = entry.stat(follow_symlinks=False).st_size
    except OSError:
        return False

    if (
        existing_sizes.get("title.tmd", 0) < 0x208
        or existing_sizes.get("title.tik", 0) < 0x2A4
        or existing_sizes.get("title.cert", 0) < 0x600
    ):
        return False

    try:
        with open(os.path.join(work_dir, "title.cert"), "rb") as fc:
            if not _validate_cert_chain_bytes(fc.read(), min_certs=3):
                return False
    except OSError:
        return False

    for c in parsed_tmd.contents:
        cid_str = f"{c.id:08X}"
        app_name = f"{cid_str}.app"
        if app_name not in existing_sizes or not _is_valid_app_disk_size(existing_sizes[app_name], c.size):
            return False

        if _is_h3_hashed_content(parsed_tmd, c):
            h3_name = f"{cid_str}.h3"
            if existing_sizes.get(h3_name, 0) == 0:
                return False
            try:
                with open(os.path.join(work_dir, h3_name), "rb") as fh3:
                    h3_mem = fh3.read()
            except OSError:
                return False
            if hashlib.sha1(h3_mem).digest() != c.hash:
                return False

    return True


def download_title_wup(
    session: requests.Session,
    title_id: str,
    target_version: int,
    wup_dir: str,
    common_key: Optional[bytes] = None,
) -> bool:
    os.makedirs(wup_dir, exist_ok=True)
    clean_tid = normalize_tid(title_id)
    title_url_path = f"{CDN_PATH}/{clean_tid}"

    tmd_path = os.path.join(wup_dir, "title.tmd")
    tik_path = os.path.join(wup_dir, "title.tik")
    cert_path = os.path.join(wup_dir, "title.cert")

    if os.path.isfile(tmd_path) and os.path.isfile(tik_path) and os.path.isfile(cert_path):
        try:
            with open(tmd_path, "rb") as ft, open(tik_path, "rb") as fk:
                existing_tmd_raw = ft.read()
                existing_tik_raw = fk.read()
            if _validate_manifest_pair_for_tid(clean_tid, existing_tmd_raw, existing_tik_raw):
                parsed_existing = parse_tmd(existing_tmd_raw)
                if parsed_existing.title_version == target_version and _verify_all_downloaded_files_present(
                    wup_dir, parsed_existing
                ):
                    if common_key is not None:
                        verify_wup_title_cryptography(wup_dir, common_key, clean_tid, expected_version=target_version)
                    return True
        except Exception:
            pass

    tmd_url = f"{title_url_path}/tmd.{target_version}"
    for manifest_attempt in range(MAX_RETRIES):
        ok_t, raw_tmd = _download_small_in_memory(session, tmd_url, tmd_path, return_bytes=True)
        ok_k, raw_tik = _download_small_in_memory(session, f"{title_url_path}/cetk", tik_path, return_bytes=True)
        if not ok_t or not ok_k:
            return False
        if _validate_manifest_pair_for_tid(clean_tid, raw_tmd, raw_tik):
            break
        _switch_cdn_host_on_error(apply_sticky_cdn(tmd_url))
        time.sleep(0.5 * (manifest_attempt + 1))
    else:
        raise RuntimeError(f"Manifest Title ID or size mismatch for {title_id}")

    tmd = parse_tmd(raw_tmd)
    if tmd.title_version != target_version:
        raise RuntimeError(f"Downloaded TMD version mismatch for {title_id}: expected {target_version}, got {tmd.title_version}")

    existing_sizes = {}
    try:
        with os.scandir(wup_dir) as it:
            for entry in it:
                if entry.is_file(follow_symlinks=False):
                    if entry.name.endswith(".tmp"):
                        force_remove(entry.path)
                    else:
                        existing_sizes[entry.name] = entry.stat(follow_symlinks=False).st_size
    except OSError:
        pass

    pending_downloads = []
    for c in tmd.contents:
        cid_str = f"{c.id:08X}"
        app_name = f"{cid_str}.app"
        app_p = os.path.join(wup_dir, app_name)
        actual_size = existing_sizes.get(app_name, -1)

        if actual_size < 0 or not _is_valid_app_disk_size(actual_size, c.size):
            if actual_size >= 0:
                force_remove(app_p)
            pending_downloads.append((f"{title_url_path}/{cid_str}", app_p, c.size, None))

        if _is_h3_hashed_content(tmd, c):
            h3_name = f"{cid_str}.h3"
            h3_p = os.path.join(wup_dir, h3_name)
            h3_valid = False
            if existing_sizes.get(h3_name, 0) > 0:
                try:
                    with open(h3_p, "rb") as fh3:
                        if hashlib.sha1(fh3.read()).digest() == c.hash:
                            h3_valid = True
                except OSError:
                    h3_valid = False
            if not h3_valid:
                force_remove(h3_p)
                pending_downloads.append((f"{title_url_path}/{cid_str}.h3", h3_p, None, c.hash))

    pending_downloads.sort(key=lambda item: item[2] or 0, reverse=True)

    for dl_url, dst_p, exp_sz, exp_sha1 in pending_downloads:
        if not download_file(session, dl_url, dst_p, tmd_size=exp_sz, expected_sha1=exp_sha1):
            return False

    cert_offset = (0xB04 if tmd.version == 1 else 0x1E4) + ((0x30 if tmd.version == 1 else 0x24) * tmd.content_count)
    cert_1_2 = raw_tmd[cert_offset : cert_offset + 0x700]
    tik_xs_cert = _extract_xs_cert_from_cetk(raw_tik)
    xs_cert = tik_xs_cert if tik_xs_cert is not None else get_default_cert(session)
    full_cert = cert_1_2 + xs_cert
    if not _validate_cert_chain_bytes(full_cert, min_certs=3):
        raise RuntimeError(f"Constructed title.cert failed 3-certificate validation for {title_id}")
    _write_bytes_fast(cert_path, full_cert)

    if not _verify_all_downloaded_files_present(wup_dir, tmd):
        raise RuntimeError(f"Post-download file verification failed for {title_id}")

    if common_key is not None:
        verify_wup_title_cryptography(wup_dir, common_key, clean_tid, expected_version=target_version)

    return True


def _resolve_verified_title_key(wup_dir: str, tmd: TMD, raw_tik: bytes, clean_tid: str, common_key: bytes) -> bytes:
    enc_tkey = raw_tik[0x1BF:0x1CF]
    wiiu_tid_bin = STRUCT_Q.pack(int(clean_tid, 16))
    tik_tid_bin = raw_tik[0x1DC:0x1E4]
    tmd_tid_bin = tmd.title_id_bin

    candidate_ivs = []
    for iv_prefix in (wiiu_tid_bin, tik_tid_bin, tmd_tid_bin):
        iv_full = iv_prefix + b"\x00" * 8
        if iv_full not in candidate_ivs:
            candidate_ivs.append(iv_full)

    extra_keys = load_extra_common_keys()
    if is_vwii_wup_title(clean_tid) and load_key_from_env("VWII_COMMON_KEY") is None:
        raise RuntimeError("The VWII_COMMON_KEY secret / environment variable is required to process vWii titles.")
    candidate_keys = [common_key] + extra_keys
    candidate_tkeys = []
    for k in candidate_keys:
        for iv in candidate_ivs:
            tk = aes_cbc_decrypt(k, iv, enc_tkey)
            if tk not in candidate_tkeys:
                candidate_tkeys.append(tk)

    linear_contents = [c for c in tmd.contents if not _is_h3_hashed_content(tmd, c)]
    if linear_contents:
        test_c = min(linear_contents, key=lambda item: item.size)
        app_p = os.path.join(wup_dir, f"{test_c.id:08X}.app")
        if os.path.isfile(app_p):
            with open(app_p, "rb") as f_test:
                raw_app = f_test.read()
            rem = len(raw_app) & 0xF
            raw_app_padded = raw_app + b"\x00" * (16 - rem) if rem != 0 else raw_app
            aligned_16 = (test_c.size + 15) & ~15
            content_ivs = [STRUCT_H.pack(test_c.index) + b"\x00" * 14]
            if test_c.index != 0:
                content_ivs.append(b"\x00" * 16)
            for tk in candidate_tkeys:
                for c_iv in content_ivs:
                    dec = aes_cbc_decrypt(tk, c_iv, raw_app_padded)
                    if (
                        hashlib.sha1(dec[: test_c.size]).digest() == test_c.hash
                        or hashlib.sha1(dec[:aligned_16]).digest() == test_c.hash
                        or hashlib.sha1(dec).digest() == test_c.hash
                    ):
                        return tk

    h3_contents = [c for c in tmd.contents if _is_h3_hashed_content(tmd, c)]
    if h3_contents:
        test_c = h3_contents[0]
        app_p = os.path.join(wup_dir, f"{test_c.id:08X}.app")
        if os.path.isfile(app_p):
            with open(app_p, "rb") as f_test:
                first_blk = f_test.read(0x10000)
            if len(first_blk) > 0x400:
                h_iv = STRUCT_H.pack(test_c.index) + b"\x00" * 14
                idx_hi, idx_lo = (test_c.index >> 8) & 0xFF, test_c.index & 0xFF
                payload_len = len(first_blk) - 0x400
                rem = payload_len & 0xF
                enc_payload = first_blk[0x400:] + b"\x00" * (16 - rem) if rem != 0 else first_blk[0x400:]
                for tk in candidate_tkeys:
                    aes_algo = algorithms.AES(tk)
                    hdr_dec = Cipher(aes_algo, modes.CBC(h_iv), backend=_BACKEND).decryptor()
                    hashes = hdr_dec.update(first_blk[:0x400]) + hdr_dec.finalize()
                    expected_true_hash = bytearray(hashes[:20])
                    c_iv = bytearray(hashes[:16])
                    c_iv[0] ^= idx_hi
                    c_iv[1] ^= idx_lo
                    expected_true_hash[0] ^= idx_hi
                    expected_true_hash[1] ^= idx_lo
                    body_dec = Cipher(aes_algo, modes.CBC(bytes(c_iv)), backend=_BACKEND).decryptor()
                    dec_body = (body_dec.update(enc_payload) + body_dec.finalize())[:payload_len]
                    if hashlib.sha1(dec_body).digest() == bytes(expected_true_hash):
                        return tk

    raise ValueError(f"No candidate Title Key passed SHA-1 decryption verification for {clean_tid}")


def read_tmd_and_title_key(wup_dir: str, common_key: bytes, expected_tid: str) -> Tuple[TMD, bytes, bytes, bytes]:
    tmd_path = os.path.join(wup_dir, "title.tmd")
    tik_path = os.path.join(wup_dir, "title.tik")
    norm_expected = normalize_tid(expected_tid)
    allowed_tids = _get_allowed_tid_ints(norm_expected)

    with open(tmd_path, "rb") as f_tmd:
        raw_tmd = f_tmd.read()
    tmd = parse_tmd(raw_tmd)

    if tmd.title_id not in allowed_tids:
        raise ValueError(f"TMD Title ID mismatch for {expected_tid}")

    with open(tik_path, "rb") as f_tik:
        raw_tik = f_tik.read()

    if len(raw_tik) < 0x2A4:
        raise ValueError(f"Truncated Ticket ({len(raw_tik)} bytes) for {expected_tid}")

    tik_tid = STRUCT_Q.unpack_from(raw_tik, 0x1DC)[0]
    if tik_tid not in allowed_tids:
        raise ValueError(f"Ticket Title ID mismatch for {expected_tid}")

    title_key = _resolve_verified_title_key(wup_dir, tmd, raw_tik, norm_expected, common_key)
    return tmd, title_key, raw_tmd, raw_tik


def _extract_vwii_decrypted_stage(tid: str, wup_dir: str, stage_dir: str, common_key: bytes) -> bool:
    if os.path.isfile(os.path.join(stage_dir, ".vwii_ready")):
        return True

    os.makedirs(stage_dir, exist_ok=True)
    cert_p = os.path.join(wup_dir, "title.cert")
    tmd, title_key, raw_tmd, raw_tik = read_tmd_and_title_key(wup_dir, common_key, tid)
    aes_algo = algorithms.AES(title_key)

    _write_bytes_fast(os.path.join(stage_dir, "title.tmd"), raw_tmd)
    _write_bytes_fast(os.path.join(stage_dir, "title.tik"), raw_tik)
    if os.path.exists(cert_p):
        shutil.copy2(cert_p, os.path.join(stage_dir, "title.cert"))

    for c in tmd.contents:
        src_app = os.path.join(wup_dir, f"{c.id:08X}.app")
        with open(src_app, "rb") as f_in:
            enc_data = f_in.read()
        rem = len(enc_data) & 0xF
        if rem != 0:
            enc_data = enc_data + b"\x00" * (16 - rem)
        iv = STRUCT_H.pack(c.index) + b"\x00" * 14
        dec_data = aes_cbc_decrypt(title_key, iv, enc_data, aes_algo=aes_algo)[: c.size]
        if len(dec_data) != c.size or hashlib.sha1(dec_data).digest() != c.hash:
            raise ValueError(
                f"SHA-1 mismatch after decrypting vWii content {c.id:08x} of {tid}: "
                f"expected {c.hash.hex()}, got {hashlib.sha1(dec_data).hexdigest()}"
            )
        _write_bytes_fast(os.path.join(stage_dir, f"{c.id:08x}.app"), dec_data)

    _write_bytes_fast(os.path.join(stage_dir, ".vwii_ready"), b"1")
    return True


def trim_tmd_body(raw_tmd: bytes) -> bytes:
    version = raw_tmd[0x180]
    count = int.from_bytes(raw_tmd[0x1DE:0x1E0], "big")
    body_len = (0xB04 + count * 0x30) if version == 1 else (0x1E4 + count * 0x24)
    if body_len > len(raw_tmd):
        raise ValueError(f"Truncated TMD: body needs {body_len} bytes, file has {len(raw_tmd)}")
    return raw_tmd[:body_len]


def trim_ticket_body(raw_tik: bytes) -> bytes:
    if len(raw_tik) >= 0x2A4 and raw_tik[0x1BC] == 0:
        return raw_tik[:0x2A4]
    return raw_tik


def _vwii_install_sort_key(vwii_hi: int, vwii_lo: int) -> Tuple[int, int, int]:
    if vwii_hi == 0x00000001:
        if vwii_lo in VWII_IOS_INSTALL_ORDER:
            return (0, VWII_IOS_INSTALL_ORDER.index(vwii_lo), vwii_lo)
        return (0, len(VWII_IOS_INSTALL_ORDER), vwii_lo)
    prefix = bytes.fromhex(f"{vwii_lo:08x}")[:3].decode("ascii", errors="ignore")
    if prefix in VWII_CHANNEL_INSTALL_ORDER:
        return (1, VWII_CHANNEL_INSTALL_ORDER.index(prefix), vwii_lo)
    return (1, len(VWII_CHANNEL_INSTALL_ORDER), (vwii_hi << 32) | vwii_lo)


class VWIISlccmptBuilder:
    def __init__(self) -> None:
        self._entries: List[Tuple[int, int, str]] = []

    def add_staged_title(self, wup_tid: str, stage_dir: str) -> None:
        clean = normalize_tid(wup_tid)
        wup_hi = int(clean[:8], 16)
        wup_lo = int(clean[8:16], 16)
        vwii_hi, vwii_lo = wup_vwii_tid_to_slccmpt(wup_hi, wup_lo)
        self._entries.append((vwii_hi, vwii_lo, stage_dir))

    def build_tree(self, slccmpt01_root: str) -> None:
        if not self._entries:
            return

        shared1_dir = os.path.join(slccmpt01_root, "shared1")
        sys_dir = os.path.join(slccmpt01_root, "sys")
        os.makedirs(shared1_dir, exist_ok=True)
        os.makedirs(sys_dir, exist_ok=True)
        for extra in ("import", "meta", "shared2", "tmp", "wfs"):
            os.makedirs(os.path.join(slccmpt01_root, extra), exist_ok=True)

        sorted_entries = sorted(self._entries, key=lambda item: _vwii_install_sort_key(item[0], item[1]))

        shared_sha1_to_id: Dict[bytes, str] = {}
        content_map_buf = bytearray()
        uid_sys_buf = bytearray()
        cert_records: Dict[str, bytes] = {}
        next_uid = 0x00001000

        for vwii_hi, vwii_lo, stage_dir in sorted_entries:
            hi_str = f"{vwii_hi:08x}"
            lo_str = f"{vwii_lo:08x}"

            tmd_path = os.path.join(stage_dir, "title.tmd")
            tik_path = os.path.join(stage_dir, "title.tik")
            cert_path = os.path.join(stage_dir, "title.cert")

            with open(tmd_path, "rb") as f_tmd:
                raw_tmd = trim_tmd_body(f_tmd.read())
            tmd = parse_tmd(raw_tmd)

            if os.path.isfile(tik_path):
                tik_dir = os.path.join(slccmpt01_root, "ticket", hi_str)
                os.makedirs(tik_dir, exist_ok=True)
                with open(tik_path, "rb") as f_tik:
                    _write_bytes_fast(os.path.join(tik_dir, f"{lo_str}.tik"), trim_ticket_body(f_tik.read()))

            if os.path.isfile(cert_path):
                with open(cert_path, "rb") as f_cert:
                    cert_bytes = f_cert.read()
                for cert_record in _parse_cert_records(cert_bytes):
                    cert_records.setdefault(cert_record.name, cert_record.raw)

            title_base = os.path.join(slccmpt01_root, "title", hi_str, lo_str)
            content_dir = os.path.join(title_base, "content")
            data_dir = os.path.join(title_base, "data")
            os.makedirs(content_dir, exist_ok=True)
            os.makedirs(data_dir, exist_ok=True)
            _write_bytes_fast(os.path.join(content_dir, "title.tmd"), raw_tmd)

            for c in tmd.contents:
                app_name = f"{c.id:08x}.app"
                src_app = os.path.join(stage_dir, app_name)
                if not os.path.isfile(src_app) or os.path.getsize(src_app) != c.size:
                    raise FileNotFoundError(f"Missing or invalid staged vWii content {src_app}")
                if c.type & 0x8000:
                    if c.hash not in shared_sha1_to_id:
                        shared_id = f"{len(shared_sha1_to_id):08x}"
                        shared_sha1_to_id[c.hash] = shared_id
                        shutil.copy2(src_app, os.path.join(shared1_dir, f"{shared_id}.app"))
                        content_map_buf.extend(shared_id.encode("ascii"))
                        content_map_buf.extend(c.hash)
                else:
                    shutil.copy2(src_app, os.path.join(content_dir, app_name))

            full_vwii_tid = (vwii_hi << 32) | vwii_lo
            uid_sys_buf.extend(struct.pack(">QI", full_vwii_tid, next_uid))
            next_uid += 1

        if len(content_map_buf) != len(shared_sha1_to_id) * 28 or (len(content_map_buf) % 28) != 0:
            raise ValueError("Corrupt vWii content.map buffer generated")
        if len(uid_sys_buf) != len(sorted_entries) * 12 or (len(uid_sys_buf) % 12) != 0:
            raise ValueError("Corrupt vWii uid.sys buffer generated")
        cert_sys_buf = bytearray()
        for prefix in VWII_CERT_SYS_ORDER:
            for cert_name in sorted(cert_records):
                if cert_name.startswith(prefix):
                    cert_sys_buf.extend(cert_records[cert_name])
        for cert_name in sorted(cert_records):
            if not cert_name.startswith(VWII_CERT_SYS_ORDER):
                cert_sys_buf.extend(cert_records[cert_name])
        if not _validate_cert_chain_bytes(bytes(cert_sys_buf), min_certs=1):
            raise ValueError("Corrupt vWii cert.sys buffer generated")

        _write_bytes_fast(os.path.join(shared1_dir, "content.map"), content_map_buf)
        _write_bytes_fast(os.path.join(sys_dir, "cert.sys"), cert_sys_buf)
        _write_bytes_fast(os.path.join(sys_dir, "uid.sys"), uid_sys_buf)


def _extract_standard_from_handle(f_in, dst_path: str, aes_algo, content_idx: int, offset: int, length: int, io_mv):
    force_remove(dst_path)
    if length == 0:
        _write_bytes_fast(dst_path, b"")
        return

    base_iv = STRUCT_H.pack(content_idx) + b"\x00" * 14
    aligned_offset = offset & ~0xF
    skip_bytes = offset - aligned_offset
    if aligned_offset > 0:
        f_in.seek(aligned_offset - 16)
        iv = f_in.read(16)
        if len(iv) != 16:
            raise IOError(f"Short IV seek read while extracting {dst_path}")
    else:
        iv = base_iv

    decryptor = Cipher(aes_algo, modes.CBC(iv), backend=_BACKEND).decryptor()
    f_in.seek(aligned_offset)

    remaining = length
    chunk_size = CHUNK_SIZE
    first_chunk = True

    buf_mode = 0 if length <= 262144 else min(chunk_size, max(65536, length))
    with open(dst_path, "wb", buffering=buf_mode) as f_out:
        while remaining > 0:
            to_read = min(chunk_size, ((remaining + skip_bytes + 15) & ~0xF))
            actual_read = f_in.readinto(io_mv[:to_read])
            if not actual_read:
                raise IOError(f"Unexpected EOF while extracting {dst_path} ({remaining} bytes remaining)")

            rem = actual_read & 0xF
            if rem != 0:
                enc_slice = bytes(io_mv[:actual_read]) + b"\x00" * (16 - rem)
                dec_data = decryptor.update(enc_slice)
            else:
                dec_data = decryptor.update(io_mv[:actual_read])

            if first_chunk:
                dec_data = dec_data[skip_bytes:]
                actual_read = max(0, actual_read - skip_bytes)
                first_chunk = False

            write_len = min(remaining, actual_read)
            f_out.write(dec_data[:write_len])
            remaining -= write_len

    if os.path.getsize(dst_path) != length:
        raise IOError(f"Extracted file size mismatch on {dst_path}: expected {length}, got {os.path.getsize(dst_path)}")


def _extract_hashed_from_handle(f_in, dst_path: str, aes_algo, content_idx: int, offset: int, length: int, stream_state, block_mv):
    force_remove(dst_path)
    if length == 0:
        _write_bytes_fast(dst_path, b"")
        return

    DATA_BLOCK, TOTAL_BLOCK = 0xFC00, 0x10000
    start_chunk_idx = offset // DATA_BLOCK
    soffset = offset % DATA_BLOCK
    h_iv = STRUCT_H.pack(content_idx) + b"\x00" * 14
    idx_hi, idx_lo = (content_idx >> 8) & 0xFF, content_idx & 0xFF

    remaining = length
    current_chunk_idx = start_chunk_idx
    c_iv = bytearray(16)

    buf_mode = 0 if length <= 262144 else min(CHUNK_SIZE, max(65536, length))
    with open(dst_path, "wb", buffering=buf_mode) as f_out:
        while remaining > 0:
            if stream_state is not None and stream_state[0] == current_chunk_idx:
                dec_content = stream_state[1]
            else:
                target_pos = current_chunk_idx * TOTAL_BLOCK
                if f_in.tell() != target_pos:
                    f_in.seek(target_pos)
                n_read = f_in.readinto(block_mv)
                if not n_read or n_read <= 0x400:
                    raise IOError(f"Unexpected EOF in hashed content while extracting {dst_path}")

                hdr_dec = Cipher(aes_algo, modes.CBC(h_iv), backend=_BACKEND).decryptor()
                hashes = hdr_dec.update(block_mv[:0x400]) + hdr_dec.finalize()

                block_num = current_chunk_idx & 0xF
                h0_off = block_num * 20
                c_iv[:] = hashes[h0_off : h0_off + 16]
                expected_h0 = bytearray(hashes[h0_off : h0_off + 20])

                if block_num == 0:
                    c_iv[0] ^= idx_hi
                    c_iv[1] ^= idx_lo
                    expected_h0[0] ^= idx_hi
                    expected_h0[1] ^= idx_lo

                payload_len = n_read - 0x400
                rem = payload_len & 0xF
                body_dec = Cipher(aes_algo, modes.CBC(bytes(c_iv)), backend=_BACKEND).decryptor()
                if rem != 0:
                    enc_data = bytes(block_mv[0x400:n_read]) + b"\x00" * (16 - rem)
                    dec_content = (body_dec.update(enc_data) + body_dec.finalize())[:payload_len]
                else:
                    dec_content = body_dec.update(block_mv[0x400:n_read]) + body_dec.finalize()

                if len(dec_content) == DATA_BLOCK and hashlib.sha1(dec_content).digest() != bytes(expected_h0):
                    raise ValueError(f"H0 block {current_chunk_idx} SHA-1 mismatch while extracting {dst_path}")

                if stream_state is not None:
                    stream_state[0] = current_chunk_idx
                    stream_state[1] = dec_content

            available_in_block = DATA_BLOCK - soffset
            write_len = min(remaining, available_in_block)
            to_write = dec_content[soffset : soffset + write_len]
            if len(to_write) < write_len:
                raise IOError(f"Short decrypted block while extracting {dst_path}")

            f_out.write(to_write)
            remaining -= write_len
            soffset = 0
            current_chunk_idx += 1

    if os.path.getsize(dst_path) != length:
        raise IOError(f"Extracted hashed file size mismatch on {dst_path}: expected {length}, got {os.path.getsize(dst_path)}")


def extract_title_from_wup(tid: str, wup_dir: str, target_dir: str, common_key: bytes) -> bool:
    if is_vwii_wup_title(tid):
        return _extract_vwii_decrypted_stage(tid, wup_dir, target_dir, common_key)

    if os.path.isfile(os.path.join(target_dir, ".cafe_ready")) and os.path.isfile(
        os.path.join(target_dir, "code", "title.tmd")
    ):
        return True

    cert_p = os.path.join(wup_dir, "title.cert")
    tmd, title_key, raw_tmd, raw_tik = read_tmd_and_title_key(wup_dir, common_key, tid)
    aes_algo = algorithms.AES(title_key)

    c0 = next((c for c in tmd.contents if c.index == 0), tmd.contents[0])
    fst_path = os.path.join(wup_dir, f"{c0.id:08X}.app")
    with open(fst_path, "rb") as f_fst:
        fst_enc = f_fst.read()
    c0_iv = STRUCT_H.pack(c0.index) + b"\x00" * 14
    rem_c0 = len(fst_enc) & 0xF
    if rem_c0 != 0:
        fst_enc = fst_enc + b"\x00" * (16 - rem_c0)
    fst_dec = aes_cbc_decrypt(title_key, c0_iv, fst_enc, aes_algo=aes_algo)[: c0.size]
    if len(fst_dec) != c0.size or hashlib.sha1(fst_dec).digest() != c0.hash:
        raise ValueError(f"Content 0 SHA-1 mismatch during extraction of {tid}")

    code_dir = os.path.join(target_dir, "code")
    os.makedirs(code_dir, exist_ok=True)
    created_dirs = {target_dir, code_dir}

    _write_bytes_fast(os.path.join(code_dir, "title.tmd"), trim_tmd_body(raw_tmd))

    is_fst = False
    offset_factor = 0x20
    info_count = entries_ptr = total_entries = name_table_off = 0

    if tmd.version == 1 and len(fst_dec) >= 0x20 and fst_dec[:4] == FST_MAGIC:
        raw_factor = STRUCT_I.unpack_from(fst_dec, 0x04)[0]
        offset_factor = raw_factor if raw_factor > 0 else 0x20
        info_count = STRUCT_I.unpack_from(fst_dec, 0x08)[0]
        entries_ptr = 0x20 + (info_count * 0x20)
        if entries_ptr + 16 <= len(fst_dec):
            total_entries = STRUCT_I.unpack_from(fst_dec, entries_ptr + 8)[0]
            name_table_off = entries_ptr + (total_entries * 0x10)
            if name_table_off <= len(fst_dec) and 0 < total_entries < 100000:
                is_fst = True
            else:
                raise ValueError(f"Corrupt FST entry table bounds in {tid}")

    if is_fst:
        _write_bytes_fast(os.path.join(code_dir, "title.fst"), fst_dec)

        path_stack, end_stack = [target_dir], [total_entries]
        content_map = {c.index: c for c in tmd.contents}
        tasks_by_cid = {}
        unpack_ii = STRUCT_II.unpack_from
        unpack_hh = STRUCT_HH.unpack_from

        for i in range(1, total_entries):
            while i >= end_stack[-1]:
                path_stack.pop()
                end_stack.pop()

            off = entries_ptr + (i * 0x10)
            e_type = fst_dec[off]
            e_name_off = (fst_dec[off + 1] << 16) | (fst_dec[off + 2] << 8) | fst_dec[off + 3]
            e_off, e_len = unpack_ii(fst_dec, off + 4)
            _, e_cid = unpack_hh(fst_dec, off + 12)

            name_start = name_table_off + e_name_off
            name_end = fst_dec.find(b"\x00", name_start)
            if name_end == -1:
                raise ValueError(f"Unterminated FST filename entry {i} in {tid}")

            name = fst_dec[name_start:name_end].decode("utf-8", errors="strict")
            if not name or "/" in name or "\\" in name or name in (".", ".."):
                raise ValueError(f"Invalid FST path component '{name}' in {tid}")

            current_path = os.path.join(path_stack[-1], name)

            if e_type & 0x01:
                if e_len <= i or e_len > total_entries:
                    raise ValueError(f"Invalid FST directory end index {e_len} in {tid}")
                if current_path not in created_dirs:
                    os.makedirs(current_path, exist_ok=True)
                    created_dirs.add(current_path)
                path_stack.append(current_path)
                end_stack.append(e_len)
            else:
                if not (e_type & 0x80):
                    if e_cid not in content_map:
                        raise ValueError(f"FST references missing content index {e_cid} in {tid}")
                    c = content_map[e_cid]
                    src_app = os.path.join(wup_dir, f"{c.id:08X}.app")
                    real_offset = e_off * offset_factor
                    max_usable_size = _get_max_content_data_size(tmd, c)
                    if real_offset + e_len > max_usable_size:
                        raise ValueError(
                            f"FST file '{name}' exceeds content {c.id:08X} size ({real_offset + e_len} > {max_usable_size}) in {tid}"
                        )
                    parent_dir = os.path.dirname(current_path)
                    if parent_dir not in created_dirs:
                        os.makedirs(parent_dir, exist_ok=True)
                        created_dirs.add(parent_dir)
                    tasks_by_cid.setdefault(e_cid, []).append((real_offset, c, src_app, current_path, e_cid, e_len))

        std_buf = std_mv = hsh_buf = hsh_mv = None

        for e_cid, cid_tasks in tasks_by_cid.items():
            cid_tasks.sort(key=lambda item: item[0])
            first_c = cid_tasks[0][1]
            src_app_path = cid_tasks[0][2]
            is_hashed = _is_h3_hashed_content(tmd, first_c)

            if is_hashed and hsh_mv is None:
                hsh_buf = bytearray(0x10000)
                hsh_mv = memoryview(hsh_buf)
            elif not is_hashed and std_mv is None:
                std_buf = bytearray(CHUNK_SIZE)
                std_mv = memoryview(std_buf)

            stream_state = [-1, b""] if is_hashed else None
            with open(src_app_path, "rb", buffering=CHUNK_SIZE) as f_in:
                for real_offset, c, _, current_path, cid_val, e_len in cid_tasks:
                    if is_hashed:
                        _extract_hashed_from_handle(
                            f_in, current_path, aes_algo, cid_val, real_offset, e_len, stream_state, hsh_mv
                        )
                    else:
                        _extract_standard_from_handle(
                            f_in, current_path, aes_algo, cid_val, real_offset, e_len, std_mv
                        )
    else:
        content_dir = os.path.join(target_dir, "content")
        meta_dir = os.path.join(target_dir, "meta")
        os.makedirs(content_dir, exist_ok=True)
        os.makedirs(meta_dir, exist_ok=True)
        buf = bytearray(CHUNK_SIZE)
        mv = memoryview(buf)

        for c in tmd.contents:
            src_app = os.path.join(wup_dir, f"{c.id:08X}.app")
            dst_path = os.path.join(content_dir, f"{c.id:08X}.app")
            iv = STRUCT_H.pack(c.index) + b"\x00" * 14
            sha1 = hashlib.sha1()
            with open(src_app, "rb", buffering=CHUNK_SIZE) as f_in, open(dst_path, "wb", buffering=CHUNK_SIZE) as f_out:
                decryptor = Cipher(aes_algo, modes.CBC(iv), backend=_BACKEND).decryptor()
                remaining = c.size
                while remaining > 0:
                    n_read = f_in.readinto(mv)
                    if not n_read:
                        break
                    rem = n_read & 0xF
                    if rem != 0:
                        padded = bytes(mv[:n_read]) + b"\x00" * (16 - rem)
                        dec = decryptor.update(padded)
                    else:
                        dec = decryptor.update(mv[:n_read])
                    write_len = min(remaining, len(dec))
                    out_slice = dec[:write_len]
                    f_out.write(out_slice)
                    sha1.update(out_slice)
                    remaining -= write_len
            if remaining != 0 or sha1.digest() != c.hash:
                raise ValueError(f"Decrypted raw content SHA-1 mismatch on {c.id:08X}.app in {tid}")

    _write_bytes_fast(os.path.join(target_dir, ".cafe_ready"), b"1")
    return True


def extract_single_file_from_fst_in_ram(
    tmd: TMD,
    title_key: bytes,
    fetch_content_cb: Callable[[Content], Optional[bytes]],
    target_filename: str,
) -> Optional[bytes]:
    aes_algo = algorithms.AES(title_key)
    c0 = next((c for c in tmd.contents if c.index == 0), tmd.contents[0])
    fst_enc = fetch_content_cb(c0)
    if not fst_enc:
        return None

    c0_iv = STRUCT_H.pack(c0.index) + b"\x00" * 14
    rem_c0 = len(fst_enc) & 0xF
    if rem_c0 != 0:
        fst_enc = fst_enc + b"\x00" * (16 - rem_c0)
    fst_dec = aes_cbc_decrypt(title_key, c0_iv, fst_enc, aes_algo=aes_algo)[: c0.size]

    if len(fst_dec) < 0x20 or fst_dec[:4] != FST_MAGIC:
        return None

    raw_factor = STRUCT_I.unpack_from(fst_dec, 0x04)[0]
    offset_factor = raw_factor if raw_factor > 0 else 0x20
    info_count = STRUCT_I.unpack_from(fst_dec, 0x08)[0]
    entries_ptr = 0x20 + (info_count * 0x20)
    if entries_ptr + 16 > len(fst_dec):
        return None

    total_entries = STRUCT_I.unpack_from(fst_dec, entries_ptr + 8)[0]
    name_table_off = entries_ptr + (total_entries * 0x10)
    if name_table_off > len(fst_dec) or total_entries <= 0 or total_entries > 100000:
        return None

    content_map = {c.index: c for c in tmd.contents}
    target_low = target_filename.lower()

    for i in range(1, total_entries):
        off = entries_ptr + (i * 0x10)
        e_type = fst_dec[off]
        if (e_type & 0x01) or (e_type & 0x80):
            continue

        e_name_off = (fst_dec[off + 1] << 16) | (fst_dec[off + 2] << 8) | fst_dec[off + 3]
        e_off, e_len = STRUCT_II.unpack_from(fst_dec, off + 4)
        _, e_cid = STRUCT_HH.unpack_from(fst_dec, off + 12)

        name_start = name_table_off + e_name_off
        name_end = fst_dec.find(b"\x00", name_start)
        if name_end == -1:
            continue

        name = fst_dec[name_start:name_end].decode("utf-8", errors="ignore")
        if name.lower() != target_low or e_cid not in content_map:
            continue

        c = content_map[e_cid]
        real_offset = e_off * offset_factor
        if real_offset + e_len > _get_max_content_data_size(tmd, c):
            return None

        raw_c = fetch_content_cb(c)
        if not raw_c:
            return None

        if _is_h3_hashed_content(tmd, c):
            DATA_BLOCK, TOTAL_BLOCK = 0xFC00, 0x10000
            chunk_idx = real_offset // DATA_BLOCK
            soffset = real_offset % DATA_BLOCK
            blk_pos = chunk_idx * TOTAL_BLOCK
            if len(raw_c) <= blk_pos + 0x400:
                return None

            blk = raw_c[blk_pos : blk_pos + TOTAL_BLOCK]
            h_iv = STRUCT_H.pack(c.index) + b"\x00" * 14
            hdr_dec = Cipher(aes_algo, modes.CBC(h_iv), backend=_BACKEND).decryptor()
            hashes = hdr_dec.update(blk[:0x400]) + hdr_dec.finalize()

            block_num = chunk_idx & 0xF
            h0_off = block_num * 20
            c_iv = bytearray(hashes[h0_off : h0_off + 16])
            if block_num == 0:
                c_iv[0] ^= (c.index >> 8) & 0xFF
                c_iv[1] ^= c.index & 0xFF

            payload = blk[0x400:]
            rem = len(payload) & 0xF
            if rem != 0:
                payload = payload + b"\x00" * (16 - rem)
            body_dec = Cipher(aes_algo, modes.CBC(bytes(c_iv)), backend=_BACKEND).decryptor()
            dec_block = body_dec.update(payload) + body_dec.finalize()
            return dec_block[soffset : soffset + e_len]
        else:
            aligned_off = real_offset & ~0xF
            skip = real_offset - aligned_off
            iv = raw_c[aligned_off - 16 : aligned_off] if aligned_off > 0 else (STRUCT_H.pack(c.index) + b"\x00" * 14)
            to_read = (e_len + skip + 15) & ~0xF
            enc_slice = raw_c[aligned_off : aligned_off + to_read]
            rem = len(enc_slice) & 0xF
            if rem != 0:
                enc_slice = enc_slice + b"\x00" * (16 - rem)
            dec = aes_cbc_decrypt(title_key, iv, enc_slice, aes_algo=aes_algo)
            return dec[skip : skip + e_len]

    return None


def decode_version_bin_bytes(data: bytes) -> Optional[dict]:
    if not data or len(data) < 17:
        return None
    pos = data.find(VER_BIN_MAGIC)
    if pos == -1 or len(data) < pos + 17:
        return None
    slice_64 = data[pos : pos + 64]
    magic, major, minor, patch, reg_byte = STRUCT_VERSION_BIN.unpack_from(slice_64, 0)
    if magic != VER_BIN_MAGIC or major > 20 or minor > 50 or patch > 50:
        return None
    reg_char = chr(reg_byte) if 32 <= reg_byte <= 126 else "?"
    return {
        "major": major,
        "minor": minor,
        "patch": patch,
        "region_char": reg_char,
        "fw_str": f"{major}.{minor}.{patch}{reg_char}",
        "tuple": (major, minor, patch),
    }
