#!/usr/bin/env python3
"""Offline APK inventory; does not execute APK code or contact its services."""
import argparse
import hashlib
import json
import re
import zipfile
import struct
import zlib
from pathlib import Path
from loguru import logger
from androguard.core.apk import APK
from androguard.core.dex import DEX

logger.disable("androguard")
parser = argparse.ArgumentParser()
parser.add_argument("apk", type=Path)
parser.add_argument("--output", type=Path, default=Path("analysis/inventory"))
args = parser.parse_args()
args.output.mkdir(parents=True, exist_ok=True)
raw = args.apk.read_bytes()
apk = APK(raw, raw=True)
certs = apk.get_certificates()
metadata = {
    "file": str(args.apk), "bytes": len(raw),
    "sha256": hashlib.sha256(raw).hexdigest(), "md5": hashlib.md5(raw).hexdigest(),
    "package": apk.get_package(), "version_name": apk.get_androidversion_name(),
    "version_code": apk.get_androidversion_code(),
    "min_sdk": apk.get_min_sdk_version(), "target_sdk": apk.get_target_sdk_version(),
    "main_activity": apk.get_main_activity(),
    "application": apk.get_attribute_value("application", "name"),
    "permissions": apk.get_permissions(),
    "signature_schemes_present": {"v1": apk.is_signed_v1(), "v2": apk.is_signed_v2(), "v3": apk.is_signed_v3()},
    "certificates": [{"sha256": c.sha256_fingerprint, "subject": c.subject.human_friendly,
                       "issuer": c.issuer.human_friendly} for c in certs],
    "limitations": ["Signature presence and certificate extraction are not cryptographic signature verification.",
                    "Static declarations do not prove runtime use or server acceptance."]
}
(args.output / "metadata.json").write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + "\n")
from lxml import etree
(args.output / "AndroidManifest.xml").write_bytes(etree.tostring(apk.get_android_manifest_xml(), pretty_print=True, encoding="utf-8"))
pattern = re.compile(r"mtop\.|damai|securityguard|securesign|nocaptcha|x-sign|x-mini|x-sg|x-umt|umid|root|frida|xposed|captcha|risk|anti.?bot", re.I)
classes = []
strings = []
with zipfile.ZipFile(args.apk) as z:
    members = [{"name": i.filename, "bytes": i.file_size, "compressed_bytes": i.compress_size} for i in z.infolist()]
    (args.output / "members.json").write_text(json.dumps(members, ensure_ascii=False, indent=2) + "\n")
    # This sample's data.png has valid local ZIP records but no usable EOCD.
    # Recover only complete, unencrypted DEX entries with matching size and CRC.
    payload = z.read("assets/data.png")
    offset = 0
    recovered = []
    payload_dir = args.output.parent / "payload"
    payload_dir.mkdir(exist_ok=True)
    while payload[offset:offset + 4] == b"PK\x03\x04":
        header = struct.unpack_from("<4s5H3I2H", payload, offset)
        _, version, flags, method, time, date, crc, packed, size, nlen, extra = header
        name = payload[offset + 30:offset + 30 + nlen].decode("utf-8")
        start = offset + 30 + nlen + extra
        end = start + packed
        if flags & 9 or method != 8 or end > len(payload):
            raise ValueError(f"Unsupported or incomplete inner ZIP record: {name}")
        data = zlib.decompress(payload[start:end], -15)
        if len(data) != size or zlib.crc32(data) != crc:
            raise ValueError(f"Inner ZIP size/CRC mismatch: {name}")
        if re.fullmatch(r"classes\d*\.dex", name):
            if not data.startswith(b"dex\n"):
                raise ValueError(f"Not a DEX: {name}")
            (payload_dir / name).write_bytes(data)
            dex = DEX(data)
            classes.extend(f"assets/data.png:{name}\t{c.get_name()}" for c in dex.get_classes())
            strings.extend(f"assets/data.png:{name}\t{s}" for s in dex.get_strings() if pattern.search(s))
            recovered.append({"name": name, "offset": offset, "bytes": size,
                              "crc32": f"{crc:08x}", "sha256": hashlib.sha256(data).hexdigest()})
        offset = end
    (args.output / "payload-recovery.json").write_text(json.dumps({
        "container": "assets/data.png", "container_bytes": len(payload),
        "container_sha256": hashlib.sha256(payload).hexdigest(),
        "local_records_end": offset, "remaining_bytes": len(payload) - offset,
        "next_magic_hex": payload[offset:offset + 4].hex(),
        "entries": recovered}, indent=2) + "\n")
    for name in z.namelist():
        if re.fullmatch(r"classes\d*\.dex", name):
            dex = DEX(z.read(name))
            classes.extend(f"{name}\t{c.get_name()}" for c in dex.get_classes())
            strings.extend(f"{name}\t{s}" for s in dex.get_strings() if pattern.search(s))
    native = []
    for name in z.namelist():
        if name.startswith("lib/") and any(k in name.lower() for k in ("security", "sg", "shell", "behav", "demolish", "preverify")):
            data = z.read(name)
            matches = [s.decode("ascii") for s in re.findall(rb"[\x20-\x7e]{5,}", data) if pattern.search(s.decode("ascii"))]
            native.append({"member": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "matching_strings": matches})
    (args.output / "native-security-strings.json").write_text(json.dumps(native, ensure_ascii=False, indent=2) + "\n")
(args.output / "classes.tsv").write_text("\n".join(classes) + "\n")
(args.output / "interesting-strings.tsv").write_text("\n".join(strings) + "\n")
print(json.dumps({"metadata": metadata, "class_count": len(classes), "matching_string_count": len(strings), "output": str(args.output)}, ensure_ascii=False, indent=2))
