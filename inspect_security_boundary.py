#!/usr/bin/env python3
"""Bind security-component class definitions to the original APK's actual DEX bytes.

Reads original top-level/plugin DEX and hash-verified recovered business DEX.
Never trusts a JADX output directory name as proof of class provenance.
"""
import argparse
import hashlib
import io
import json
import zipfile
from pathlib import Path

from androguard.core.dex import DEX
from loguru import logger

logger.disable("androguard")
TARGETS = (
    "Lcom/alibaba/wireless/security/middletierplugin/",
    "Lcom/alibaba/wireless/security/securitybody/",
    "Lcom/taobao/wireless/security/adapter/JNICLibrary;",
)


def inspect_dex(origin, blob):
    record = {"origin": origin, "bytes": len(blob),
              "sha256": hashlib.sha256(blob).hexdigest(), "matching_definitions": []}
    # Rejecting a byte-level miss is safe; a hit still requires a class definition.
    if not any(prefix.encode("ascii") in blob for prefix in TARGETS):
        return record
    dex = DEX(blob)
    for cls in dex.get_classes():
        if not cls.get_name().startswith(TARGETS):
            continue
        methods = []
        router_methods = []
        for method in cls.get_methods():
            if "native" in method.get_access_flags_string():
                methods.append({"name": method.get_name(),
                                "descriptor": method.get_descriptor(),
                                "access": method.get_access_flags_string()})
            instructions = list(method.get_instructions())
            commands = [
                instruction.get_output()
                for instruction in instructions
                if instruction.get_name().startswith("const")
                and instruction.get_output().rsplit(", ", 1)[-1] in {"70101", "70102", "70103"}
            ]
            if commands:
                router_methods.append({
                    "name": method.get_name(), "descriptor": method.get_descriptor(),
                    "instructions": [
                        {"opcode": instruction.get_name(), "operands": instruction.get_output()}
                        for instruction in instructions
                        if instruction.get_name().startswith("const")
                        or "->doCommand(" in instruction.get_output()
                    ],
                })
        record["matching_definitions"].append({
            "class": cls.get_name(), "native_methods": methods, "router_methods": router_methods,
        })
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk", type=Path, default=Path("damai-9.0.35.apk"))
    parser.add_argument("--recovery", type=Path, default=Path("analysis/inventory/payload-recovery.json"))
    parser.add_argument("--payload", type=Path, default=Path("analysis/payload"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    recovery = json.loads(args.recovery.read_text(encoding="utf-8"))
    records = []
    with zipfile.ZipFile(args.apk) as apk:
        container = apk.read(recovery["container"])
        if hashlib.sha256(container).hexdigest() != recovery["container_sha256"]:
            raise ValueError("Recovery manifest is not bound to this APK's payload container")
        for name in apk.namelist():
            if "/" not in name and name.endswith(".dex"):
                records.append(inspect_dex(name, apk.read(name)))
            elif name.startswith("lib/") and name.endswith(".so"):
                data = apk.read(name)
                if not data.startswith(b"PK"):
                    continue
                with zipfile.ZipFile(io.BytesIO(data)) as plugin:
                    for member in plugin.namelist():
                        if member.endswith(".dex"):
                            records.append(inspect_dex(name + ":" + member, plugin.read(member)))
        for entry in recovery["entries"]:
            data = (args.payload / entry["name"]).read_bytes()
            if hashlib.sha256(data).hexdigest() != entry["sha256"]:
                raise ValueError("Recovered DEX digest mismatch: " + entry["name"])
            records.append(inspect_dex(recovery["container"] + ":" + entry["name"], data))
    with args.apk.open("rb") as apk_file:
        apk_digest = hashlib.file_digest(apk_file, "sha256").hexdigest()
    report = {
        "apk": str(args.apk), "apk_sha256": apk_digest,
        "target_prefixes": TARGETS, "dex_records": records,
        "limitation": "Absence is limited to class definitions in inventoried DEX; native/encrypted/runtime payloads remain possible.",
    }
    text = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    print(text, end="")


if __name__ == "__main__":
    main()
