"""Programmatic official-SDK queries. No credential export or automatic purchases."""
from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path
import shutil
import subprocess
import sys

from .client import QueryClient, QueryStopped, query_spec
from .transport import RuntimeTransport

ROOT = Path(__file__).resolve().parent


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--device", default="127.0.0.1:23942", help="Frida endpoint or device ID")
    p.add_argument("--serial", default="emulator-5554", help="ADB device serial")
    sdk = Path(os.environ.get("ANDROID_HOME", "/opt/homebrew/share/android-commandlinetools"))
    p.add_argument("--adb", default=shutil.which("adb") or str(sdk / "platform-tools" / "adb"))
    p.add_argument("--pid", type=int, help="Attach to this cn.damai main-process PID instead of resolving it via ADB")
    p.add_argument("--timeout", type=float, default=40, help="RPC deadline in seconds")
    p.add_argument("--bundle", type=Path, default=ROOT / "agent.bundle.js")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("build", help="Compile the bridge locally; no device/network request")
    sub.add_parser("status", help="Read package/version and session-presence boolean; no ticket API request")
    orders = sub.add_parser("orders", help="Query the logged-in account's order list")
    orders.add_argument("--page", type=int, default=1)
    orders.add_argument("--page-size", type=int, default=20)
    orders.add_argument("--query-type", type=int, default=0)
    order = sub.add_parser("order", help="Query one order using the logged-in account")
    order.add_argument("--order-id", required=True)
    sku = sub.add_parser("sku", help="Query performance/SKU availability; not a ticket reservation")
    sku.add_argument("--item-id", required=True)
    sku.add_argument("--perform-id")
    for q in (orders, order, sku):
        q.add_argument("--count", type=int, default=1, help="Finite number of successful queries to attempt")
        q.add_argument("--interval", type=float, default=30, help="Seconds between successful queries, minimum 30")
    return p


def resolve_pid(args: argparse.Namespace) -> int:
    if args.pid is not None:
        if args.pid <= 0:
            raise ValueError("pid must be positive")
        return args.pid
    proc = subprocess.run([args.adb, "-s", args.serial, "shell", "pidof", "cn.damai"],
                          capture_output=True, text=True, timeout=15)
    values = proc.stdout.split()
    if proc.returncode or len(values) != 1 or not values[0].isdecimal():
        raise RuntimeError("No unique cn.damai main process; start the official App on the selected device")
    return int(values[0])


def build_bundle(path: Path) -> None:
    import frida
    if frida.__version__ != "16.7.19":
        raise RuntimeError("This verified runtime requires frida==16.7.19 (client and server)")
    compiler = frida.Compiler()
    source = compiler.build(str(ROOT / "agent.js"), project_root=str(ROOT))
    path.write_text(source, encoding="utf-8")
    print(json.dumps({"compiled": True, "bundle": str(path), "bytes": len(source.encode("utf-8"))}))


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "build":
            build_bundle(args.bundle)
            return 0
        if not math.isfinite(args.timeout) or args.timeout < 10:
            raise ValueError("timeout must be finite and at least 10 seconds")
        spec = None
        if args.command != "status":
            # Validate all scheduling/input bounds before attaching or making any query.
            if args.count < 1 or not math.isfinite(args.interval) or args.interval < 30:
                raise ValueError("count must be positive; interval must be finite and at least 30 seconds")
            spec = query_spec(args.command, item_id=getattr(args, "item_id", None),
                              perform_id=getattr(args, "perform_id", None),
                              order_id=getattr(args, "order_id", None),
                              page=getattr(args, "page", 1), page_size=getattr(args, "page_size", 20),
                              query_type=getattr(args, "query_type", 0),
                              timeout_ms=int((args.timeout - 5) * 1000))
        pid = resolve_pid(args)
        with RuntimeTransport(args.device, pid, args.bundle, args.timeout) as runtime:
            if args.command == "status":
                print(json.dumps(runtime.status(), ensure_ascii=False))
            else:
                client = QueryClient(runtime)
                for index, result in enumerate(client.repeat(spec, count=args.count,
                                                             interval_seconds=args.interval), start=1):
                    print(json.dumps({"query": args.command, "sequence": index, "response": result},
                                     ensure_ascii=False), flush=True)
        return 0
    except QueryStopped as exc:
        print(json.dumps({"ok": False, "stopped": True, "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 4
    except (RuntimeError, OSError, ValueError, TimeoutError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print(json.dumps({"ok": False, "stopped": True, "error": "Interrupted; no request is retried"}), file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
