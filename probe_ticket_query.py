#!/usr/bin/env python3
"""Read-only MTop baseline probes and offline Java-layer protocol reconstruction.

This is not an App client: no SecurityGuard signing, device identity or login.
Offline INPUT reconstruction is not signature generation; a rejected baseline
request says nothing about ticket availability.
"""
import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from native_mtop_protocol import build_sign_input, encode_form_params, encode_protocol_headers


def reconstruct_protocol(params, domain, unified):
    """Reconstruct only the source-confirmed Java layer; never generate a signature."""
    if not isinstance(params, dict) or any(
        not isinstance(key, str) or (value is not None and not isinstance(value, str))
        for key, value in params.items()
    ):
        raise ValueError("Protocol params must map string keys to strings or null")
    for key in ("api", "v", "data", "t", "appKey"):
        if not isinstance(params.get(key), str) or not params[key]:
            raise ValueError("Missing non-empty protocol string: " + key)
    methods = {
        ("mtop.alibaba.damai.detail.getdetail", "1.2"): "POST",
        ("mtop.alibaba.detail.subpage.getdetail", "2.0"): "GET",
    }
    method = methods.get((params["api"], params["v"]))
    if method is None:
        raise ValueError("Only the original read-only detail/SKU API versions are supported")
    headers, remaining = encode_protocol_headers(params)
    api, version = remaining.pop("api"), remaining.pop("v")
    encoded = encode_form_params(remaining)
    url = f"https://{domain}/gw/{api}/{version}/"
    headers["content-type"] = "application/x-www-form-urlencoded;charset=UTF-8"
    if method == "GET" and encoded:
        url += "?" + encoded
    return {
        "mode": "offline_java_protocol_reconstruction",
        "executed": False,
        "native_sdk_invoked": False,
        "sign_input": build_sign_input(params, params["appKey"], unified),
        "request": {"method": method, "url": url, "headers": headers,
                    "body": encoded if method == "POST" else None},
        "limitations": [
            "INPUT is not x-sign; no SecurityGuard factors are generated or validated.",
            "Supplied data/t/identity are preserved, not replaced with invented device state.",
            "Parameter order follows input JSON, not Java HashMap iteration.",
            "Runtime global query overrides and additional MTop properties are not reproduced.",
            "This diagnostic may contain supplied identity values; keep it local.",
        ],
    }


def print_report(report, output):
    rendered = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")


class NoRedirect(HTTPRedirectHandler):
    # Do not follow login/challenge URLs or replay a request at another endpoint.
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--item-id", default="1068122930586")
    parser.add_argument("--endpoint", choices=("detail", "sku"), default="sku")
    parser.add_argument("--perform-id", help="SKU cached performance selection (dataType=2)")
    parser.add_argument("--domain", choices=("acs.m.taobao.com", "mtop.damai.cn"),
                        default="acs.m.taobao.com",
                        help="SDK default; neither choice proves current App routing")
    parser.add_argument("--execute", action="store_true", help="Send exactly one request, no retries")
    parser.add_argument("--output", type=Path, help="Save request metadata and response, no cookies")
    parser.add_argument("--protocol-params", type=Path,
                        help="Offline reconstruction from raw SDK protocol-map JSON, including raw data string")
    parser.add_argument("--legacy-sign-input", action="store_true",
                        help="Use the legacy INPUT extdata rule (only with --protocol-params)")
    args = parser.parse_args()
    if args.protocol_params:
        if args.execute:
            parser.error("--protocol-params is offline only; native signing is not implemented")
        if args.perform_id:
            parser.error("--perform-id cannot override raw protocol params")
        try:
            params = json.loads(args.protocol_params.read_text(encoding="utf-8"))
            report = reconstruct_protocol(params, args.domain, not args.legacy_sign_input)
        except (OSError, ValueError) as error:
            parser.error(str(error))
        print_report(report, args.output)
        return 0
    if args.legacy_sign_input:
        parser.error("--legacy-sign-input requires --protocol-params")
    if not args.item_id.isdecimal() or (args.perform_id and not args.perform_id.isdecimal()):
        parser.error("item-id and perform-id must be decimal identifiers")
    if args.perform_id and args.endpoint != "sku":
        parser.error("perform-id applies only to sku")

    data = {"itemId": args.item_id}
    if args.endpoint == "detail":
        api, version, method = "mtop.alibaba.damai.detail.getdetail", "1.2", "POST"
    else:
        api, version, method = "mtop.alibaba.detail.subpage.getdetail", "2.0", "GET"
        ex_params = {"dataId": args.perform_id, "dataType": "2"} if args.perform_id else {}
        data.update(bizCode="ali.china.damai", scenario="itemsku", exParams=ex_params)

    # Empty/null SKU properties are omitted. Exact on-device serialization is unverified.
    encoded = encode_form_params({"data": json.dumps(data, ensure_ascii=False, separators=(",", ":"))})
    url = f"https://{args.domain}/gw/{api}/{version}/"
    headers = {
        "Accept": "application/json",
        "User-Agent": "damai-reverse-readonly-probe/1.0",
        "x-pv": "6.3",
        "x-t": str(int(time.time())),
    }
    body = None
    if method == "GET":
        url += "?" + encoded
    else:
        body = encoded.encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded;charset=UTF-8"
    report = {
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "mode": "unsigned_native_gateway_baseline",
        "executed": args.execute,
        "request": {"method": method, "url": url, "api": api, "version": version,
                    "data": data, "headers": headers},
        "limitations": [
            "No x-sign, x-appkey, device security tokens or account session supplied.",
            "SDK default domain is a candidate, not verified live Dolores routing.",
            "Not equivalent to the full App request; rejection does not indicate sold out.",
        ],
    }
    exit_code = 0
    if args.execute:
        started = time.monotonic()
        try:
            try:
                response = build_opener(NoRedirect()).open(
                    Request(url, data=body, headers=headers, method=method), timeout=20)
            except HTTPError as error:
                response = error
            with response:
                text = response.read().decode("utf-8", errors="replace")
                report["response"] = {
                    "http_status": response.code,
                    "content_type": response.headers.get("Content-Type"),
                    "bxpunish": response.headers.get("bxpunish"),
                }
            try:
                payload = json.loads(text)
            except json.JSONDecodeError:
                payload = None
                report["response"]["body_text"] = text
            else:
                report["response"]["body"] = payload
            ret = payload.get("ret", []) if isinstance(payload, dict) else []
            report["api_success"] = isinstance(ret, list) and any(
                isinstance(value, str) and value.split("::", 1)[0] == "SUCCESS" for value in ret)
            if not report["api_success"] or not 200 <= response.code < 300:
                exit_code = 1
        except (URLError, TimeoutError, OSError) as error:
            report["transport_error"] = str(error)
            exit_code = 2
        report["elapsed_ms"] = round((time.monotonic() - started) * 1000)
    print_report(report, args.output)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
