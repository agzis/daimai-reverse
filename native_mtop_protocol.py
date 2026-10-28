"""Java-layer MTop INPUT reconstruction; not a valid x-sign.

Sources: mtopsdk/security/InnerSignImpl.java:152-225,
mtopsdk/security/util/SecurityUtils.java:11-35, and
mtopsdk/mtop/protocol/converter/impl/{AbstractNetworkConverter,InnerNetworkConverter}.java.
No native signing algorithm is implemented.
"""
from collections.abc import Mapping
from typing import Optional
from hashlib import md5
from unicodedata import category
from urllib.parse import quote_plus

# InnerNetworkConverter.java:12-49, resolved HttpHeaderConstant/XStateConstants.
_HEADER_MAP = {
    "x-sid": "sid", "x-t": "t", "x-appkey": "appKey", "x-ttid": "ttid",
    "x-devid": "deviceId", "x-utdid": "utdid", "x-sign": "sign",
    "x-nq": "nq", "x-nettype": "netType", "x-pv": "pv", "x-uid": "uid",
    "x-umt": "umt", "x-reqbiz-ext": "reqbiz-ext", "x-router-id": "routerId",
    "x-place-id": "placeId", "x-open-biz": "open-biz",
    "x-mini-appkey": "mini-appkey", "x-req-appkey": "req-appkey",
    "x-open-biz-data": "open-biz-data", "x-act": "accessToken",
    "x-mini-wua": "x-mini-wua", "x-app-conf-v": "x-app-conf-v",
    "x-exttype": "exttype", "x-extdata": "extdata", "x-features": "x-features",
    "x-page-name": "x-page-name", "x-page-url": "x-page-url",
    "x-page-mab": "x-page-mab", "x-app-ver": "x-app-ver", "x-orange-q": "x-orange-q",
    "user-agent": "user-agent", "x-c-traceid": "x-c-traceid",
    "x-falco-id": "x-falco-id", "f-refer": "f-refer",
    "x-netinfo": "x-netinfo", "x-s-c": "x-s-c",
    "x-sgext": "x-sgext", "x-accept-stream": "x-accept-stream",
}


def _java_urlencode(value: str) -> str:
    """Match java.net.URLEncoder.encode(value, "utf-8")."""
    return quote_plus(value, safe="*-._", encoding="utf-8", errors="replace").replace("~", "%7E")


def encode_protocol_headers(
    params: Mapping[str, Optional[str]],
) -> tuple[dict[str, str], dict[str, Optional[str]]]:
    """Convert source parameter keys to encoded headers and remaining params.

    Mirrors AbstractNetworkConverter.buildRequestHeaders(..., true); does not
    mutate input. Java Map.remove removes null-valued mapped keys too, but those
    values are omitted from output headers. Location combines lng,lat.
    """
    remaining = dict(params)
    headers: dict[str, str] = {}
    for header, parameter in _HEADER_MAP.items():
        if parameter in remaining:
            value = remaining.pop(parameter)
            if value is not None:
                headers[header] = _java_urlencode(value)
    longitude = remaining.pop("lng", None)
    latitude = remaining.pop("lat", None)
    if longitude is not None and latitude is not None:
        headers["x-location"] = _java_urlencode(longitude + "," + latitude)
    return headers, remaining


def _java_string(value: Optional[str]) -> str:
    return "null" if value is None else value


def _md5_or_blank(value: Optional[str]) -> str:
    if value is None or all(_java_is_whitespace(ch) for ch in value):
        return _java_string(value)
    return md5(value.encode("utf-8", errors="replace")).hexdigest()


def _java_is_whitespace(char: str) -> bool:
    # Character.isWhitespace: ASCII separators/control whitespace, plus Unicode
    # separator categories except the three non-breaking space characters.
    codepoint = ord(char)
    if 0x09 <= codepoint <= 0x0D or 0x1C <= codepoint <= 0x1F:
        return True
    return category(char) in {"Zs", "Zl", "Zp"} and char not in "\u00a0\u2007\u202f"


def encode_form_params(params: Mapping[str, Optional[str]]) -> str:
    """Serialize parameters like NetworkConverterUtils.createParamQueryStr.

    Entries are emitted in mapping iteration order. Null values become literal
    ``null``; keys and non-null values use Java UTF-8 form URL encoding.
    """
    return "&".join(
        f"{_java_urlencode(key)}={_java_urlencode(value) if value is not None else 'null'}"
        for key, value in params.items()
    )


def build_sign_input(
    params: Mapping[str, Optional[str]], app_key: str, unified: bool = True
) -> str:
    """Build Java signature INPUT (not a valid x-sign).

    Field order/null handling: InnerSignImpl.java:152-225. Hash and null
    conversion: SecurityUtils.java:11-35. Direct StringBuilder.append(null)
    becomes literal ``null``; convertNull2Default fields become empty.
    Unified mode always includes extdata; legacy mode skips blank extdata.
    """
    def defaulted(key: str) -> str:
        value = params.get(key)
        return "" if value is None else value

    fields = [
        defaulted("utdid"), defaulted("uid"), defaulted("reqbiz-ext"), app_key,
        _md5_or_blank(params.get("data")), _java_string(params.get("t")),
        _java_string(params.get("api")), _java_string(params.get("v")),
        defaulted("sid"), defaulted("ttid"), defaulted("deviceId"),
        defaulted("lat"), defaulted("lng"),
    ]
    extdata = params.get("extdata")
    if unified:
        fields.append(defaulted("extdata"))
    elif extdata is not None and not all(_java_is_whitespace(ch) for ch in extdata):
        fields.append(extdata)
    fields.extend([
        _java_string(params.get("x-features")), defaulted("routerId"),
        defaulted("placeId"), defaulted("open-biz"), defaulted("mini-appkey"),
        defaulted("req-appkey"), defaulted("accessToken"), defaulted("open-biz-data"),
    ])
    return "&".join(fields)
