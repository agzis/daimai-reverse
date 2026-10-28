"""Read-only queries through the authenticated, unmodified official App SDK."""
from __future__ import annotations

import math
import time
from typing import Any, Callable, Iterator

from .transport import RuntimeTransport


class QueryStopped(RuntimeError):
    """The query must not be replayed automatically."""


def query_spec(kind: str, *, item_id: str | None = None, perform_id: str | None = None,
               order_id: str | None = None, page: int = 1, page_size: int = 20,
               query_type: int = 0, timeout_ms: int = 25_000) -> dict[str, Any]:
    common = {"method": "GET", "need_session": kind != "sku", "need_ecode": kind != "sku",
              "use_wua": False, "timeout_ms": timeout_ms}
    if kind == "orders":
        if page < 1 or not 1 <= page_size <= 100:
            raise ValueError("page must be positive and page-size must be between 1 and 100")
        common.update(api="mtop.damai.wireless.order.orderlist.get", version="1.0",
                      request_class="cn.damai.trade.newtradeorder.ui.orderlist.net.OrderListRequest",
                      data={"pageNum": page, "pageSize": page_size, "queryOrderType": 1,
                            "queryType": query_type})
    elif kind == "order":
        if not order_id or not order_id.isdecimal():
            raise ValueError("order-id must be a decimal identifier")
        common.update(api="mtop.damai.wireless.order.orderdetail", version="2.0",
                      request_class="cn.damai.trade.newtradeorder.ui.orderdetail.net.OrderDetailRequest",
                      data={"orderId": order_id, "sVersion": "2"})
    elif kind == "sku":
        if not item_id or not item_id.isdecimal() or (perform_id is not None and not perform_id.isdecimal()):
            raise ValueError("item-id and optional perform-id must be decimal identifiers")
        extra = {"dataId": perform_id, "dataType": "2"} if perform_id else {}
        common.update(api="mtop.alibaba.detail.subpage.getdetail", version="2.0",
                      request_class="cn.damai.commonbusiness.seatbiz.sku.qilin.request.SkuRequest",
                      data={"itemId": item_id, "scenario": "itemsku", "bizCode": "ali.china.damai",
                            "exParams": extra})
    else:
        raise ValueError(f"Unknown query kind: {kind}")
    return common


def require_success(result: dict[str, Any]) -> dict[str, Any]:
    """HTTP 200 alone, queued responses and SDK callbacks are not business success."""
    if (result.get("source") != "onSuccess" or result.get("ret") != "SUCCESS"
            or result.get("http_status") != 200 or result.get("error") is not None):
        code = result.get("ret") or "UNKNOWN_RESPONSE"
        status = result.get("http_status")
        # No response bodies, identities or security values in the exception.
        raise QueryStopped(f"SDK query stopped: code={code}, status={status}; no automatic retry")
    return result


class QueryClient:
    def __init__(self, transport: RuntimeTransport):
        self.transport = transport

    def query(self, spec: dict[str, Any]) -> dict[str, Any]:
        if spec.get("method") != "GET" or spec.get("request_class") not in {
            "cn.damai.trade.newtradeorder.ui.orderlist.net.OrderListRequest",
            "cn.damai.trade.newtradeorder.ui.orderdetail.net.OrderDetailRequest",
            "cn.damai.commonbusiness.seatbiz.sku.qilin.request.SkuRequest",
        }:
            raise ValueError("QueryClient only accepts the documented read-only request wrappers")
        status = self.transport.status()
        if status.get("package") != "cn.damai" or status.get("version") != "9.0.34":
            raise QueryStopped("Runtime package/version differs from the verified 9.0.34 contract")
        if spec.get("need_session") and not status.get("has_session"):
            raise QueryStopped("No App account session is present; log in manually in the official App")
        return require_success(self.transport.request(spec))

    def repeat(self, spec: dict[str, Any], *, count: int = 1, interval_seconds: float = 30,
               sleep: Callable[[float], None] = time.sleep) -> Iterator[dict[str, Any]]:
        """Finite scheduled queries; any business/transport error terminates the sequence."""
        if not isinstance(count, int) or isinstance(count, bool) or count < 1:
            raise ValueError("count must be a positive integer")
        if not math.isfinite(interval_seconds) or interval_seconds < 30:
            raise ValueError("interval must be finite and at least 30 seconds")
        for index in range(count):
            if index:
                sleep(interval_seconds)
            yield self.query(spec)
