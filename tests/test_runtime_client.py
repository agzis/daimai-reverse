import unittest

from damai_runtime.client import QueryClient, QueryStopped, query_spec, require_success


class SessionRuntime:
    def __init__(self, responses, *, has_session=True, version="9.0.34"):
        self.responses = iter(responses)
        self.has_session = has_session
        self.version = version
        self.dispatched = 0

    def status(self):
        return {"package": "cn.damai", "version": self.version, "has_session": self.has_session}

    def request(self, _spec):
        self.dispatched += 1
        result = next(self.responses)
        if isinstance(result, Exception):
            raise result
        return result


def response(code, *, status=200, source="onSuccess"):
    return {"source": source, "ret": code, "http_status": status, "error": None, "data": {}}


class QueryBoundaryTests(unittest.TestCase):
    def test_business_rejection_ends_scheduled_queries_even_with_http_200(self):
        runtime = SessionRuntime([response("SUCCESS"), response("FAIL_SYS_USER_VALIDATE"), response("SUCCESS")])
        waits = []
        results = QueryClient(runtime).repeat(query_spec("orders"), count=3, sleep=waits.append)
        next(results)
        with self.assertRaisesRegex(QueryStopped, "FAIL_SYS_USER_VALIDATE"):
            next(results)
        with self.assertRaises(StopIteration):
            next(results)
        self.assertEqual(runtime.dispatched, 2, "a rejected API must not be automatically replayed")
        self.assertEqual(waits, [30], "there must be no scheduled delay/retry after rejection")

    def test_transport_timeout_is_not_replayed(self):
        runtime = SessionRuntime([TimeoutError("unknown outcome"), response("SUCCESS")])
        results = QueryClient(runtime).repeat(query_spec("orders"), count=2, sleep=lambda _: None)
        with self.assertRaises(TimeoutError):
            next(results)
        with self.assertRaises(StopIteration):
            next(results)
        self.assertEqual(runtime.dispatched, 1)

    def test_no_session_prevents_account_api_dispatch(self):
        runtime = SessionRuntime([], has_session=False)
        with self.assertRaisesRegex(QueryStopped, "log in manually"):
            QueryClient(runtime).query(query_spec("orders"))
        self.assertEqual(runtime.dispatched, 0)

    def test_unverified_app_build_prevents_dispatch(self):
        runtime = SessionRuntime([], version="9.0.35")
        with self.assertRaisesRegex(QueryStopped, "version"):
            QueryClient(runtime).query(query_spec("orders"))
        self.assertEqual(runtime.dispatched, 0)

    def test_success_requires_both_business_and_transport_success(self):
        cases = [response("SUCCESS", status=419), response(None), response("FAIL_SYS_TRAFFIC_LIMIT"),
                 response("SUCCESS", source="onSystemError")]
        for result in cases:
            with self.subTest(code=result["ret"], status=result["http_status"], source=result["source"]):
                with self.assertRaises(QueryStopped):
                    require_success(result)


if __name__ == "__main__":
    unittest.main()
