"""Boundary regressions for Java-layer MTop INPUT/header conversion."""
import hashlib
import unittest

from native_mtop_protocol import build_sign_input, encode_form_params, encode_protocol_headers


class ProtocolBoundaryTests(unittest.TestCase):
    def test_null_direct_appends_and_blank_data(self):
        result = build_sign_input({"api": None, "data": "", "x-features": None}, "K")
        self.assertEqual(result.split("&")[4:8], ["", "null", "null", "null"])
        self.assertEqual(result.split("&")[13:15], ["", "null"])
        self.assertEqual(build_sign_input({"data": None}, "K").split("&")[4], "null")

    def test_md5_hashes_exact_json_utf8_bytes(self):
        raw = '{\"é\":1}'
        self.assertEqual(
            build_sign_input({"data": raw}, "K").split("&")[4],
            hashlib.md5(raw.encode("utf-8")).hexdigest(),
        )

    def test_extdata_unified_and_legacy_slot(self):
        params = {"extdata": "X", "x-features": "F"}
        unified = build_sign_input(params, "K", True).split("&")
        legacy = build_sign_input(params, "K", False).split("&")
        self.assertEqual(unified[13:15], ["X", "F"])
        self.assertEqual(legacy[13:15], ["X", "F"])
        self.assertEqual(build_sign_input({"extdata": " \t"}, "K", False).split("&")[13], "null")
        self.assertEqual(build_sign_input({"data": "\u00a0"}, "K").split("&")[4],
                         hashlib.md5("\u00a0".encode("utf-8")).hexdigest())
        self.assertEqual(
            build_sign_input({"data": "\u0085"}, "K").split("&")[4],
            hashlib.md5("\u0085".encode("utf-8")).hexdigest(),
        )
        self.assertEqual(
            build_sign_input({"data": "\ud800"}, "K").split("&")[4],
            hashlib.md5(b"?").hexdigest(),
        )

    def test_java_urLEncoder_space_star_tilde_and_unicode(self):
        headers, _ = encode_protocol_headers({"sid": "a b*~雪"})
        self.assertEqual(headers["x-sid"], "a+b*%7E%E9%9B%AA")

    def test_null_header_is_removed_without_mutating_input(self):
        source = {"sid": None, "unmapped": None, "lat": "1", "lng": "2"}
        headers, remainder = encode_protocol_headers(source)
        self.assertEqual(headers, {"x-location": "2%2C1"})
        self.assertEqual(remainder, {"unmapped": None})
        self.assertEqual(source, {"sid": None, "unmapped": None, "lat": "1", "lng": "2"})

    def test_form_params_null_empty_and_java_form_encoding(self):
        self.assertEqual(
            encode_form_params({"a b": None, "empty": "", "plus": "+~"}),
            "a+b=null&empty=&plus=%2B%7E",
        )


if __name__ == "__main__":
    unittest.main()
