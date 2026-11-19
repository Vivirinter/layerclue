import unittest

from check_results import OPTIONAL, REQUIRED, check


def results():
    return {name: {"result": "success" if name in REQUIRED else "skipped"}
            for name in REQUIRED | OPTIONAL}


class GateTests(unittest.TestCase):
    def test_success_with_unrequested_labs(self):
        check(results())

    def test_success_with_requested_labs(self):
        data = results()
        for name in OPTIONAL:
            data[name]["result"] = "success"
        check(data)

    def test_required_failure_cancellation_and_skip(self):
        for name in REQUIRED:
            for status in ("failure", "cancelled", "skipped", "unknown", None):
                with self.subTest(name=name, status=status):
                    data = results()
                    data[name]["result"] = status
                    with self.assertRaises(ValueError):
                        check(data)

    def test_requested_lab_failure_or_cancellation(self):
        for name in OPTIONAL:
            for status in ("failure", "cancelled", "unknown", None):
                with self.subTest(name=name, status=status):
                    data = results()
                    data[name]["result"] = status
                    with self.assertRaises(ValueError):
                        check(data)

    def test_requested_lab_must_not_be_silently_skipped(self):
        for name in OPTIONAL:
            with self.subTest(name=name), self.assertRaises(ValueError):
                check(results(), {name})

    def test_requested_lab_success(self):
        data = results()
        for name in OPTIONAL:
            data[name]["result"] = "success"
        check(data, OPTIONAL)

    def test_unknown_requested_lab(self):
        with self.assertRaises(ValueError):
            check(results(), {"not-a-lab"})

    def test_incomplete_or_malformed_results(self):
        missing = results()
        missing.pop("quality")
        extra = results()
        extra["unexpected"] = {"result": "success"}
        malformed = results()
        malformed["quality"] = "success"
        for data in ({}, [], None, missing, extra, malformed):
            with self.subTest(data=data), self.assertRaises(ValueError):
                check(data)


if __name__ == "__main__":
    unittest.main()
