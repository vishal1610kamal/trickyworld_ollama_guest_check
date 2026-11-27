import unittest

from guestcheck import versions as V


def cves(version):
    return [c for c, _, _ in V.affected(version)]


class Versions(unittest.TestCase):
    def test_parse_orders_release_candidates_first(self):
        self.assertLess(V.parse("0.35.0-rc1"), V.parse("0.35.0"))
        self.assertLess(V.parse("0.34.9"), V.parse("0.35.0-rc0"))
        self.assertEqual(V.parse("v0.40.18"), (0, 40, 18, 1, 0))
        self.assertIsNone(V.parse("garbage"))

    def test_ranges(self):
        # CVE-2026-108836's record says "up to 0.34.1", with no first affected version
        self.assertEqual(cves("0.1.28"), ["CVE-2024-28224", "CVE-2024-37032", "CVE-2026-7482", "CVE-2026-108836"])
        self.assertEqual(cves("0.1.30"), ["CVE-2024-37032", "CVE-2026-7482", "CVE-2026-108836"])
        self.assertEqual(cves("0.5.7"), ["CVE-2026-7482", "CVE-2026-108836"])
        self.assertEqual(cves("0.14.3"), ["CVE-2026-7482", "CVE-2026-103663", "CVE-2026-108836"])
        self.assertEqual(cves("0.31.0"), ["CVE-2026-103663", "CVE-2026-85180", "CVE-2026-108836"])
        self.assertEqual(cves("0.33.3"), ["CVE-2026-103663", "CVE-2026-108836"])
        self.assertEqual(cves("0.34.2"), ["CVE-2026-103663"])
        self.assertEqual(cves("0.35.0-rc1"), ["CVE-2026-103663"])
        self.assertEqual(cves(V.SAFE_FLOOR), [])
        self.assertEqual(cves("0.40.18"), [])
        self.assertEqual(cves("0.40.19-rc0"), [])

    def test_unknown_versions(self):
        self.assertEqual(V.affected("0.0.0"), [])
        self.assertEqual(V.affected(""), [])


if __name__ == "__main__":
    unittest.main()
