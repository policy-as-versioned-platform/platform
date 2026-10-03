"""An unpriced exposure regime remains visible without an invented monetary amount.

These tests exercise the public handbook render over the composed artefact shape. A
missing regime amount is a named absence; a measured zero remains a monetary zero.
"""
import unittest

import yaml

import handbook


class UnpricedExposureRegime(unittest.TestCase):
    def artefact(self, amount):
        files, evidence = handbook._fixture()
        header = yaml.safe_load(files[handbook.HEADER_PATH])
        regime = header["exposure"]["regimes"][0]
        regime["amount"] = amount
        regime["controls"] = ["ac-1"]
        header["exposure"]["total"] = None
        files[handbook.HEADER_PATH] = yaml.safe_dump(header, sort_keys=False)
        return files, evidence

    def test_unpriced_regime_names_its_absent_amount_and_still_renders(self):
        for amount_present in (True, False):
            with self.subTest(amount_present=amount_present):
                files, evidence = self.artefact(None)
                if not amount_present:
                    header = yaml.safe_load(files[handbook.HEADER_PATH])
                    del header["exposure"]["regimes"][0]["amount"]
                    files[handbook.HEADER_PATH] = yaml.safe_dump(header, sort_keys=False)
                page = handbook.render(files, evidence)
                regimes = page.split("- Regimes (1):", 1)[1].split("## 5.", 1)[0]
                self.assertIn("`uk-gdpr` from ico feed `penalty-schema` v3:", regimes)
                self.assertIn("unpriced", regimes)
                self.assertIn("1 control(s) named", regimes)
                self.assertNotIn("GBP 0.00", regimes)
                self.assertIn("`exposure.regimes[0].amount` (in `composed/HEADER.yaml`)", page)
                self.assertNotIn("- Total:", page)

    def test_a_measured_zero_remains_a_monetary_amount(self):
        page = handbook.render(*self.artefact(0.0))
        regimes = page.split("- Regimes (1):", 1)[1].split("## 5.", 1)[0]
        self.assertIn("v3: GBP 0.00, 1 control(s) named", regimes)
        self.assertNotIn("unpriced", regimes)
        self.assertNotIn("`exposure.regimes[0].amount`", page)

    def test_a_nonnumeric_present_amount_is_still_refused(self):
        with self.assertRaisesRegex(handbook.CannotRender, "an amount that is not a number"):
            handbook.render(*self.artefact("unknown"))


if __name__ == "__main__":
    unittest.main()
