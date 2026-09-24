"""Ticket 110: compose/verify through real temporary files and fixture git tags.

No real publisher is tagged; the signature-shaped block explicitly says FIXTURE.
Run: python3 -m unittest discover -s compose -p 'test_portable_observations.py'
"""
import json
import os
import shutil
from pathlib import Path
import subprocess
import tempfile
import sys
import unittest

import composition as ct

# The renderers import their shared module by name; load the stable shipped
# module before temporary fixture paths so it never points at a deleted fixture.
sys.path.insert(0, str(ct.PLATFORM_DIR / "distribution"))
import cage_body  # noqa: F401,E402


class PublisherFixture(unittest.TestCase):
    """One fixture publisher tagging cve at three majors, and one adopter pinning cve@v1."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.adopter = self.root / "adopter"
        self.publisher = self.root / "fixture-publisher"
        self.publisher.mkdir()
        self.trees = {"fixture-platform": self.root / "platform",
                      "fixture-nist": self.root / "nist",
                      "fixture-publisher": self.publisher}
        ct._write_fixture_catalog(self.trees["fixture-nist"])
        ct._write_fixture_platform(self.trees["fixture-platform"], ct.PLATFORM_DIR, [])
        shutil.copy(ct.PLATFORM_DIR / "distribution/cage_body.py",
                    self.trees["fixture-platform"] / "distribution/cage_body.py")
        (self.trees["fixture-platform"] / "graded/policies").mkdir(parents=True, exist_ok=True)
        shutil.copy(ct.PLATFORM_DIR / "graded/policies/cage-tier.yaml",
                    self.trees["fixture-platform"] / "graded/policies/cage-tier.yaml")
        ct._write_fixture_adopter(self.adopter, "SMALL", extra_inherits=[{
            "party": "fixture-publisher", "kind": "feed", "name": "cve", "version": "v1",
            "since": "2026-09-01"}])
        for major in (1, 2, 3):
            dest = self.publisher / "cve" / f"v{major}"
            dest.mkdir(parents=True)
            (dest / "feed.json").write_text(json.dumps({
                "kind": "feed", "name": "cve", "version": f"{major}.0.0",
                "published_by": "fixture-publisher", "published_at": "2026-09-01T00:00:00Z",
                "payload_schema": "cve/payload.schema.json",
                "payload": {"severity_lm_gbp": {"high": [1000, 2000, 3000]},
                            "cves": {"fixture": {"component": "fixture", "cvss": 8,
                                    "severity": "high", "epss": 0.5, "source": "fixture"}}}}))
        self.git("init", "-q")
        self.git("add", ".")
        self.git("commit", "-qm", "fixture")
        self.tag("v1.0.0", "2026-09-01")
        self.tag("v2.0.0", "2026-09-10")

    def git(self, *args, date="2026-09-01"):
        env = {**os.environ, "GIT_AUTHOR_NAME": "fixture", "GIT_AUTHOR_EMAIL": "fixture@invalid",
               "GIT_COMMITTER_NAME": "fixture", "GIT_COMMITTER_EMAIL": "fixture@invalid",
               "GIT_COMMITTER_DATE": date + "T12:00:00Z"}
        return subprocess.run(["git", "-C", str(self.publisher), "-c", "core.hooksPath=/dev/null",
                               "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", *args],
                              check=True, capture_output=True, text=True, env=env)

    def tag(self, version, date):
        self.git("tag", "-a", "cve/" + version, "-m", "-----BEGIN FIXTURE (not a signature)-----",
                 date=date)

    def composed(self, trees=None, **kwargs):
        doc, rendered = ct.compose(self.adopter, self.trees if trees is None else trees, **kwargs)
        self.assertEqual(doc["outcome"], "composed", doc)
        return doc, rendered

    def save(self, rendered):
        for rel, content in rendered.items():
            path = self.adopter / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)


class PortableObservations(PublisherFixture):
    def test_signed_supersede_rerenders_without_the_publisher(self):
        doc, first = self.composed()
        self.assertEqual([p["amount"] for p in doc["prices"] if p["kind"] == "supersede"], [0.0])
        self.save(first)
        _, present = self.composed()
        _, absent = self.composed({k: v for k, v in self.trees.items() if k != "fixture-publisher"})
        self.assertEqual(present, absent)
        self.assertEqual(ct.verify(self.adopter, self.trees), (True, []))

    def test_later_tag_changes_fresh_composition_but_not_verification(self):
        doc, signed = self.composed(as_of="2027-09-10")
        surcharge = next(p for p in doc["prices"] if p["kind"] == "supersede")
        self.assertGreater(surcharge["amount"], 0)
        self.save(signed)
        self.tag("v3.0.0", "2026-09-11")
        self.assertEqual(ct.verify(self.adopter, self.trees), (True, []))
        self.assertEqual(ct.verify(self.adopter, {k: v for k, v in self.trees.items()
                                                 if k != "fixture-publisher"}), (True, []))
        refreshed, _ = self.composed(as_of="2027-09-10")
        latest = next(p for p in refreshed["prices"] if p["kind"] == "supersede")
        self.assertEqual(latest["newer"]["version"], "v3")
        self.assertEqual(latest["since"], "2026-09-10")
        self.assertIn("does not establish the publisher's current newest major", signed["composed/HANDBOOK.md"])

    def test_behind_a_major_the_checkout_cannot_read_is_priced_and_replays(self):
        # Ticket 128: the adopters check a publisher out at their pinned commit, so a
        # newer major tagged on a later commit has no directory here. The signed tags
        # still say the pin is behind, and being behind is never free.
        for major in (2, 3):
            shutil.rmtree(self.publisher / "cve" / f"v{major}")
        self.git("add", "-A")
        self.git("commit", "-qm", "the pinned commit carries only v1")
        self.tag("v3.0.0", "2026-09-11")
        doc, first = self.composed(as_of="2027-09-10")
        line = next(p for p in doc["prices"] if p["kind"] == "feed")
        self.assertEqual(line["superseded"]["state"], "behind", line["superseded"])
        self.assertIn("carries no directory", line["superseded"]["detail"])
        sups = [p for p in doc["prices"] if p["kind"] == "supersede"]
        self.assertEqual(len(sups), 1, doc["prices"])
        sup = sups[0]
        self.assertEqual(sup["newer"]["version"], "v3")
        self.assertEqual(sup["newer"]["tag"], "cve/v3.0.0")
        self.assertIs(sup["newer"]["readable"], False)
        self.assertIsNone(sup["newer"]["published_at"])
        self.assertEqual(sup["newer"]["since_tag"], "cve/v2.0.0")
        self.assertEqual(sup["since"], "2026-09-10")
        self.assertGreater(sup["amount"], 0)
        self.assertAlmostEqual(sup["amount"], sup["base"] * (sup["ramp"] - 1.0))
        self.assertTrue(any("no directory" in lim for lim in sup["limits"]), sup["limits"])
        self.save(first)
        _, present = self.composed(as_of="2027-09-10")
        without = {k: v for k, v in self.trees.items() if k != "fixture-publisher"}
        _, absent = self.composed(without, as_of="2027-09-10")
        self.assertEqual(present, absent)
        self.assertEqual(first, present)
        self.assertEqual(ct.verify(self.adopter, self.trees), (True, []))
        self.assertEqual(ct.verify(self.adopter, without), (True, []))

    def test_an_unreadable_target_must_say_so_consistently(self):
        for major in (2, 3):
            shutil.rmtree(self.publisher / "cve" / f"v{major}")
        self.git("add", "-A")
        self.git("commit", "-qm", "the pinned commit carries only v1")
        _, signed = self.composed()
        self.save(signed)
        provenance = self.adopter / ct.vendored_rel("fixture-publisher", "cve", "v1") / ct.VENDORED_PROVENANCE
        original = provenance.read_text()
        without = {k: v for k, v in self.trees.items() if k != "fixture-publisher"}
        for key, value in (("readable", True), ("readable", "no"), ("published_at", "2026-09-10")):
            with self.subTest(key=key, value=value):
                record = json.loads(original)
                record["publisher_observation"]["newer"][key] = value
                provenance.write_text(json.dumps(record))
                doc, _ = ct.compose(self.adopter, without)
                self.assertEqual(doc["outcome"], "refused")
                self.assertIn("no valid recorded publisher observation",
                              str(doc["party_artefact_errors"]))

    def test_legacy_provenance_requires_refresh_and_does_not_invent_history(self):
        _, signed = self.composed()
        self.save(signed)
        provenance = self.adopter / ct.vendored_rel("fixture-publisher", "cve", "v1") / ct.VENDORED_PROVENANCE
        record = json.loads(provenance.read_text())
        del record["publisher_observation"]
        provenance.write_text(json.dumps(record))
        ok, failures = ct.verify(self.adopter, self.trees)
        self.assertFalse(ok)
        self.assertIn("no valid recorded publisher observation", str(failures))
        without = {k: v for k, v in self.trees.items() if k != "fixture-publisher"}
        doc, _ = ct.compose(self.adopter, without)
        self.assertEqual(doc["outcome"], "refused")
        _, refreshed = self.composed()
        self.save(refreshed)
        self.assertEqual(ct.verify(self.adopter, without), (True, []))

    def test_current_and_unobserved_are_recorded_not_reinterpreted_offline(self):
        self.git("tag", "-d", "cve/v2.0.0")
        _, signed = self.composed()
        self.save(signed)
        self.assertEqual(ct.verify(self.adopter, {k: v for k, v in self.trees.items()
                                                 if k != "fixture-publisher"}), (True, []))
        self.git("tag", "-d", "cve/v1.0.0")
        doc, unsigned = self.composed()
        self.assertEqual(next(p for p in doc["prices"] if p["kind"] == "feed")["superseded"]["state"],
                         "unobserved")
        self.save(unsigned)
        self.tag("v2.0.0", "2026-09-10")
        self.assertEqual(ct.verify(self.adopter, self.trees), (True, []))

    def test_snapshot_for_another_feed_or_invalid_dates_refuses(self):
        _, signed = self.composed()
        self.save(signed)
        provenance = self.adopter / ct.vendored_rel("fixture-publisher", "cve", "v1") / ct.VENDORED_PROVENANCE
        original = provenance.read_text()
        for field, value in (("party", "another-publisher"), ("sha", "0" * 40),
                             ("name", "another-feed"), ("version", "v2"), ("schema", 9)):
            with self.subTest(field=field):
                record = json.loads(original)
                record["publisher_observation"][field] = value
                provenance.write_text(json.dumps(record))
                ok, failures = ct.verify(self.adopter, self.trees)
                self.assertFalse(ok)
                self.assertIn("no valid recorded publisher observation", str(failures))
        record = json.loads(original)
        record["publisher_observation"]["newer"]["since"] = "2026-02-30"
        provenance.write_text(json.dumps(record))
        self.assertFalse(ct.verify(self.adopter, self.trees)[0])

    def test_incomplete_signature_and_mismatched_target_tags_refuse_offline(self):
        _, signed = self.composed()
        self.save(signed)
        provenance = self.adopter / ct.vendored_rel("fixture-publisher", "cve", "v1") / ct.VENDORED_PROVENANCE
        original = provenance.read_text()
        without = {k: v for k, v in self.trees.items() if k != "fixture-publisher"}
        cases = (("pin_signature", "tag", None),
                 ("pin_signature", "tag", "cve/v9.0.0"),
                 ("newer", "tag", "another-feed/v2.0.0"),
                 ("newer", "tag", "cve/v3.0.0"),
                 ("newer", "since_tag", "cve/v1.0.0"),
                 ("newer", "since_tag", "cve/v3.0.0"))
        for section, key, value in cases:
            with self.subTest(section=section, key=key, value=value):
                record = json.loads(original)
                observation = record["publisher_observation"]
                if value is None:
                    del observation[section][key]
                else:
                    observation[section][key] = value
                provenance.write_text(json.dumps(record))
                doc, _ = ct.compose(self.adopter, without)
                self.assertEqual(doc["outcome"], "refused")
                self.assertIn("no valid recorded publisher observation", str(doc["party_artefact_errors"]))


class TwoFeedsOfOnePublisherAtOneMajor(PublisherFixture):
    """Ticket 136: tuppence pins feeds/cve@v2, and the selfcheck's threat-register bump to v2
    (the same edit a real Renovate PR makes) refused because both feeds vendored to
    composed/feeds/feeds/v2. A feed is (party, name, version), so its vendored copy is too."""

    def setUp(self):
        super().setUp()
        dest = self.publisher / "eol" / "v1"
        dest.mkdir(parents=True)
        (dest / "feed.json").write_text(json.dumps({
            "kind": "feed", "name": "eol", "version": "1.0.0",
            "published_by": "fixture-publisher", "published_at": "2026-09-01T00:00:00Z",
            "payload_schema": "eol/payload.schema.json",
            "payload": {"feed_version": "v1", "currency": "GBP", "components": {
                "fixture": {"eol_date": "2026-01-01", "source": "fixture",
                            "base_lef": [1, 3, 6], "base_lm_gbp": [2000, 10000, 40000]}}}}))
        self.git("add", "eol")
        self.git("commit", "-qm", "a second feed at the same major")
        doc = ct.yaml.safe_load((self.adopter / "party.yaml").read_text())
        doc["inherits"].append({"party": "fixture-publisher", "kind": "feed", "name": "eol",
                                "version": "v1", "since": "2026-09-01"})
        (self.adopter / "party.yaml").write_text(ct.yaml.safe_dump(doc, sort_keys=False))

    def test_each_feed_vendors_to_its_own_directory(self):
        doc, rendered = self.composed(as_of="2026-09-20")
        self.assertEqual(doc["refusals"], [])
        for name in ("cve", "eol"):
            base = f"composed/feeds/fixture-publisher/{name}/v1"
            record = json.loads(rendered[f"{base}/PROVENANCE.json"])
            self.assertEqual((record["name"], record["version"]), (name, "v1"))
            self.assertIn(f"{base}/{name}/v1/feed.json", rendered)
        header = ct.yaml.safe_load(rendered["composed/HEADER.yaml"])
        self.assertEqual(sorted(v["path"] for v in header["vendored-feeds"]),
                         ["composed/feeds/fixture-publisher/cve/v1",
                          "composed/feeds/fixture-publisher/eol/v1"])
        self.save(rendered)
        self.assertEqual(ct.verify(self.adopter, self.trees), (True, []))


class TwoFeedsOfOnePublisherAtTwoMajors(PublisherFixture):
    """Ticket 137: compose() kept one parent tree per party, so with the publisher absent
    the second feed read the first feed's vendored tree and refused. tuppence pins
    feeds/threat-register@v1 and feeds/cve@v2, the same shape as cve@v1 and eol@v2 here."""

    def setUp(self):
        super().setUp()
        dest = self.publisher / "eol" / "v2"
        dest.mkdir(parents=True)
        (dest / "feed.json").write_text(json.dumps({
            "kind": "feed", "name": "eol", "version": "2.0.0",
            "published_by": "fixture-publisher", "published_at": "2026-09-01T00:00:00Z",
            "payload_schema": "eol/payload.schema.json",
            "payload": {"feed_version": "v2", "currency": "GBP", "components": {
                "fixture": {"eol_date": "2026-01-01", "source": "fixture",
                            "base_lef": [1, 3, 6], "base_lm_gbp": [2000, 10000, 40000]}}}}))
        self.git("add", "eol")
        self.git("commit", "-qm", "a second feed at another major")
        doc = ct.yaml.safe_load((self.adopter / "party.yaml").read_text())
        doc["inherits"].append({"party": "fixture-publisher", "kind": "feed", "name": "eol",
                                "version": "v2", "since": "2026-09-01"})
        (self.adopter / "party.yaml").write_text(ct.yaml.safe_dump(doc, sort_keys=False))
        self.without = {k: v for k, v in self.trees.items() if k != "fixture-publisher"}

    def test_each_feed_reads_its_own_vendored_tree_with_the_publisher_absent(self):
        doc, signed = self.composed(as_of="2026-09-20")
        self.assertEqual(sorted((p["name"], p["version"]) for p in doc["parents"]
                                if p["kind"] == "feed"), [("cve", "v1"), ("eol", "v2")])
        self.save(signed)
        _, present = self.composed(as_of="2026-09-20")
        doc_absent, absent = self.composed(self.without, as_of="2026-09-20")
        self.assertEqual(present, absent)
        self.assertEqual(signed, present)
        self.assertEqual([p for p in doc_absent["parents"] if p["kind"] == "feed"],
                         [p for p in doc["parents"] if p["kind"] == "feed"])
        self.assertEqual(ct.verify(self.adopter, self.trees), (True, []))
        self.assertEqual(ct.verify(self.adopter, self.without), (True, []))

    def test_a_tampered_second_feed_still_refuses_by_its_own_name(self):
        _, signed = self.composed(as_of="2026-09-20")
        self.save(signed)
        feed = (self.adopter / ct.vendored_rel("fixture-publisher", "eol", "v2")
                / "eol" / "v2" / "feed.json")
        feed.write_text(feed.read_text().replace("40000", "40001"))
        doc, _ = ct.compose(self.adopter, self.without, as_of="2026-09-20")
        self.assertEqual(doc["outcome"], "refused")
        errors = str(doc["party_artefact_errors"])
        self.assertIn("fixture-publisher/feed@v2", errors)
        self.assertIn("does not match the digest", errors)
