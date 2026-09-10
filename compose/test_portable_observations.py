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


class PortableObservations(unittest.TestCase):
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
        (self.trees["fixture-platform"] / "graded/policies").mkdir(parents=True)
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

    def test_legacy_provenance_requires_refresh_and_does_not_invent_history(self):
        _, signed = self.composed()
        self.save(signed)
        provenance = self.adopter / "composed/feeds/fixture-publisher/v1/PROVENANCE.json"
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
        provenance = self.adopter / "composed/feeds/fixture-publisher/v1/PROVENANCE.json"
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
        provenance = self.adopter / "composed/feeds/fixture-publisher/v1/PROVENANCE.json"
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
