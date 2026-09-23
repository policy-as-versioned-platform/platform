"""Eco-system ticket 130: every object the composer renders has a delivery route.

The composer renders two kinds of object. A policy version's members land in
`composed/policies/v<version>/`, and the adopter's ResourceSet ranges one Kustomization per
version over those directories. The platform machinery (the orphan guard and cage, the
governed-namespace cage, their holds, the report, the bottom-rung reach cage and its
PriorityClass) lands at the `composed/` root. No Kustomization reached the root, so on a cluster
that machinery never arrived.

The route decided here: the composer renders `composed/kustomization.yaml`, listing exactly the
root objects it rendered, and the adopter reconciles `./composed` with one more Kustomization.
These tests hold that at the composer's own seam, `compose()`:

  * the root kustomization exists and lists every root object the composer rendered, and only
    those, so a machinery file can never be rendered and left behind;
  * every object the composer renders is under exactly one route: a version directory or the
    root list, never both and never neither;
  * the root list re-renders byte for byte, so `verify()` holds it like any other file;
  * the handbook, which describes what is installed, does not describe the kustomization as an
    installed object.

No git, no network. Run: python3 -m unittest discover -s compose -p 'test_machinery_delivery.py'
"""
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

import composition as ct
import handbook

sys.path.insert(0, str(ct.PLATFORM_DIR / "distribution"))
import cage_body  # noqa: F401,E402

REAL = ct.PLATFORM_DIR
VERSION = "4.0.0"
ROOT_KUSTOMIZATION = "composed/kustomization.yaml"


def _objects(text: str) -> list[dict]:
    return [d for d in yaml.safe_load_all(text) if isinstance(d, dict) and d.get("kind")]


class MachineryDelivery(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.platform = root / "platform"
        self.adopter = root / "adopter"
        self.trees = {"fixture-platform": self.platform, "fixture-nist": root / "nist"}
        ct._write_fixture_catalog(self.trees["fixture-nist"])
        ct._write_fixture_platform(self.platform, REAL, [])
        ct._write_versions_yaml(self.platform, [
            {"version": VERSION, "tag": f"policy/v{VERSION}", "commit": "e" * 40}])
        version_dir = self.platform / "distribution" / "policies" / f"v{VERSION}"
        version_dir.mkdir(parents=True, exist_ok=True)
        for name in ("cage-tier.yaml", "priorityclasses.yaml"):
            shutil.copy(REAL / "distribution" / "policies" / f"v{VERSION}" / name,
                        version_dir / name)
        ct._write_fixture_adopter(self.adopter, "SMALL")

    def compose(self):
        doc, rendered = ct.compose(self.adopter, self.trees)
        self.assertEqual(doc["outcome"], "composed", doc["refusals"])
        return doc, rendered

    def root_objects(self, rendered):
        """Every rendered file directly under composed/ that carries a cluster object."""
        return sorted(p for p, text in rendered.items()
                      if p.startswith("composed/") and p.count("/") == 1
                      and p.endswith(".yaml") and p != ROOT_KUSTOMIZATION
                      and _objects(text))

    def test_the_root_kustomization_lists_every_root_object(self):
        _, rendered = self.compose()
        self.assertIn(ROOT_KUSTOMIZATION, rendered)
        doc = yaml.safe_load(rendered[ROOT_KUSTOMIZATION])
        self.assertEqual(doc["apiVersion"], "kustomize.config.k8s.io/v1beta1")
        self.assertEqual(doc["kind"], "Kustomization")
        listed = [f"composed/{r}" for r in doc["resources"]]
        self.assertEqual(listed, self.root_objects(rendered))
        # The machinery the ticket names is in it: the orphan cage, the governed-namespace cage
        # and the unsuffixed class they both name.
        for name in ("orphan-cage.yaml", "governed-namespace-guard.yaml",
                     "bottom-rung-priorityclass.yaml"):
            self.assertIn(name, doc["resources"])

    def test_the_root_list_names_files_not_directories(self):
        # A directory in the root list would reach composed/policies/v*/ a second time, and give
        # every versioned object two owners.
        _, rendered = self.compose()
        for r in yaml.safe_load(rendered[ROOT_KUSTOMIZATION])["resources"]:
            self.assertNotIn("/", r)
            self.assertIn(f"composed/{r}", rendered)

    def test_every_rendered_object_has_exactly_one_route(self):
        _, rendered = self.compose()
        listed = {f"composed/{r}" for r in yaml.safe_load(rendered[ROOT_KUSTOMIZATION])["resources"]}
        routes = {}
        for path, text in rendered.items():
            if not path.endswith(".yaml") or path == ROOT_KUSTOMIZATION or not _objects(text):
                continue
            in_version = path.startswith("composed/policies/v") and path.count("/") == 3
            in_root = path in listed
            routes[path] = (in_version, in_root)
        self.assertTrue(routes)
        stranded = sorted(p for p, (v, r) in routes.items() if not v and not r)
        doubled = sorted(p for p, (v, r) in routes.items() if v and r)
        self.assertEqual((stranded, doubled), ([], []))

    def test_the_root_kustomization_verifies_byte_for_byte(self):
        _, rendered = self.compose()
        for rel, content in rendered.items():
            path = self.adopter / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        self.assertEqual(ct.verify(self.adopter, self.trees), (True, []))
        # And a hand edit to it is caught like a hand edit to any member.
        path = self.adopter / ROOT_KUSTOMIZATION
        path.write_text(path.read_text() + "- planted.yaml\n")
        ok, mismatches = ct.verify(self.adopter, self.trees)
        self.assertFalse(ok)
        self.assertIn(f"{ROOT_KUSTOMIZATION}: committed content differs from the re-render",
                      mismatches)

    def test_the_handbook_does_not_count_the_kustomization_as_installed(self):
        _, rendered = self.compose()
        paths = {o["path"] for o in handbook._policy_objects(rendered)}
        self.assertNotIn(ROOT_KUSTOMIZATION, paths)
        self.assertIn("composed/orphan-cage.yaml", paths)


if __name__ == "__main__":
    unittest.main()
