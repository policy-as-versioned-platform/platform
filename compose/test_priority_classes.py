"""Eco-system ticket 111: a composed set carries every PriorityClass its members name.

The cage writes `priorityClassName` from its own dial. The Priority admission plugin refuses a pod
that names a class the cluster does not hold. So a composed version that carries a cage and not
the classes that cage names cannot admit one workload, on any adopter. These tests hold two
things at the composer's own seam, `compose()`:

  * each composed version directory carries the classes its members name, rendered faithfully,
    so the version's own Kustomization delivers them and prunes them with the version;
  * a set whose member names a class it does not carry is REFUSED, naming the class.

No git, no network. Run: python3 -m unittest discover -s compose -p 'test_priority_classes.py'
"""
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

import composition as ct

sys.path.insert(0, str(ct.PLATFORM_DIR / "distribution"))
import cage_body  # noqa: F401,E402

REAL = ct.PLATFORM_DIR
VERSION = "4.0.0"
CLASSES = ["cage-baseline-4-0-0", "cage-restricted-4-0-0",
           "cage-quarantine-4-0-0", "cage-isolated-4-0-0"]


class PriorityClasses(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.platform = root / "platform"
        self.adopter = root / "adopter"
        self.trees = {"fixture-platform": self.platform, "fixture-nist": root / "nist"}
        ct._write_fixture_catalog(self.trees["fixture-nist"])
        ct._write_fixture_platform(self.platform, REAL, [])
        # The real version: the served cage and the classes the platform ships beside it.
        ct._write_versions_yaml(self.platform, [
            {"version": VERSION, "tag": f"policy/v{VERSION}", "commit": "e" * 40}])
        self.version_dir = self.platform / "distribution" / "policies" / f"v{VERSION}"
        self.version_dir.mkdir(parents=True, exist_ok=True)
        for name in ("cage-tier.yaml", "priorityclasses.yaml"):
            shutil.copy(REAL / "distribution" / "policies" / f"v{VERSION}" / name,
                        self.version_dir / name)
        # `_write_fixture_platform` copies the real machinery whole: the bottom-rung cages and
        # the one unsuffixed class they name.
        ct._write_fixture_adopter(self.adopter, "SMALL")

    def compose(self):
        return ct.compose(self.adopter, self.trees)

    def undelivered(self, doc):
        return sorted(r["subject"] for r in doc["refusals"]
                      if r["kind"] == "undelivered-priority-class")

    def write_classes(self, keep):
        docs = [d for d in yaml.safe_load_all((self.version_dir / "priorityclasses.yaml").read_text())
                if d and d["metadata"]["name"] in keep]
        (self.version_dir / "priorityclasses.yaml").write_text(yaml.safe_dump_all(docs, sort_keys=False))

    # --- what the served cage names ------------------------------------------------------

    def test_the_served_cage_names_its_four_classes_and_nothing_unread(self):
        doc = yaml.safe_load((self.version_dir / "cage-tier.yaml").read_text())
        self.assertEqual(ct.named_priority_classes(doc), (set(CLASSES), []))

    def test_a_pinned_tier_names_only_its_own_row(self):
        orphan = ct._load_module(self.platform, "render-orphan-guard.py", "render_orphan_guard")
        cage = orphan.orphan_cage([VERSION])
        self.assertEqual(ct.named_priority_classes(cage), ({"cage-isolated"}, []))

    # --- the delivery: compose the classes into the version's own directory ---------------

    def test_each_version_carries_the_classes_its_cage_names(self):
        doc, rendered = self.compose()
        self.assertEqual(doc["outcome"], "composed", doc["refusals"])
        sources = {d["metadata"]["name"]: d for d in
                   yaml.safe_load_all((self.version_dir / "priorityclasses.yaml").read_text()) if d}
        carried = {}
        for path, text in rendered.items():
            if path.startswith(f"composed/policies/v{VERSION}/"):
                obj = yaml.safe_load(text)
                if obj.get("kind") == "PriorityClass":
                    carried[obj["metadata"]["name"]] = (path, obj)
        self.assertEqual(sorted(carried), sorted(CLASSES))
        for name, (path, obj) in carried.items():
            self.assertTrue(ct.render_is_faithful(obj, sources[name]), path)
            self.assertEqual(obj["metadata"]["labels"][ct.COMPOSED_FOR], "fixture-adopter14")
        members = [m for m in doc["members"] if m["kind"] == "PriorityClass"]
        self.assertEqual(sorted((m["version"] or "machinery", m["name"]) for m in members),
                         [(VERSION, n.rsplit("-", 3)[0]) for n in sorted(CLASSES)]
                         + [("machinery", "cage-isolated")])
        self.assertIn("composed/bottom-rung-priorityclass.yaml", rendered)

    def test_the_composed_classes_verify_byte_for_byte(self):
        _, rendered = self.compose()
        for rel, content in rendered.items():
            path = self.adopter / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        self.assertEqual(ct.verify(self.adopter, self.trees), (True, []))

    # --- the refusal: a set that names a class it does not carry -------------------------

    def test_a_version_that_carries_none_of_its_classes_refuses(self):
        (self.version_dir / "priorityclasses.yaml").unlink()
        doc, _ = self.compose()
        self.assertEqual(doc["outcome"], "refused")
        self.assertEqual(self.undelivered(doc), sorted(f"{n}@{VERSION}" for n in CLASSES))
        detail = next(r["detail"] for r in doc["refusals"]
                      if r["subject"] == f"cage-isolated-4-0-0@{VERSION}")
        self.assertIn("cage-tier", detail)
        self.assertIn(f"composed/policies/v{VERSION}/", detail)

    def test_one_missing_class_is_named_alone(self):
        self.write_classes(set(CLASSES) - {"cage-isolated-4-0-0"})
        doc, _ = self.compose()
        self.assertEqual(doc["outcome"], "refused")
        self.assertEqual(self.undelivered(doc), [f"cage-isolated-4-0-0@{VERSION}"])

    def test_a_class_in_another_version_does_not_count(self):
        # A class is delivered by its OWN version's Kustomization and pruned with it, so a
        # namesake carried under a different version directory is not a delivery.
        (self.version_dir / "priorityclasses.yaml").unlink()
        other = self.platform / "distribution" / "policies" / "v4.0.1"
        other.mkdir(parents=True)
        shutil.copy(REAL / "distribution" / "policies" / f"v{VERSION}" / "priorityclasses.yaml",
                    other / "priorityclasses.yaml")
        ct._write_versions_yaml(self.platform, [
            {"version": VERSION, "tag": f"policy/v{VERSION}", "commit": "e" * 40},
            {"version": "4.0.1", "tag": "policy/v4.0.1", "commit": "f" * 40}])
        doc, _ = self.compose()
        self.assertEqual(self.undelivered(doc), sorted(f"{n}@{VERSION}" for n in CLASSES))

    def test_an_expression_the_composer_cannot_read_refuses(self):
        path = self.version_dir / "cage-tier.yaml"
        path.write_text(path.read_text().replace(
            "priorityClassName: variables.dial.pc", "priorityClassName: string(variables.dial.pc)"))
        doc, _ = self.compose()
        self.assertEqual(doc["outcome"], "refused")
        unread = [r for r in doc["refusals"] if r["kind"] == "unreadable-priority-class"]
        self.assertEqual([r["subject"] for r in unread], [f"graded-enforcement/cage-tier@{VERSION}"])
        self.assertIn("string(variables.dial.pc)", unread[0]["detail"])

    def test_an_overlay_member_naming_a_literal_class_refuses(self):
        party = yaml.safe_load((self.adopter / "party.yaml").read_text())
        party["overlay"]["add"] = [{"version": VERSION, "manifest": {
            "apiVersion": "policies.kyverno.io/v1alpha1", "kind": "MutatingPolicy",
            "metadata": {"name": "own-class-4-0-0", "labels": {ct.LABEL_FAMILY: "own"}},
            "spec": {"mutations": [{"patchType": "ApplyConfiguration", "applyConfiguration": {
                "expression": 'Object{\n  spec: Object.spec{\n    priorityClassName: "made-up"\n  }\n}'}}]},
        }}]
        (self.adopter / "party.yaml").write_text(yaml.safe_dump(party, sort_keys=False))
        doc, _ = self.compose()
        self.assertEqual(self.undelivered(doc), [f"made-up@{VERSION}"])

    def add_overlay_mutation(self, mutation):
        party = yaml.safe_load((self.adopter / "party.yaml").read_text())
        party["overlay"]["add"] = [{"version": VERSION, "manifest": {
            "apiVersion": "policies.kyverno.io/v1alpha1", "kind": "MutatingPolicy",
            "metadata": {"name": "own-class-4-0-0", "labels": {ct.LABEL_FAMILY: "own"}},
            "spec": {"mutations": [mutation]},
        }}]
        (self.adopter / "party.yaml").write_text(yaml.safe_dump(party, sort_keys=False))

    def unreadable_subjects(self, doc):
        return [r["subject"] for r in doc["refusals"] if r["kind"] == "unreadable-priority-class"]

    def test_a_jsonpatch_that_writes_the_class_refuses(self):
        # Review round: every served cage-tier already carries a `patchType: JSONPatch`
        # mutation, so a JSONPatch path is an ordinary spelling, not an exotic one.
        self.add_overlay_mutation({"patchType": "JSONPatch", "jsonPatch": {
            "expression": '[JSONPatch{op: "add", path: "/spec/priorityClassName", value: "made-up"}]'}})
        doc, _ = self.compose()
        self.assertEqual(doc["outcome"], "refused")
        self.assertEqual(self.unreadable_subjects(doc), [f"own/own-class@{VERSION}"])

    def test_a_patch_path_in_structured_form_refuses(self):
        self.add_overlay_mutation({"patchType": "JSONPatch", "patches": [
            {"op": "replace", "path": "/spec/template/spec/priorityClassName", "value": "made-up"}]})
        doc, _ = self.compose()
        self.assertEqual(doc["outcome"], "refused")
        self.assertEqual(self.unreadable_subjects(doc), [f"own/own-class@{VERSION}"])

    def test_reading_the_machinery_leaves_the_shared_cage_body_alone(self):
        # Review round: only `_load_guards` may bind `cage_body`, and it puts the old one back.
        before = sys.modules.get("cage_body")
        ct._load_guards_from(self.platform)
        self.assertIs(sys.modules.get("cage_body"), before)

    def test_machinery_that_names_a_class_it_does_not_ship_refuses(self):
        (self.platform / "distribution" / "render-bottom-rung-netpol.py").unlink()
        doc, rendered = self.compose()
        self.assertNotIn("composed/bottom-rung-priorityclass.yaml", rendered)
        self.assertEqual(doc["outcome"], "refused")
        self.assertEqual(self.undelivered(doc), ["cage-isolated@machinery"])


if __name__ == "__main__":
    unittest.main()
