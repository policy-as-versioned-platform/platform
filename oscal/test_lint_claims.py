"""Claims must resolve to actual shipped machinery, never a remembered name list."""
import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('lint_claims',Path(__file__).with_name('lint_claims.py'))
lint=importlib.util.module_from_spec(spec)
spec.loader.exec_module(lint)


class MachineryClaims(unittest.TestCase):
    def test_new_machinery_claims_resolve_and_an_unshipped_claim_still_fails(self):
        names=lint.shipped_policy_names()
        self.assertTrue({'policy-version-orphan-cage','governed-namespace-unclaimed-report',
                         'cage-netpol-bottom-rung'} <= names)
        self.assertNotIn('cage-isolated',names,'PriorityClass is not a policy implementation')
        self.assertNotIn('unshipped-fixture-claim',names)

    def test_removed_optional_machinery_is_not_remembered_as_shipped(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            shutil.copytree(lint.PLATFORM_ROOT/'distribution',root/'distribution')
            (root/'graded/policies').mkdir(parents=True)
            shutil.copy(lint.PLATFORM_ROOT/'graded/policies/cage-tier.yaml',
                        root/'graded/policies/cage-tier.yaml')
            (root/'distribution/render-bottom-rung-netpol.py').unlink()
            names=lint.shipped_policy_names(platform_root=root)
            self.assertNotIn('cage-netpol-bottom-rung',names)
            self.assertIn('policy-version-orphan-cage',names)


if __name__=='__main__':
    unittest.main()
