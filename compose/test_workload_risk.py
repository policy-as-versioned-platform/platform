"""An explicitly bound restatement carries its real Cage decision into OSCAL."""
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import yaml

import composition as ct


class WorkloadRisk(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.adopter = root/'adopter'
        self.platform = root/'platform'
        self.trees = {'fixture-platform': self.platform, 'fixture-nist': root/'nist'}
        ct._write_fixture_catalog(self.trees['fixture-nist'])
        ct._write_fixture_platform(self.platform, ct.PLATFORM_DIR, [('aa-2', 'member-a')])
        ct._write_fixture_adopter(self.adopter, 'SMALL')
        member = self.platform/'distribution/policies/v1.0.0/member-a.yaml'
        member.write_text(member.read_text().replace('Audit', 'Deny'))
        apps = self.adopter/'gitops/apps'
        (apps/'pod.yaml').write_text(yaml.safe_dump({'apiVersion': 'v1', 'kind': 'Pod',
            'metadata': {'name': 'legacy-till', 'namespace': 'shop',
                         'labels': {'policy-as-versioned.dev/policy-version': '1.0.0'}},
            'spec': {'containers': [{'name': 'app', 'image': 'fixture'}]}}))
        self.restatement = {'name': 'member-a', 'version': '1.0.0', 'action': 'Audit',
            'scenario': 'policy/scenarios/driftwood-root-residual.json',
            'why': 'Fixture root inability, priced by the published scenario',
            'subject': 'shop/legacy-till'}

    def compose(self, **changes):
        party = self.adopter/'party.yaml'
        declaration = yaml.safe_load(party.read_text())
        declaration['overlay']['restate'] = [{**self.restatement, **changes}]
        party.write_text(yaml.safe_dump(declaration))
        return ct.compose(self.adopter, self.trees)

    def test_bound_restated_workload_emits_a_joinable_risk_from_its_actual_decision(self):
        document, rendered = self.compose()
        self.assertEqual(document['outcome'], 'composed', document)
        entry, = document['cages']
        risk = entry['oscal_risk']
        decision = entry['decision']
        self.assertEqual(decision['org'], 'fixture-adopter14')
        self.assertEqual(decision['tcor']['residual'], entry['residual'])
        self.assertEqual(risk, ct._cage_engine().oscal_risk(decision,
            subject='shop/legacy-till', policy='member-a', control='aa-2'))
        self.assertEqual(entry['binding'], {'subject': 'shop/legacy-till', 'policy': 'member-a', 'control': 'aa-2'})
        self.assertNotIn('risks', document, 'the same money stays on the existing cage line')
        spec = importlib.util.spec_from_file_location('priced_workload_converter', ct.PLATFORM_DIR/'oscal/result2oscal.py')
        converter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(converter)
        component = json.loads((self.platform/'oscal/component-definition.json').read_text())
        assessment = converter.convert([{'scope': {'kind': 'Pod', 'name': 'legacy-till', 'namespace': 'shop'},
            'results': [{'policy': 'member-a-1-0-0', 'result': 'fail'}]}], component)
        emitted = {observation['uuid'] for result in assessment['assessment-results']['results']
                   for observation in result['observations']}
        self.assertIn(risk['related-observations'][0]['observation-uuid'], emitted)
        for relative, content in rendered.items():
            destination = self.adopter/relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(content)
        self.assertEqual(ct.verify(self.adopter, self.trees), (True, []))

    def test_unbound_inability_keeps_its_decision_without_inventing_a_pod_risk(self):
        del self.restatement['subject']
        document, _ = self.compose()
        self.assertEqual(document['outcome'], 'composed', document)
        entry, = document['cages']
        self.assertEqual(entry['decision']['action'], 'Cage')
        self.assertNotIn('oscal_risk', entry)

    def test_invalid_or_undeclared_subject_refuses(self):
        for subject in ('shop/not-declared', 'Upper/pod', '../legacy-till', 'shop/', 'shop/pod/extra'):
            with self.subTest(subject=subject):
                document, _ = self.compose(subject=subject)
                self.assertEqual(document['outcome'], 'refused', document)
                self.assertIn('subject', str(document))

    def test_a_binding_needs_one_published_policy_to_control_mapping(self):
        for claims in ([], [('aa-1', 'member-a'), ('aa-2', 'member-a')]):
            with self.subTest(claims=claims):
                ct._write_component_definition(self.platform/'oscal/component-definition.json', claims)
                document, _ = self.compose()
                self.assertEqual(document['outcome'], 'refused', document)
                self.assertIn('mapping', str(document))

    def test_a_stricter_statement_cannot_claim_a_retained_workload_risk(self):
        document, _ = self.compose(action='Deny')
        self.assertEqual(document['outcome'], 'refused', document)
        self.assertIn('binding', str(document))

    def test_the_lane_joins_the_actual_bound_decision_with_its_pinned_engine(self):
        document, _ = self.compose()
        for relative in ('oscal/result2oscal.py', 'graded/cage.py'):
            destination = self.platform/relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(ct.PLATFORM_DIR/relative, destination)
        entry, = document['cages']
        report = {'scope': {'kind': 'Pod', 'name': 'legacy-till', 'namespace': 'shop'},
                  'results': [{'policy': 'member-a-1-0-0', 'result': 'fail'}]}
        pod = {'metadata': {'name': 'legacy-till', 'namespace': 'shop', 'labels': {
            'policy-as-versioned.dev/policy-version': '1.0.0',
            'posture.acme.io/caged': 'true', 'posture.acme.io/tier': entry['tier']}}}
        class API:
            reason = ''
            def get(self, *arguments):
                if arguments[0] == '-n':
                    return pod
                return {'items': [json.loads(json.dumps(report))] if arguments[1].startswith('policyreports.') else []}
        sampler = SimpleNamespace(Cluster=lambda _: API(), now=lambda: '2026-10-03T00:00:00Z',
            rc=SimpleNamespace(pinned_tag=lambda: 'v1.0.0', render=lambda _: {
                'member': {'kind': 'ValidatingPolicy', 'metadata': {'name': 'member-a-1-0-0'}}}),
            _git_output=lambda *_: json.dumps(document))
        ambient = SimpleNamespace(NS=ct._cage_engine().NS, observation_uuid=lambda *_: 'wrong-ambient-engine',
                                  oscal_risk=lambda *_args, **_kwargs: {})
        for party in ('driftwood', 'tuppence', 'ludlow'):
            with self.subTest(party=party):
                spec = importlib.util.spec_from_file_location('workload_lane_'+party,
                    ct.PLATFORM_DIR.parent/party/'drift/oscal_lane.py')
                lane = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(lane)
                original_load = lane.load
                def collect():
                    with patch.object(lane, 'load', side_effect=lambda path, name:
                            sampler if name == 'five_facts_instrument' else original_load(path, name)), \
                            patch.dict(sys.modules, {'cage': ambient}):
                        return lane.collect('fixture', self.platform)
                row = collect()
                self.assertEqual(row['status'], 'observed', row)
                self.assertEqual(row['risk_validation_errors'], [], row)
                self.assertEqual(row['missing_risk_observations'], [], row)
                self.assertEqual(row['risks'], [entry['oscal_risk']])
                original = json.loads(json.dumps(entry))
                for fault in ('unbound', 'wrong-tier', 'wrong-version', 'wrong-price', 'wrong-rule'):
                    with self.subTest(fault=fault):
                        if fault == 'unbound':
                            entry.pop('binding')
                            entry.pop('oscal_risk')
                        elif fault == 'wrong-tier':
                            pod['metadata']['labels']['posture.acme.io/tier'] = 'wrong-tier'
                        elif fault == 'wrong-version':
                            pod['metadata']['labels']['policy-as-versioned.dev/policy-version'] = '2.0.0'
                        elif fault == 'wrong-price':
                            entry['oscal_risk']['characterizations'][0]['facets'][-1]['value'] = '0'
                        else:
                            entry['rule'] = 'fam-a/unrelated-check@1.0.0'
                        row = collect()
                        self.assertEqual(row['status'], 'observed', row)
                        self.assertTrue(row['missing_risk_observations'], row)
                        self.assertEqual(row['risks'], [], row)
                        entry.clear()
                        entry.update(json.loads(json.dumps(original)))
                        pod['metadata']['labels']['posture.acme.io/tier'] = original['tier']
                        pod['metadata']['labels']['policy-as-versioned.dev/policy-version'] = '1.0.0'


if __name__ == '__main__':
    unittest.main()
