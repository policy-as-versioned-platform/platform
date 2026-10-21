"""Explicit workload decisions through public composition and persisted replay.

All Pods, policies and scenarios here are synthetic local fixture data. The
legacy fixture setup is shared; its sibling-dependent lane tests are not run.
"""
import json
import signal
import shutil
import unittest
import yaml
import composition as ct
import test_workload_risk as fixtures


class WorkloadDeclarations(unittest.TestCase):
    def setUp(self):
        fixture = fixtures.WorkloadRisk()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.adopter, self.platform, self.trees = fixture.adopter, fixture.platform, fixture.trees

    def explicit_workload(self, **changes):
        member = self.platform/'distribution/policies/v1.0.0/member-a.yaml'
        policy = yaml.safe_load(member.read_text())
        policy['kind'] = 'MutatingPolicy'
        policy['spec'] = {'mutations': [{'patchType': 'ApplyConfiguration',
            'applyConfiguration': {'expression': 'Object{}'}}]}
        member.write_text(yaml.safe_dump(policy, sort_keys=False))
        scenario = self.adopter/'workload-scenarios/legacy-till.json'
        scenario.parent.mkdir(exist_ok=True)
        scenario.write_text(json.dumps({'version': 'fixture-v1',
            'name': 'Synthetic legacy-till retained workload exposure; no operational evidence',
            'retained': {'lef': [1, 1, 1], 'lm': [100, 100, 100]}}))
        declaration = {'publisher': 'fixture-platform', 'family': 'fam-a',
            'name': 'member-a', 'version': '1.0.0', 'subject': 'shop/legacy-till',
            'scenario': 'workload-scenarios/legacy-till.json', 'mode': 'retained',
            'why': 'Synthetic explicit workload decision, not a policy restatement'}
        declaration.update(changes)
        party = self.adopter/'party.yaml'
        doc = yaml.safe_load(party.read_text())
        doc['overlay']['floor'] = 'isolated'
        doc['overlay']['workload_cages'] = [declaration]
        party.write_text(yaml.safe_dump(doc, sort_keys=False))
        return declaration

    def test_explicit_mutating_workload_decision_is_priced_carried_and_replayable(self):
        self.explicit_workload()
        party = self.adopter/'party.yaml'
        declared = party.read_text()
        plain = yaml.safe_load(declared)
        del plain['overlay']['workload_cages']
        party.write_text(yaml.safe_dump(plain, sort_keys=False))
        baseline, before = ct.compose(self.adopter, self.trees)
        party.write_text(declared)
        document, rendered = ct.compose(self.adopter, self.trees)
        self.assertEqual(document['outcome'], 'composed', document)
        entry, = document['cages']
        self.assertEqual(entry['decision']['uncaged_residual'], 100)
        self.assertEqual(entry['tier'], 'isolated')
        self.assertAlmostEqual(entry['residual'], 2)
        self.assertEqual(entry['binding'], {'subject': 'shop/legacy-till',
            'policy': 'member-a', 'control': 'aa-2'})
        self.assertEqual(entry['oscal_risk']['related-observations'],
            [{'observation-uuid': '8fc9650c-a286-508a-b84e-51dc8d902556'}])
        self.assertEqual(document['prices'], baseline['prices'])
        self.assertEqual({k: v for k, v in rendered.items() if '/policies/' in k},
                         {k: v for k, v in before.items() if '/policies/' in k})
        for relative, content in rendered.items():
            destination = self.adopter/relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(content)
        self.assertEqual(ct.verify(self.adopter, self.trees), (True, []))

    def test_replay_binds_the_explicit_scenario_bytes_not_only_its_numeric_output(self):
        self.explicit_workload()
        _, rendered = ct.compose(self.adopter, self.trees)
        for relative, content in rendered.items():
            destination = self.adopter/relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(content)
        scenario_path = self.adopter/'workload-scenarios/legacy-till.json'
        scenario = json.loads(scenario_path.read_text())
        scenario['note'] = 'Different scenario provenance, same monetary triples'
        scenario_path.write_text(json.dumps(scenario))
        ok, mismatches = ct.verify(self.adopter, self.trees)
        self.assertFalse(ok, mismatches)

    def test_excluded_scenario_bytes_cannot_escape_persisted_replay(self):
        for relative in ('.github/workload.json', '__pycache__/workload.json',
                         'observations/workload.json'):
            with self.subTest(relative=relative):
                self.explicit_workload(scenario=relative)
                scenario = self.adopter/relative
                scenario.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy(self.adopter/'workload-scenarios/legacy-till.json', scenario)
                if relative.startswith('observations/'):
                    workflow = self.adopter/'.github/workflows/clock.yml'
                    workflow.parent.mkdir(parents=True, exist_ok=True)
                    workflow.write_text('''on:
  schedule:
    - cron: '0 0 * * *'
env:
  OBSERVATION_LANE: observations
jobs:
  sample:
    runs-on: ubuntu-latest
    steps:
      - run: echo synthetic-only
''')
                document, rendered = ct.compose(self.adopter, self.trees)
                if document['outcome'] == 'composed':
                    for name, content in rendered.items():
                        path = self.adopter/name
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_text(content)
                    self.assertEqual(ct.verify(self.adopter, self.trees), (True, []))
                    state = json.loads(scenario.read_text())
                    state['note'] = 'Changed provenance only; same monetary state'
                    scenario.write_text(json.dumps(state))
                    self.assertFalse(ct.verify(self.adopter, self.trees)[0],
                        'accepted excluded scenario provenance escaped public replay')
                self.assertEqual(document['outcome'], 'refused', document)

    def test_explicit_scenario_inputs_do_not_mint_invalid_prices(self):
        self.explicit_workload()
        path = self.adopter/'workload-scenarios/legacy-till.json'
        for state in ({'lef': [-1, -1, -1], 'lm': [100, 100, 100]},
                      {'lef': [1, 1, 1], 'lm': [-100, -100, -100]},
                      {'lef': [3, 2, 1], 'lm': [100, 100, 100]},
                      {'lef': [True, True, True], 'lm': [100, 100, 100]},
                      {'lef': [1, 1, 1], 'lm': [float('inf')]*3},
                      {'lef': [1, 1, 1], 'lm': [float('nan')]*3},
                      {'lef': [1, 1], 'lm': [100, 100, 100]},
                      {'lef': [1, 1, 1]},
                      {'lef': [1, 1, 1], 'lm': []}):
            with self.subTest(state=state):
                path.write_text(json.dumps({'retained': state}))
                def timeout(*_):
                    raise TimeoutError('public compose did not refuse invalid inputs promptly')
                previous = signal.signal(signal.SIGALRM, timeout)
                signal.alarm(3)
                try:
                    document, _ = ct.compose(self.adopter, self.trees)
                finally:
                    signal.alarm(0)
                    signal.signal(signal.SIGALRM, previous)
                self.assertEqual(document['outcome'], 'refused', document)
                self.assertEqual(document['cages'], [])
                self.assertIn('scenario', str(document['refusals']))

    def test_declared_pod_must_be_unique_and_claim_the_priced_version(self):
        self.explicit_workload()
        pod_path = self.adopter/'gitops/apps/pod.yaml'
        original = pod_path.read_text()
        for fault in ('wrong-version', 'duplicate'):
            with self.subTest(fault=fault):
                if fault == 'wrong-version':
                    pod = yaml.safe_load(original)
                    pod['metadata']['labels']['policy-as-versioned.dev/policy-version'] = '2.0.0'
                    pod_path.write_text(yaml.safe_dump(pod))
                else:
                    pod_path.write_text(original)
                    (pod_path.parent/'duplicate.yaml').write_text(original)
                document, _ = ct.compose(self.adopter, self.trees)
                self.assertEqual(document['outcome'], 'refused', document)
                self.assertEqual(document['cages'], [])

    def test_pod_dns_name_limit_is_independent_of_total_subject_length(self):
        for suffix, outcome in (('a'*63, 'refused'), ('a'*61, 'composed')):
            with self.subTest(pod_length=3*64+len(suffix)):
                name = '.'.join(['a'*63]*3+[suffix])
                self.explicit_workload(subject='ns/'+name)
                path = self.adopter/'gitops/apps/pod.yaml'
                pod = yaml.safe_load(path.read_text())
                pod['metadata'].update(namespace='ns', name=name)
                path.write_text(yaml.safe_dump(pod))
                document, _ = ct.compose(self.adopter, self.trees)
                self.assertEqual(document['outcome'], outcome, document)

    def test_a_non_gbp_band_or_scenario_cannot_be_relabelled_as_gbp(self):
        self.explicit_workload()
        party = self.adopter/'party.yaml'
        declaration = yaml.safe_load(party.read_text())
        declaration['appetite']['tolerance']['currency'] = 'USD'
        party.write_text(yaml.safe_dump(declaration))
        document, _ = ct.compose(self.adopter, self.trees)
        self.assertEqual(document['outcome'], 'refused', document)
        self.assertEqual(document['cages'], [])

        self.assertIn('GBP', str(document['refusals']))
        declaration['appetite']['tolerance']['currency'] = 'GBP'
        party.write_text(yaml.safe_dump(declaration))
        scenario_path = self.adopter/'workload-scenarios/legacy-till.json'
        scenario = json.loads(scenario_path.read_text())
        scenario['currency'] = 'USD'
        scenario_path.write_text(json.dumps(scenario))
        document, _ = ct.compose(self.adopter, self.trees)
        self.assertEqual(document['outcome'], 'refused', document)
        self.assertEqual(document['cages'], [])

    def test_only_an_exact_resolved_policy_and_closed_declaration_are_accepted(self):
        original = self.explicit_workload()
        path = self.adopter/'party.yaml'
        party = yaml.safe_load(path.read_text())
        for change in ({'publisher': 'not-the-publisher'}, {'family': 'not-the-family'},
                       {'name': 'not-the-policy'}, {'version': '2.0.0'},
                       {'subject': 'shop/undeclared'}, {'subject': '../legacy-till'},
                       {'scenario': None}, {'mode': 'not-declared'}, {'extra': 'ignored?'},
                       {'mode': None}):
            with self.subTest(change=change):
                party['overlay']['workload_cages'] = [{**original, **change}]
                path.write_text(yaml.safe_dump(party))
                document, _ = ct.compose(self.adopter, self.trees)
                self.assertEqual(document['outcome'], 'refused', document)
                self.assertEqual(document['cages'], [])
        party['overlay']['workload_cages'] = [dict(original)]
        del party['overlay']['workload_cages'][0]['mode']
        path.write_text(yaml.safe_dump(party))
        document, _ = ct.compose(self.adopter, self.trees)
        self.assertEqual(document['outcome'], 'refused', document)

    def test_scenario_must_be_an_ordinary_file_inside_the_adopter_source(self):
        original = self.explicit_workload()
        source = self.adopter/'workload-scenarios/legacy-till.json'
        outside = self.adopter.parent/'outside.json'
        shutil.copy(source, outside)
        alias = self.adopter/'workload-scenarios/alias.json'
        alias.symlink_to(outside)
        for path in ('../outside.json', str(outside), 'workload-scenarios/alias.json',
                     'workload-scenarios/missing.json', 'composed/evidence.json'):
            with self.subTest(path=path):
                party_path = self.adopter/'party.yaml'
                party = yaml.safe_load(party_path.read_text())
                party['overlay']['workload_cages'] = [{**original, 'scenario': path}]
                party_path.write_text(yaml.safe_dump(party))
                document, _ = ct.compose(self.adopter, self.trees)
                self.assertEqual(document['outcome'], 'refused', document)
                self.assertEqual(document['cages'], [])

    def test_duplicate_bindings_across_both_producers_refuse_without_policy_override(self):
        original = self.explicit_workload()
        path = self.adopter/'party.yaml'
        party = yaml.safe_load(path.read_text())
        party['overlay']['workload_cages'] = [original, original]
        path.write_text(yaml.safe_dump(party))
        document, _ = ct.compose(self.adopter, self.trees)
        self.assertEqual(document['outcome'], 'refused', document)
        self.assertIn('duplicate workload binding', str(document['refusals']))
        member = self.platform/'distribution/policies/v1.0.0/member-a.yaml'
        policy = yaml.safe_load(member.read_text())
        policy['kind'], policy['spec'] = 'ValidatingPolicy', {'validationActions': ['Deny'],
            'validations': [{'expression': 'true'}]}
        member.write_text(yaml.safe_dump(policy))
        party['overlay']['workload_cages'] = [original]
        party['overlay']['restate'] = [{'name': 'member-a', 'version': '1.0.0',
            'action': 'Audit', 'subject': 'shop/legacy-till',
            'scenario': 'policy/scenarios/driftwood-root-residual.json', 'why': 'Synthetic inability'}]
        path.write_text(yaml.safe_dump(party))
        document, _ = ct.compose(self.adopter, self.trees)
        self.assertEqual(document['outcome'], 'refused', document)
        self.assertIn('duplicate workload binding', str(document['refusals']))
        policy['kind'], policy['spec'] = 'MutatingPolicy', {'mutations': []}
        member.write_text(yaml.safe_dump(policy))
        del party['overlay']['workload_cages']
        path.write_text(yaml.safe_dump(party))
        document, _ = ct.compose(self.adopter, self.trees)
        self.assertEqual(document['outcome'], 'refused', document)
        self.assertTrue(any(row['kind'] == 'restatement-of-non-validating'
                            for row in document['refusals']))
        self.assertEqual(document['cages'], [])


if __name__ == "__main__":
    unittest.main()
