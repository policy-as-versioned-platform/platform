"""Transition comparisons survive the public compose/save/verify boundary."""
import json
import unittest
import composition as ct
import test_portable_observations as fixtures


class ComparisonHistory(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.PortableObservations()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def save(self, doc, rendered):
        self.fixture.save(rendered)
        (self.fixture.adopter / 'composed/evidence.json').write_text(json.dumps(doc))

    def test_unsigned_feed_transition_survives_saved_evidence_and_repeated_compose(self):
        self.fixture.git('tag', '-d', 'cve/v1.0.0')
        doc, rendered = self.fixture.composed()
        self.assertEqual([d['kind'] for d in doc['deltas']], ['new-untagged-pin'])
        self.save(doc, rendered)
        self.assertEqual(ct.verify(self.fixture.adopter, self.fixture.trees), (True, []))
        again, rerender = self.fixture.composed()
        self.assertEqual(doc['deltas'], again['deltas'])
        self.assertEqual(rendered, rerender)

    def test_next_source_transition_advances_history_then_replays(self):
        self.fixture.git('tag', '-d', 'cve/v1.0.0')
        first, output = self.fixture.composed()
        self.save(first, output)
        self.fixture.tag('v1.0.0', '2026-09-01')
        closed, output = self.fixture.composed()
        self.assertEqual([d['kind'] for d in closed['deltas']], ['closed-untagged-pin'])
        self.save(closed, output)
        again, _ = self.fixture.composed()
        self.assertEqual(closed['deltas'], again['deltas'])
        self.assertEqual(ct.verify(self.fixture.adopter, self.fixture.trees), (True, []))

    def test_malformed_history_and_changed_replay_inputs_refuse(self):
        import yaml
        doc, output = self.fixture.composed()
        self.save(doc, output)
        path = self.fixture.adopter / 'composed/HEADER.yaml'
        original = path.read_text()
        for bad in (None, {}, {'schema': True, 'after': 'a'*64, 'before': {}}):
            header = yaml.safe_load(original)
            header['comparison-inputs'] = bad
            path.write_text(yaml.safe_dump(header))
            result, rendered = ct.compose(self.fixture.adopter, self.fixture.trees)
            self.assertEqual(result['outcome'], 'refused')
            self.assertIn('invalid comparison history', str(result))
            self.assertEqual(rendered, {})
        path.write_text(original)
        party = self.fixture.adopter / 'party.yaml'
        party.write_text(party.read_text() + '\n# new source state\n')
        self.assertFalse(ct.verify(self.fixture.adopter, self.fixture.trees)[0])

    def test_legacy_refresh_records_existing_state_without_inventing_lost_transition(self):
        import yaml
        self.fixture.git('tag', '-d', 'cve/v1.0.0')
        doc, output = self.fixture.composed()
        self.save(doc, output)
        path = self.fixture.adopter / 'composed/HEADER.yaml'
        header = yaml.safe_load(path.read_text())
        del header['comparison-inputs']
        path.write_text(yaml.safe_dump(header))
        self.assertFalse(ct.verify(self.fixture.adopter, self.fixture.trees)[0])
        refreshed, output = self.fixture.composed()
        self.assertEqual(refreshed['deltas'], [])
        self.save(refreshed, output)
        self.assertEqual(ct.verify(self.fixture.adopter, self.fixture.trees), (True, []))

    def test_control_and_namespace_changes_retain_their_original_comparison(self):
        import yaml
        doc, output = self.fixture.composed()
        self.save(doc, output)
        path = self.fixture.adopter / 'party.yaml'
        party = yaml.safe_load(path.read_text())
        party['baseline'] = 'BIG'
        pin = self.fixture.adopter / 'gitops/apps/nist-pin-configmap.yaml'
        pin.write_text(pin.read_text().replace('SMALL', 'BIG'))
        path.write_text(yaml.safe_dump(party))
        ns = self.fixture.adopter / 'workload.yaml'
        ns.write_text(yaml.safe_dump({'apiVersion':'v1', 'kind':'Namespace',
            'metadata':{'name':'new-space', 'labels':{'policy-as-versioned.dev/institution':'fixture-adopter'}}}))
        changed, output = self.fixture.composed()
        kinds = [d['kind'] for d in changed['deltas']]
        self.assertIn('baseline-widening', kinds)
        self.assertIn('new-hole', kinds)
        self.assertIn('new-ungoverned-namespace', kinds)
        self.save(changed, output)
        again, _ = self.fixture.composed()
        self.assertEqual(changed['deltas'], again['deltas'])
        self.assertEqual(ct.verify(self.fixture.adopter, self.fixture.trees), (True, []))

    def test_publisher_version_comparison_survives_save_and_replay(self):
        import yaml
        doc, output = self.fixture.composed()
        self.save(doc, output)
        path = self.fixture.adopter / 'party.yaml'
        party = yaml.safe_load(path.read_text())
        next(e for e in party['inherits'] if e.get('name') == 'cve')['version'] = 'v2'
        path.write_text(yaml.safe_dump(party))
        changed, output = self.fixture.composed()
        feed = next(p for p in changed['prices'] if p['kind'] == 'feed')
        self.assertEqual(feed['old_version'], 'v1')
        self.save(changed, output)
        again, _ = self.fixture.composed()
        self.assertEqual(feed, next(p for p in again['prices'] if p['kind'] == 'feed'))
        self.assertEqual(ct.verify(self.fixture.adopter, self.fixture.trees), (True, []))

    def test_corrupt_recorded_inputs_refuse_instead_of_bootstrapping(self):
        doc, output = self.fixture.composed()
        self.save(doc, output)
        for relative, broken in (('composed/HEADER.yaml', '[unterminated'),
                                 ('composed/evidence.json', '{broken')):
            path = self.fixture.adopter / relative
            original = path.read_text()
            path.write_text(broken)
            result, rendered = ct.compose(self.fixture.adopter, self.fixture.trees)
            self.assertEqual(result['outcome'], 'refused')
            self.assertEqual(rendered, {})
            self.assertFalse(ct.verify(self.fixture.adopter, self.fixture.trees)[0])
            path.write_text(original)

    def test_already_replayable_legacy_artefact_keeps_legacy_verification(self):
        import yaml
        doc, output = self.fixture.composed()
        header = yaml.safe_load(output['composed/HEADER.yaml'].split(ct.HEADER_COMMENT)[-1])
        del header['comparison-inputs']
        output['composed/HEADER.yaml'] = ct.HEADER_COMMENT + yaml.safe_dump(header, **ct.YAML_KWARGS)
        self.save(doc, output)
        self.assertEqual(ct.verify(self.fixture.adopter, self.fixture.trees), (True, []))

    def test_restatement_cage_transition_replays_then_advances_on_next_source_edit(self):
        import yaml
        member = self.fixture.trees['fixture-platform'] / 'distribution/policies/v1.0.0/member-a.yaml'
        member.write_text(member.read_text().replace('Audit', 'Deny'))
        path = self.fixture.adopter / 'party.yaml'
        party = yaml.safe_load(path.read_text())
        party['overlay']['restate'] = [{'name':'member-a', 'version':'1.0.0', 'action':'Audit',
            'scenario':'policy/scenarios/driftwood-root-residual.json', 'why':'fixture inability'}]
        path.write_text(yaml.safe_dump(party))
        first, output = self.fixture.composed()
        self.assertTrue(first['cages'][0]['changed'])
        self.save(first, output)
        again, _ = self.fixture.composed()
        self.assertEqual(first['cages'], again['cages'])
        self.assertEqual(ct.verify(self.fixture.adopter, self.fixture.trees), (True, []))
        path.write_text(path.read_text() + '\n# subsequent source edit\n')
        changed, output = self.fixture.composed()
        self.assertFalse(changed['cages'][0]['changed'])
        self.save(changed, output)
        self.assertEqual(ct.verify(self.fixture.adopter, self.fixture.trees), (True, []))
