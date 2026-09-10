"""Ticket 27 floor effects through the public composition/replay seam."""
import json
import unittest
import yaml
import composition as ct
import test_portable_observations as fixtures


class FloorChange(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.PortableObservations()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def floor(self, value):
        path = self.fixture.adopter / 'party.yaml'
        doc = yaml.safe_load(path.read_text())
        if value is None:
            doc['overlay'].pop('floor', None)
        else:
            doc['overlay']['floor'] = value
        path.write_text(yaml.safe_dump(doc, sort_keys=False))

    def test_lowering_is_visible_without_changing_publisher_comparison(self):
        self.floor('isolated')
        _, rendered = self.fixture.composed()
        self.fixture.save(rendered)
        self.floor('baseline')
        doc, rendered = self.fixture.composed()
        effect = doc['floor_change']
        self.assertEqual(effect['before'], {'known': True, 'value': 'isolated'})
        self.assertEqual(effect['after'], {'known': True, 'value': 'baseline'})
        line = effect['lines'][0]
        self.assertEqual((line['before_tier'], line['after_tier']), ('isolated', 'baseline'))
        self.assertGreater(line['residual_delta'], 0)
        price = next(p for p in doc['prices'] if p['kind'] == 'feed')
        self.assertEqual((price['old_tier'], price['proposed_tier'], price['changed']),
                         ('baseline', 'baseline', False))
        self.assertEqual(price['old_price'], price['new_price'])
        self.assertEqual([d['kind'] for d in doc['deltas']], ['floor-change'])

    def transition(self, before, after):
        self.floor(before)
        _, rendered = self.fixture.composed()
        self.fixture.save(rendered)
        self.floor(after)
        return self.fixture.composed()

    def test_removal_is_known_absence_not_unknown_history(self):
        doc, _ = self.transition('isolated', None)
        effect = doc['floor_change']
        self.assertEqual(effect['after'], {'known': True, 'value': None})
        self.assertTrue(effect['changed'])
        self.assertEqual(effect['lines'][0]['after_tier'], 'baseline')

    def test_tightening_prices_retained_residual_not_uncaged_exposure(self):
        doc, _ = self.transition(None, 'isolated')
        line = doc['floor_change']['lines'][0]
        self.assertEqual((line['before_tier'], line['after_tier']), ('baseline', 'isolated'))
        self.assertAlmostEqual(line['before_residual'], line['uncaged_amount'] * .70)
        self.assertAlmostEqual(line['after_residual'], line['uncaged_amount'] * .02)
        self.assertLess(line['residual_delta'], 0)

    def test_unchanged_floor_has_no_invented_delta_and_missing_history_stays_named(self):
        doc, rendered = self.transition('baseline', 'baseline')
        self.assertIsNone(doc['floor_change']['changed'])
        self.assertEqual(doc['floor_change']['before'], {'known': False})
        self.assertIn('previous floor', doc['floor_change']['could_not_look'])
        self.assertEqual(doc['deltas'], [])
        self.fixture.save(rendered)
        again, rerender = self.fixture.composed()
        self.assertEqual(doc['floor_change'], again['floor_change'])
        self.assertEqual(rendered, rerender)

    def test_floor_change_with_no_selected_tier_change_still_records_zero(self):
        path = self.fixture.adopter / 'party.yaml'
        doc = yaml.safe_load(path.read_text())
        doc['appetite']['tolerance']['amount'] = 1
        path.write_text(yaml.safe_dump(doc))
        changed, _ = self.transition('baseline', 'restricted')
        line = changed['floor_change']['lines'][0]
        self.assertTrue(changed['floor_change']['changed'])
        self.assertEqual((line['before_tier'], line['after_tier']), ('isolated', 'isolated'))
        self.assertEqual(line['residual_delta'], 0)

    def test_publisher_move_is_held_at_current_inputs_for_both_floor_sides(self):
        self.floor('isolated')
        _, rendered = self.fixture.composed()
        self.fixture.save(rendered)
        path = self.fixture.publisher / 'cve/v2/feed.json'
        feed = json.loads(path.read_text())
        feed['payload']['severity_lm_gbp']['high'] = [2000, 4000, 6000]
        path.write_text(json.dumps(feed))
        party = self.fixture.adopter / 'party.yaml'
        doc = yaml.safe_load(party.read_text())
        doc['overlay']['floor'] = 'baseline'
        next(e for e in doc['inherits'] if e.get('name') == 'cve')['version'] = 'v2'
        party.write_text(yaml.safe_dump(doc))
        result, _ = self.fixture.composed()
        price = next(p for p in result['prices'] if p['kind'] == 'feed')
        self.assertNotEqual(price['old_price'], price['new_price'])
        line = result['floor_change']['lines'][0]
        self.assertEqual(line['uncaged_amount'], price['new_price'])
        self.assertAlmostEqual(line['before_residual'], price['new_price'] * .02)
        self.assertAlmostEqual(line['after_residual'], price['new_price'] * .70)

    def test_floor_comparison_survives_save_verify_and_detects_changed_output(self):
        doc, rendered = self.transition('isolated', None)
        self.assertIn('composed/floor-change.json', rendered)
        self.fixture.save(rendered)
        (self.fixture.adopter / 'composed/evidence.json').write_text(json.dumps(doc))
        again, rerender = self.fixture.composed()
        self.assertEqual(doc['floor_change'], again['floor_change'])
        self.assertEqual(rendered, rerender)
        self.assertEqual(ct.verify(self.fixture.adopter, self.fixture.trees), (True, []))
        path = self.fixture.adopter / 'composed/floor-change.json'
        path.write_text('{}')
        ok, differences = ct.verify(self.fixture.adopter, self.fixture.trees)
        self.assertFalse(ok)
        self.assertTrue(any('floor-change.json' in line for line in differences))

    def test_malformed_recorded_history_refuses_instead_of_guessing(self):
        _, rendered = self.transition('isolated', 'baseline')
        self.fixture.save(rendered)
        path = self.fixture.adopter / 'composed/HEADER.yaml'
        header = yaml.safe_load(path.read_text())
        header['floor-comparison']['before'] = {'known': True}
        path.write_text(yaml.safe_dump(header))
        doc, rendered = ct.compose(self.fixture.adopter, self.fixture.trees)
        self.assertEqual(doc['outcome'], 'refused')
        self.assertIn('invalid floor history', str(doc))
        self.assertEqual(rendered, {})

    def test_explicit_null_history_is_invalid_not_an_absent_legacy_record(self):
        _, rendered = self.transition(None, 'isolated')
        self.fixture.save(rendered)
        path = self.fixture.adopter / 'composed/HEADER.yaml'
        header = yaml.safe_load(path.read_text())
        header['floor-comparison'] = None
        path.write_text(yaml.safe_dump(header))
        doc, _ = ct.compose(self.fixture.adopter, self.fixture.trees)
        self.assertEqual(doc['outcome'], 'refused')
        self.assertIn('invalid floor history', str(doc))
