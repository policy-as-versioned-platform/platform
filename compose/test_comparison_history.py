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


class OptionalHeaderField(unittest.TestCase):
    """Eco-system ticket 123: `overlay-controls` is carried only where the
    recorded header carries it. Absent means the header predates the field,
    which is not the same fact as an empty overlay."""

    HEADER = {'parents': [], 'baseline': 'SMALL', 'holes': [], 'selected-controls': ['aa-1'],
              'ungoverned-namespaces': []}

    def test_a_header_without_the_field_projects_without_it(self):
        import comparison_history as ch
        before = ch.project(dict(self.HEADER), [], [])
        self.assertNotIn('overlay-controls', before['header'])

    def test_a_header_with_the_field_projects_it_even_when_empty(self):
        import comparison_history as ch
        for overlay in ([], ['aa-3']):
            before = ch.project({**self.HEADER, 'overlay-controls': overlay}, [], [])
            self.assertEqual(before['header']['overlay-controls'], overlay)

    def test_a_malformed_field_or_an_unknown_one_refuses(self):
        import comparison_history as ch
        for header in ({**self.HEADER, 'overlay-controls': [1]}, {**self.HEADER, 'other': []},
                       {**self.HEADER, 'withdrawn-selectable': 'false'},
                       {**self.HEADER, 'withdrawn-selectable': []}):
            with self.assertRaises(ch.InvalidHistory):
                ch._validate({'header': header, 'prices': [], 'cages': []})

    def test_withdrawn_selectable_is_a_boolean_carried_only_where_recorded(self):
        """Eco-system ticket 126: `withdrawn-selectable: false` says the header's
        selection admitted only ids its catalogue defines. Absent means an older
        composer, which is not the same fact as false."""
        import comparison_history as ch
        self.assertNotIn('withdrawn-selectable', ch.project(dict(self.HEADER), [], [])['header'])
        before = ch.project({**self.HEADER, 'withdrawn-selectable': False}, [], [])
        self.assertIs(before['header']['withdrawn-selectable'], False)


def _after(rendered):
    import yaml
    header = yaml.safe_load(rendered['composed/HEADER.yaml'].split(ct.HEADER_COMMENT)[-1])
    return header['comparison-inputs']['after']


class ObservationLane(unittest.TestCase):
    """Eco-system ticket 134. A clock appends observations to the paths its
    workflow declares as OBSERVATION_LANE (ADR-0023). Those files are not
    source, so appending to them must not start a new comparison."""

    def setUp(self):
        self.fixture = fixtures.PortableObservations()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.adopter = self.fixture.adopter
        workflows = self.adopter / '.github/workflows'
        workflows.mkdir(parents=True)
        # Quoted and unquoted, a file and a directory: the adopters use all four.
        (workflows / 'drift-sample.yml').write_text(
            'on: {schedule: [{cron: "7 5 * * *"}]}\n'
            'env:\n  OBSERVATION_LANE: "drift/samples.jsonl"\n'
            'jobs:\n  sample:\n    runs-on: ubuntu-latest\n    steps: [{run: "true"}]\n')
        (workflows / 'twin-sweep.yml').write_text(
            'on: {schedule: [{cron: "5 7 * * *"}]}\n'
            'jobs:\n  sweep:\n    runs-on: ubuntu-latest\n'
            '    env:\n      OBSERVATION_LANE: observations\n    steps: [{run: "true"}]\n')
        for relative in ('drift/samples.jsonl', 'observations/twin-sweep.jsonl'):
            path = self.adopter / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('{"day": 1}\n')

    def append(self, relative, line='{"day": 2}\n'):
        path = self.adopter / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('a') as handle:
            handle.write(line)

    def test_a_lane_append_leaves_the_identity_and_verification_unchanged(self):
        doc, rendered = self.fixture.composed()
        self.fixture.save(rendered)
        (self.adopter / 'composed/evidence.json').write_text(json.dumps(doc))
        for relative in ('drift/samples.jsonl', 'observations/twin-sweep.jsonl',
                         'observations/a-new-capture.jsonl'):
            with self.subTest(lane=relative):
                self.append(relative)
                again, rerender = self.fixture.composed()
                self.assertEqual(_after(rendered), _after(rerender))
                self.assertEqual(rendered, rerender)
                self.assertEqual(ct.verify(self.adopter, self.fixture.trees), (True, []))

    def test_a_party_edit_changes_the_identity(self):
        _, rendered = self.fixture.composed()
        self.fixture.save(rendered)
        party = self.adopter / 'party.yaml'
        party.write_text(party.read_text() + '\n# a declaration moved\n')
        _, rerender = self.fixture.composed()
        self.assertNotEqual(_after(rendered), _after(rerender))
        self.assertFalse(ct.verify(self.adopter, self.fixture.trees)[0])

    def test_a_source_file_beside_a_lane_file_is_still_source(self):
        _, rendered = self.fixture.composed()
        self.append('drift/five-facts.py', '# the probe changed\n')
        _, rerender = self.fixture.composed()
        self.assertNotEqual(_after(rendered), _after(rerender))

    def test_a_yaml_file_in_a_lane_stays_source_because_the_composer_reads_it(self):
        _, rendered = self.fixture.composed()
        self.append('observations/namespace.yaml',
                    'apiVersion: v1\nkind: Namespace\nmetadata: {name: lane-space}\n')
        _, rerender = self.fixture.composed()
        self.assertNotEqual(_after(rendered), _after(rerender))

    def test_a_changed_lane_declaration_starts_a_new_comparison(self):
        _, rendered = self.fixture.composed()
        workflow = self.adopter / '.github/workflows/drift-sample.yml'
        workflow.write_text(workflow.read_text().replace('drift/samples.jsonl', 'drift'))
        _, rerender = self.fixture.composed()
        self.assertNotEqual(_after(rendered), _after(rerender))

    def test_a_lane_path_outside_the_repository_refuses_by_name(self):
        workflow = self.adopter / '.github/workflows/drift-sample.yml'
        for bad in ('../elsewhere', '/etc', 'composed'):
            with self.subTest(lane=bad):
                workflow.write_text(f'env:\n  OBSERVATION_LANE: "{bad}"\n')
                result, rendered = ct.compose(self.adopter, self.fixture.trees)
                self.assertEqual(result['outcome'], 'refused')
                self.assertIn('OBSERVATION_LANE', str(result))
                self.assertEqual(rendered, {})


class GitAdopter(unittest.TestCase):
    """The portable fixture adopter as a git work tree with one commit."""

    def setUp(self):
        import tempfile
        self.fixture = fixtures.PortableObservations()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.adopter = self.fixture.adopter
        hooks = tempfile.TemporaryDirectory()
        self.addCleanup(hooks.cleanup)
        self.hooks = hooks.name
        self.git('init', '-q')
        doc, rendered = self.fixture.composed()
        self.fixture.save(rendered)
        (self.adopter / 'composed/evidence.json').write_text(json.dumps(doc))
        self.commit('the served artefact')

    def git(self, *args):
        import subprocess
        return subprocess.run(
            ['git', '-C', str(self.adopter), '-c', f'core.hooksPath={self.hooks}',
             '-c', 'commit.gpgsign=false', '-c', 'user.name=fixture',
             '-c', 'user.email=fixture@invalid', *args],
            check=True, capture_output=True, text=True)

    def commit(self, message):
        self.git('add', '--', '.')
        self.git('commit', '-qm', message)

    def new_namespace(self, name='new-space'):
        import yaml
        (self.adopter / 'workload.yaml').write_text(yaml.safe_dump(
            {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': name}}))

    def save(self, doc, rendered):
        self.fixture.save(rendered)
        (self.adopter / 'composed/evidence.json').write_text(json.dumps(doc))

    @staticmethod
    def kinds(doc):
        return sorted(d['kind'] for d in doc['deltas'])



class CommittedBefore(GitAdopter):
    """Eco-system ticket 133. In a git work tree the "before" of a new
    comparison is the committed artefact at HEAD, never whatever a previous
    pass left in the working tree."""

    def test_two_recomposes_in_a_row_give_the_same_deltas_as_one(self):
        self.new_namespace()
        once, rendered = self.fixture.composed()
        self.assertIn('new-ungoverned-namespace', self.kinds(once))
        for _ in range(2):
            self.save(once, rendered)
            again, rerender = self.fixture.composed()
            self.assertEqual(once['deltas'], again['deltas'])
            self.assertEqual(rendered, rerender)

    def test_a_stale_working_tree_before_does_not_hide_a_delta(self):
        # The tuppence rollout (PR 36): a first pass ran on a tree that then
        # changed again before the second pass. The second pass took the first
        # pass's own header as its "before", and the delta disappeared.
        self.new_namespace()
        first, rendered = self.fixture.composed()
        self.assertIn('new-ungoverned-namespace', self.kinds(first))
        self.save(first, rendered)
        readme = self.adopter / 'README.md'
        readme.write_text('an edit after the first pass\n')
        second, _ = self.fixture.composed()
        self.assertEqual(self.kinds(first), self.kinds(second))

    def test_a_half_written_composed_tree_is_not_read_as_the_before(self):
        self.new_namespace()
        clean, rendered = self.fixture.composed()
        (self.adopter / 'composed/HEADER.yaml').write_text('[unterminated')
        dirty, rerender = self.fixture.composed()
        self.assertEqual(clean['deltas'], dirty['deltas'])
        self.assertEqual(rendered, rerender)

    def test_a_committed_recompose_is_the_next_before(self):
        self.new_namespace()
        first, rendered = self.fixture.composed()
        self.save(first, rendered)
        self.commit('recompose')
        self.assertEqual(ct.verify(self.adopter, self.fixture.trees), (True, []))
        again, rerender = self.fixture.composed()
        self.assertEqual(first['deltas'], again['deltas'])
        self.assertEqual(rendered, rerender)
        self.new_namespace('another-space')
        later, _ = self.fixture.composed()
        self.assertEqual(sorted(d.get('namespace') for d in later['deltas']
                                if d['kind'] == 'new-ungoverned-namespace'), ['another-space'])



def v330_identity(adopter, parents, observations, as_of, namespace_facts):
    """platform v3.3.0 (38089a6) compose/comparison_history.py identity(),
    verbatim, so the migration test does not trust the code under test to
    restate the formula it replaces."""
    import hashlib
    import comparison_history as ch
    sources = {}
    for path in sorted(adopter.rglob('*')):
        relative = path.relative_to(adopter)
        if any(part.startswith('.') or part == '__pycache__' for part in relative.parts):
            continue
        if relative.parts[0] == 'composed' or not path.is_file():
            continue
        sources[str(relative)] = hashlib.sha256(path.read_bytes()).hexdigest()
    return ch._digest({'sources': sources, 'parents': parents, 'observations': observations,
                       'as_of': as_of, 'namespace_facts': namespace_facts})


class FormulaMigration(GitAdopter):
    """Eco-system ticket 134. Tools v3.3.0 hashed the lane files too. An
    artefact recorded under that formula is the same comparison under this
    one: verification accepts it as recorded, and a fresh composition keeps
    its before and re-stamps only `after`, even after later lane commits."""

    def v330_artefact(self):
        from unittest import mock
        workflows = self.adopter / '.github/workflows'
        workflows.mkdir(parents=True)
        (workflows / 'drift-sample.yml').write_text('env:\n  OBSERVATION_LANE: "drift/samples.jsonl"\n')
        lane = self.adopter / 'drift/samples.jsonl'
        lane.parent.mkdir()
        lane.write_text('{"day": 1}\n')
        self.new_namespace()
        with mock.patch.object(ct.comparison_history, 'identity', v330_identity):
            doc, rendered = self.fixture.composed()
            self.save(doc, rendered)
            self.commit('recompose under v3.3.0')
            self.assertEqual(ct.verify(self.adopter, self.fixture.trees), (True, []))
        self.assertIn('new-ungoverned-namespace', self.kinds(doc))
        return doc, rendered

    def lane_commit(self):
        with (self.adopter / 'drift/samples.jsonl').open('a') as handle:
            handle.write('{"day": 2}\n')
        self.commit('drift sample')

    def test_verification_accepts_a_v330_record_across_a_lane_commit(self):
        self.v330_artefact()
        self.lane_commit()
        self.assertEqual(ct.verify(self.adopter, self.fixture.trees), (True, []))

    def test_a_fresh_compose_keeps_the_v330_comparison_and_restamps_after(self):
        doc, rendered = self.v330_artefact()
        self.lane_commit()
        again, rerender = self.fixture.composed()
        self.assertEqual(doc['deltas'], again['deltas'])
        self.assertNotEqual(_after(rendered), _after(rerender))
        differs = sorted(k for k in rendered if rendered[k] != rerender.get(k))
        self.assertEqual(differs, ['composed/HEADER.yaml'])
        old = rendered['composed/HEADER.yaml'].replace(_after(rendered), _after(rerender))
        self.assertEqual(old, rerender['composed/HEADER.yaml'])

    def test_a_v330_record_over_a_changed_source_still_starts_a_new_comparison(self):
        self.v330_artefact()
        party = self.adopter / 'party.yaml'
        party.write_text(party.read_text() + '\n# a declaration moved\n')
        self.commit('a source edit')
        self.assertFalse(ct.verify(self.adopter, self.fixture.trees)[0])
        again, _ = self.fixture.composed()
        self.assertNotIn('new-ungoverned-namespace', self.kinds(again))
