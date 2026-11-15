# platform

The owner's sentence: "quantified risk and a reactive ratcheting process cage to mitigate the quantified risk until the risk is within financial tolerance of the organisation".

This repository holds the loop that does that, the cage it moves, and the proof that the cage works. Licence: [Apache-2.0](LICENSE).

## What the loop is

In one cycle `loop/probe.py` tests each capability on a live connection, and `loop/loop.py cycle` prices every row of the party, sums the rows that are still open into the exposure, adds the running cost of the rung, compares that figure with the tolerance and holds or moves the rung one notch. It writes one ledger line whatever the verdict, and if the probe cannot measure, the verdict is `could-not-look` and nothing moves.

`loop.py check-diff` says whether a diff is one notch of the rung line, or pin lines only. `loop.py bump-pins` follows ico and feeds with `git ls-remote`. It never moves the platform pin: the loop's own code changes only by a pull request in the adopter.

An adopter's workflow checks this repository out at a pinned, signed tag and its commit and runs these scripts. A tag names a release of this repository, and `policy-version` in `cage/` is the cage's version. Cage 8.0.2 is carried by tag `policy/v8.0.2`. From now on, when the cage's rules change, the cage takes the version of the tag that carries it. Nothing checks this: whoever changes a rule in `cage/` moves the version in both cage files, `harness/fixture/apps/shop.yaml` and the adopter's pods to the new tag's. The unit tests check only that the copies in this repository agree with each other.

`LOOP.md` in the [hub](https://github.com/policy-as-versioned-flux/policy-as-versioned-flux) says what the loop does now. The full design is `.scratch/distil/CONTRACT.md` there, and section numbers in code comments are its.

## Where things are

| Path | What it holds |
|---|---|
| `loop/` | `loop.py`, `probe.py` and their tests. Standard library only |
| `cage/cage-tier.yaml` | The policy that rewrites a pod when it is created. On an update it sets the two labels only, because Kubernetes will not change a running pod's limits or capabilities. It acts on pods, not on pod controllers: a controller's pods are caged when they are created. What a rung does to a pod is read there |
| `cage/cage-netpol.yaml` | The policy that writes the network rules |
| `cage/rungs.json` | The ladder: what each rung closes, and what it costs a year |
| `harness/` | `up.sh` builds a kind cluster. `proof.sh` runs the proof on it. `fixture/` is the test party |

## Run the tests

```sh
python3 -m unittest discover -s loop -p 'test_*.py' -v
```

They need no network, no cluster and no installed package.

## Run the proof

```sh
bash harness/up.sh cage harness/fixture/apps --no-netpol
bash harness/proof.sh
```

This needs docker, `kubectl`, `curl`, `sha256sum` and kind 0.32.0. On Linux `up.sh` downloads kind itself. It builds a kind cluster named `loop` and downloads Kyverno 1.18.2. `proof.sh` then makes four runs of the probe and the loop: the cage with no network rule, the cage with its network rule, the rule deleted, and a climb in place. In the climb a pod created at `baseline` keeps running while the Namespace moves to `quarantine`; one update to the pod moves its label and brings back its network rule, with no restart. It is green only if the ledger line of each of the four runs says what it should (the figure follows what is measured), the rule `cage-reach-isolated` exists after run 2, every step of the climb holds, Kyverno has made no rewrite of the cage for pod controllers, a pod that asks for the host and for privilege comes back on its rung and without them from server-side dry runs in `fixture` and in `cage-check` (a Namespace that is not governed, so the pod falls to `isolated`), and a pod in `cage-check` that claims no cage version makes the cage write no rule.

A pod moved to another rung in place keeps the limits and capabilities it was created with until it is replaced.
