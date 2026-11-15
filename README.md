# platform

The owner's sentence: "quantified risk and a reactive ratcheting process cage to mitigate the quantified risk until the risk is within financial tolerance of the organisation".

This repository holds the loop that does that, the cage it moves, and the proof that the cage works. Licence: [Apache-2.0](LICENSE).

## What the loop is

In one cycle `loop/probe.py` tests each capability on a live connection, and `loop/loop.py cycle` prices the rows that are still open, adds the running cost of the rung, compares that figure with the tolerance and holds or moves the rung one notch. It writes one ledger line whatever the verdict, and if the probe cannot measure, the verdict is `could-not-look` and nothing moves.

`loop.py check-diff` says whether a diff is one notch of the rung line, or pin lines only. `loop.py bump-pins` follows ico and feeds with `git ls-remote`. It never moves the platform pin: the loop's own code changes only by a pull request in the adopter.

An adopter's workflow checks this repository out at a pinned, signed tag and its commit and runs these scripts. A tag names a release of this repository; `policy-version` in `cage/` is the cage's own version and moves only when the cage's behaviour changes.

The whole design is in `LOOP.md` in the [hub](https://github.com/policy-as-versioned-flux/policy-as-versioned-flux). Section numbers in code comments are those of `.scratch/distil/CONTRACT.md` in the hub.

## Where things are

| Path | What it holds |
|---|---|
| `loop/` | `loop.py`, `probe.py` and their tests. Python 3.10 or later, standard library only |
| `cage/cage-tier.yaml` | The policy that rewrites a pod. What a rung does to a pod is read there |
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

This needs docker, `kubectl`, `curl`, `sha256sum` and kind 0.32.0. On Linux `up.sh` downloads kind itself. It builds a kind cluster named `loop` and downloads Kyverno 1.18.2. `proof.sh` then makes three runs of the probe and the loop: the cage with no network rule, the cage with its network rule, and the rule deleted. It is green only if the figure follows what is measured in all three.
