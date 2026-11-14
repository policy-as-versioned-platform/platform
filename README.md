# platform

The owner's sentence: "quantified risk and a reactive ratcheting process cage to mitigate the quantified risk until the risk is within financial tolerance of the organisation".

This repository holds the loop that does that, the cage it moves, and the proof that the cage works. Licence: [Apache-2.0](LICENSE).

## What the loop is

One cycle is one pass:

1. **Sense.** `loop/probe.py` checks that every pod in the governed Namespace is Ready and stamped at the rung in git. It then tests each capability, `egress` and `inbound`, on a live connection.
2. **Price.** `loop/loop.py cycle` prices each row that is still open and adds the running cost of the current rung. The sum is the figure.
3. **Compare and decide.** It compares the figure with the tolerance. It holds, or moves one notch tighter, or moves one notch looser. A notch is one changed line: the rung line of the governed Namespace.
4. **Record.** It writes one JSON line for the ledger, whatever the verdict.

If the probe cannot measure, the verdict is `could-not-look` and nothing moves. If a capability the rung declares closed is measured open, the verdict is `cage-ineffective`.

`loop.py check-diff` says whether a diff is one notch of the rung line, or pin lines only. `loop.py bump-pins` follows the pinned repositories with `git ls-remote`.

An adopter's workflow checks this repository out at a pinned commit and runs these scripts. The whole design is in `LOOP.md` in the [hub](https://github.com/policy-as-versioned-flux/policy-as-versioned-flux).

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
