"""The probe: read the cluster and test each capability on a live connection.

Standard library only. It uses kubectl only, through one injected run function.
It creates and deletes nothing.
"""
import argparse
import json
import re
import subprocess
import sys
import time

GOVERNED = "policy-as-versioned.dev/governed=true"
PROBE = "loop.policy-as-versioned.dev/probe"
CAGED = "posture.acme.io/caged"
TIER = "posture.acme.io/tier"
REFERENCE = "loop-reference"
SNIPPET = ('if command -v bash >/dev/null 2>&1; then timeout 4 bash -c "</dev/tcp/$0/$1" 2>/dev/null; rc=$?; '
           'elif command -v nc >/dev/null 2>&1; then nc -w 4 -z "$0" "$1" 2>/dev/null; rc=$?; '
           'else rc=127; fi; echo loop-probe-rc=$rc')
MARKER = re.compile(r"loop-probe-rc=(\d+)")
SETTLE_SECONDS = 600  # step 3: how long a pod may take to start


class Failed(Exception):
    """A step failed, so the probe could not look."""


def get(run, *args):
    code, out = run(["get", *args, "-o", "json"])
    if code != 0:
        raise Failed(f"kubectl get {' '.join(args)} failed: {(out.strip().splitlines() or ['no output'])[-1]}")
    try:
        return json.loads(out)
    except ValueError:
        raise Failed(f"kubectl get {' '.join(args)} did not answer in JSON") from None


def name(thing):
    return thing["metadata"]["name"]


def labels(thing):
    return thing["metadata"].get("labels") or {}


def ready(pod):
    conditions = pod.get("status", {}).get("conditions") or []
    return any(one["type"] == "Ready" and one["status"] == "True" for one in conditions)


def first_port(pod):
    for container in pod["spec"]["containers"]:
        for port in container.get("ports") or []:
            return port["containerPort"]
    return None


def connect(run, namespace, pod, host, port):
    """One connect from a pod. True is open. The answer is the marker, never kubectl's exit code."""
    _, out = run(["exec", "-n", namespace, pod, "--", "sh", "-c", SNIPPET, str(host), str(port)])
    marker = MARKER.search(out)
    if not marker or marker.group(1) == "127":
        raise Failed(f"the connect from {pod} to {host}:{port} could not run")
    return marker.group(1) == "0"


def settle(run, sleep, namespace, rung, limit, result):
    """Step 3. A pod still starting is waited for. A missing or wrong stamp is judged at once."""
    waited = 0
    while True:
        pods = get(run, "pods", "-n", namespace)["items"]
        result["pods"] = [{"name": name(pod), "ready": ready(pod), "rung": labels(pod).get(TIER)}
                          for pod in pods]
        for pod in pods:
            if labels(pod).get(CAGED) != "true" or labels(pod).get(TIER) != rung:
                raise Failed(f"pod {name(pod)} is not stamped {rung}")
        if all(ready(pod) for pod in pods):
            return pods
        if waited >= limit:
            waiting = ", ".join(name(pod) for pod in pods if not ready(pod))
            raise Failed(f"not Ready after {waited} seconds: {waiting}")
        sleep(5)
        waited += 5


def settled(read, sleep, netpol):
    """Step 9. Settle one reading into "open" or "closed"."""
    is_open = read()
    if is_open and netpol:  # the rule may not be programmed yet
        for _ in range(20):
            sleep(3)
            is_open = read()
            if not is_open:
                break
    if is_open:
        return "open"
    for _ in range(3):  # a reading that is not open must hold
        sleep(3)
        if read():
            return "open"
    return "closed"


def look(run, sleep, settle_seconds, result):
    """Steps 1 to 10 of the contract's 4.2. A step that fails raises Failed."""
    governed = get(run, "namespaces", "-l", GOVERNED)["items"]
    if len(governed) != 1:
        raise Failed(f"{len(governed)} governed Namespaces, not one")
    namespace, rung = name(governed[0]), labels(governed[0]).get(TIER)
    result["rung"] = rung

    policies = [one for one in get(run, "mutatingpolicies.policies.kyverno.io")["items"]
                if name(one).startswith("cage-tier-")]
    if len(policies) != 1:
        raise Failed(f"{len(policies)} cage-tier policies, not one")
    if not policies[0].get("status", {}).get("conditionStatus", {}).get("ready"):
        raise Failed(f"policy {name(policies[0])} is not ready")

    pods = settle(run, sleep, namespace, rung, settle_seconds, result)

    reference = {name(pod): pod for pod in get(run, "pods", "-n", REFERENCE)["items"]}
    for who in ("sink", "client"):
        if who not in reference or not ready(reference[who]):
            raise Failed(f"reference pod {who} is not Ready")
        if CAGED in labels(reference[who]) or TIER in labels(reference[who]):
            raise Failed(f"reference pod {who} carries the cage's stamp")
    if get(run, "networkpolicies", "-n", REFERENCE)["items"]:
        raise Failed(f"a NetworkPolicy exists in {REFERENCE}")
    sink = get(run, "service", "sink", "-n", REFERENCE)["spec"]["clusterIP"]

    probes = [name(pod) for pod in pods if labels(pod).get(PROBE) == "true"]
    if len(probes) != 1:
        raise Failed(f"{len(probes)} probe pods, not one")
    netpol = bool(get(run, "networkpolicies", "-n", namespace)["items"])

    def reference_works():
        for attempt in range(10):
            if attempt:
                sleep(3)
            if connect(run, REFERENCE, "client", sink, 80):
                return True
        return False

    result["reference"] = {"before": reference_works(), "after": None}
    if not result["reference"]["before"]:
        raise Failed("the reference could not connect before the tests")

    egress = settled(lambda: connect(run, namespace, probes[0], sink, 80), sleep, netpol)

    targets = [(pod["status"]["podIP"], first_port(pod)) for pod in pods if first_port(pod)]
    if not targets:
        raise Failed("no governed pod declares a port")
    serving = {"ok": 0, "total": len(targets)}

    def inbound():
        serving["ok"] = sum(connect(run, REFERENCE, "client", host, port) for host, port in targets)
        return serving["ok"] > 0

    inbound_reading = settled(inbound, sleep, netpol)

    result["reference"]["after"] = reference_works()
    if not result["reference"]["after"]:
        raise Failed("the reference could not connect after the tests")
    result["capabilities"] = {"egress": egress, "inbound": inbound_reading}
    result["serving"] = serving


def measure(run, sleep, settle_seconds):
    """Look at the cluster. `run(args) -> (code, output)` is the only way to reach it."""
    result = {"looked": False, "why": "", "rung": None, "pods": [],
              "capabilities": None, "reference": None, "serving": None}
    try:
        look(run, sleep, settle_seconds, result)
        result["looked"] = True
    except Failed as failure:
        result["why"] = str(failure)
    except (LookupError, TypeError, AttributeError) as error:
        result["why"] = f"an answer from kubectl had an unexpected shape: {error!r}"
    return result


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--context", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)

    def run(kubectl_args):
        command = ["kubectl", "--context", args.context, "--request-timeout=30s", *kubectl_args]
        try:
            done = subprocess.run(command, capture_output=True, text=True, timeout=120)
        except (OSError, subprocess.SubprocessError) as error:
            return 127, str(error)
        return done.returncode, done.stdout if done.returncode == 0 else done.stdout + done.stderr

    result = measure(run, time.sleep, SETTLE_SECONDS)
    text = json.dumps(result)
    with open(args.out, "w", encoding="utf-8") as handle:
        handle.write(text + "\n")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
