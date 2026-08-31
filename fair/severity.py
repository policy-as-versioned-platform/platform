#!/usr/bin/env python3
"""severity.py — a lognormal body spliced to a generalised-Pareto tail.

Ticket 08 decision 7 says, verbatim: "When a payload supplies `lm` as
`{model: lognormal-gpd, mu, sigma, u, xi, beta}`, `fair.py` dispatches to
`twin/severity.py` and `tail` names it."

It lives here, not at `twin/severity.py`, because `twin/` is a python package in
the HUB repo and `fair.py` runs inside the `platform` repo: the two are separate
GitHub repos with no dependency between them, so `import twin.severity` from
`fair.py` is not an import that can ever resolve. The seam the ticket wanted is
the *payload* crossing (the twin emits `lm` as a severity spec, ADR-0021), not a
shared python module. The spec crosses as JSON; the sampler lives beside the
engine that consumes it.

Model. Below the threshold `u` the magnitude of one loss event is lognormal
(mu, sigma) on the log scale. The lognormal mass above `u` is replaced by
`u + GPD(xi, beta)` — the peaks-over-threshold form, so the tail decays as a
power law with index 1/xi instead of the lognormal's much lighter tail. That is
the whole point of the model: a bounded beta-PERT cannot draw a loss bigger than
its `max`, and a real breach can.

Stdlib only (`random`, `math`), sampled from an rng the caller owns, so the seed
is fair.py's seed and nothing else.
"""
from __future__ import annotations

import math

MODEL = "lognormal-gpd"
_KEYS = ("mu", "sigma", "u", "xi", "beta")


def is_spec(lm):
    """True if this lm is a severity spec rather than a (min, mode, max) triple."""
    return isinstance(lm, dict)


def check(spec):
    """Validate a severity spec, raising ValueError with a plain message. Returns it."""
    if not isinstance(spec, dict):
        raise ValueError("severity spec must be an object, got %r" % (type(spec).__name__,))
    model = spec.get("model")
    if model != MODEL:
        raise ValueError(
            "severity spec: unknown model %r (this engine knows %r)" % (model, MODEL))
    missing = [k for k in _KEYS if k not in spec]
    if missing:
        raise ValueError("severity spec %s: missing %s" % (MODEL, ", ".join(missing)))
    bad = [k for k in _KEYS if not isinstance(spec[k], (int, float)) or isinstance(spec[k], bool)]
    if bad:
        raise ValueError("severity spec %s: %s must be numbers" % (MODEL, ", ".join(bad)))
    if spec["sigma"] <= 0:
        raise ValueError("severity spec %s: sigma must be > 0, got %r" % (MODEL, spec["sigma"]))
    if spec["beta"] <= 0:
        raise ValueError("severity spec %s: beta must be > 0, got %r" % (MODEL, spec["beta"]))
    if spec["u"] <= 0:
        raise ValueError("severity spec %s: u (the threshold) must be > 0, got %r"
                         % (MODEL, spec["u"]))
    # ponytail: xi >= 0 only (heavy or exponential tail). A negative xi is a valid
    # GPD with a finite upper bound; allow it when a publisher actually ships one.
    if spec["xi"] < 0:
        raise ValueError("severity spec %s: xi must be >= 0, got %r" % (MODEL, spec["xi"]))
    return spec


def sample(spec, n, rng):
    """Sample n loss magnitudes: lognormal below u, u + GPD(xi, beta) above it."""
    check(spec)
    mu, sigma = float(spec["mu"]), float(spec["sigma"])
    u, xi, beta = float(spec["u"]), float(spec["xi"]), float(spec["beta"])
    out = []
    for _ in range(n):
        x = math.exp(mu + sigma * rng.gauss(0.0, 1.0))
        if x > u:  # over the threshold: redraw the excess from the Pareto tail
            v = rng.random()
            excess = -beta * math.log1p(-v) if xi == 0 else beta / xi * ((1.0 - v) ** -xi - 1.0)
            x = u + excess
        out.append(x)
    return out
