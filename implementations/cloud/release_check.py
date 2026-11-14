#!/usr/bin/env python3
"""Cloud-only release preflight; no tag, commit or network operation occurs."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import yaml
from trigger import find
from replay import replay


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hub', type=Path, required=True)
    parser.add_argument('--record', required=True)
    parser.add_argument('--version', required=True)
    args = parser.parse_args()
    package = Path(__file__).resolve().parent
    descriptor = yaml.safe_load((package / 'package.yaml').read_text())
    if not re.fullmatch(r'\d+\.\d+\.\d+', args.version) or descriptor['version'] != args.version or (package / 'VERSION').read_text().strip() != args.version:
        raise ValueError('tag, package descriptor and VERSION disagree')
    trigger = find(args.hub, args.record)
    if trigger is None:
        raise ValueError('no citable modern step-4 PASS: cloud release remains prepared')
    tag = 'cloud/v' + args.version
    repository = package.parents[1]
    if subprocess.run(['git', '-C', str(repository), 'rev-parse', '--verify', 'refs/tags/' + tag], capture_output=True).returncode == 0:
        raise ValueError('cloud tag already exists; a published tag is frozen')
    engines = Path(os.environ['KYVERNO_ENGINE_DIR'])
    cells = []
    for engine in descriptor['tested_engines']:
        result = replay(str(engines / engine / 'kyverno'), package)
        if result['engine'] != engine:
            raise ValueError('local engine slot does not hold ' + engine)
        cells.append(result)
    print(json.dumps({'tag': tag, 'trigger': trigger, 'cells': cells, 'proof_boundary': descriptor['proof_boundary']}, indent=2))


if __name__ == '__main__':
    main()
