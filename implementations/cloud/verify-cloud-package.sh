#!/usr/bin/env bash
# A self-proof over real CEL. Live admission is the separate hub check.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="${CLOUD_PYTHON:-python3}"
"$PY" - "$HERE" <<'PY'
import os
from pathlib import Path
import shutil
import sys
sys.path.insert(0, sys.argv[1])
import yaml
from replay import replay
package = Path(sys.argv[1])
declared = yaml.safe_load((package / 'package.yaml').read_text())['tested_engines']
engine_dir = os.environ.get('KYVERNO_ENGINE_DIR')
for engine in declared:
    binary = str(Path(engine_dir) / engine / 'kyverno') if engine_dir else shutil.which('kyverno')
    if not binary or not Path(binary).is_file():
        raise SystemExit('FAIL: no local binary for declared cloud engine ' + engine)
    result = replay(binary, package)
    if result['engine'] != engine:
        raise SystemExit('FAIL: cloud engine slot ' + engine + ' holds ' + result['engine'])
    print(result)
print('PASS: cloud CEL replay and idempotency on every declared engine; offline mapping is not vendor-schema or admission evidence')
PY
