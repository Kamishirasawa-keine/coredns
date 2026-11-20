#!/bin/sh
# Present white-box tests to Go at their original package paths without copying files.
set -eu
cd "$(dirname "$0")/.."
overlay=$(mktemp)
trap 'rm -f "$overlay"' EXIT
python3 - "$overlay" <<'PY'
import json
import sys
from pathlib import Path

mapping = {}
for template in Path('test/whitebox').rglob('*_test.go.txt'):
    relative = template.relative_to('test/whitebox').with_suffix('')
    destination = relative if relative.parent == Path('.') else Path('plugin') / relative
    mapping[str(destination.resolve())] = str(template.resolve())
Path(sys.argv[1]).write_text(json.dumps({'Replace': mapping}))
PY
go test -overlay "$overlay" . ./plugin/...
