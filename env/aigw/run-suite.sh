#!/usr/bin/env bash
# Run inside the fixture container: one Tao test, both reports must pass.
set -euo pipefail
run=${1:?provide a unique run name}
[[ "$run" =~ ^[a-zA-Z0-9_-]+$ ]] || exit 2
mkdir "/evidence/$run"
export AIGW_RESULT="/evidence/$run/result.json"
export ICAP_RESULT="$AIGW_RESULT"
export TAO_TEST_PATH=/work/${AIGW_SUITE:-aigw_smoke_suite.py}
export PYTHONPATH="/work:${PYTHONPATH:-}"
export TAO_OUTPUT_FILE="/evidence/$run/tao.xml"
export TAO_TIME_OUT=240 TAO_LOG_DISPLAY=all TAO_LOG_LEVEL=INFO
export CONFIG_SERVER_DPC_RAISE_ON_ERROR=false
set +e
tao_runner >"/evidence/$run/tao.log" 2>&1
status=$?
set -e
echo "$status" >"/evidence/$run/exit-status"
if [[ "$status" == 0 ]]; then
    python3 /work/icap_check_result.py "/evidence/$run"
fi
exit "$status"
