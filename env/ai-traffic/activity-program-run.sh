#!/usr/bin/env bash
set -euo pipefail
run=${1:?provide a unique run name}
[[ "$run" =~ ^[a-zA-Z0-9_-]+$ ]] || exit 2
test -d "/evidence/$run"
test ! -e "/evidence/$run/result.json"
export ICAP_RESULT="/evidence/$run/result.json"
export TAO_TEST_PATH=/work/activity_program_suite.py
if [[ "${ACTIVITY_COMBINED:-0}" == 1 ]]; then
    export TAO_TEST_PATH=/work/activity_combined_suite.py
fi
if [[ "${ACTIVITY_TLS_MODE:-0}" == 1 ]]; then
    export TAO_TEST_PATH=/work/tls_mode_suite.py
fi
export ICAP_SUITE=activity-program
export PYTHONPATH="/work:${PYTHONPATH:-}"
export TAO_OUTPUT_FILE="/evidence/$run/tao.xml"
export TAO_TIME_OUT=240
export TAO_LOG_DISPLAY=all TAO_LOG_LEVEL=INFO
export CONFIG_SERVER_DPC_RAISE_ON_ERROR=false
set +e
tao_runner >"/evidence/$run/tao.log" 2>&1
status=$?
printf '%s\n' "$status" >"/evidence/$run/exit-status"
if [[ "$status" == 0 ]]; then
    python3 /work/icap_check_result.py "/evidence/$run"
    status=$?
fi
printf '%s\n' "$status" >"/evidence/$run/checked-exit-status"
exit "$status"
