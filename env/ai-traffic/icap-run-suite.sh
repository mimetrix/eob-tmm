#!/bin/bash
# Run inside the SSA fixture container; preserve each attempt separately.
set -euo pipefail
run=${1:?provide a unique run name}
[[ "$run" =~ ^[a-zA-Z0-9_-]+$ ]] || exit 2
mkdir "/evidence/$run"
export ICAP_RESULT="/evidence/$run/result.json"
export ICAP_SUITE=${2:-baseline}
export PYTHONPATH="/work:${PYTHONPATH:-}"
export TAO_OUTPUT_FILE="/evidence/$run/tao.xml"
export TAO_TEST_PATH=/work/icap_suite.py
if [[ "$ICAP_SUITE" == attribution ]]; then
    export TAO_TEST_PATH=/work/attribution_suite.py
fi
if [[ "$ICAP_SUITE" == configuration ]]; then
    export TAO_TEST_PATH=/work/config_suite.py
fi
if [[ "$ICAP_SUITE" == tutorial ]]; then
    export TAO_TEST_PATH=/work/template_suite.py
fi
if [[ "$ICAP_SUITE" == request-scope ]]; then
    export TAO_TEST_PATH=/work/request_scope_suite.py
fi
if [[ "$ICAP_SUITE" == parser-lifetime ]]; then
    export TAO_TEST_PATH=/work/lifetime_suite.py
fi
if [[ "$ICAP_SUITE" == correlation ]]; then
    export TAO_TEST_PATH=/work/correlation_suite.py
fi
if [[ "$ICAP_SUITE" == metadata ]]; then
    export TAO_TEST_PATH=/work/metadata_suite.py
fi
if [[ "$ICAP_SUITE" == method ]]; then
    export TAO_TEST_PATH=/work/method_suite.py
fi
if [[ "$ICAP_SUITE" == collector ]]; then
    export TAO_TEST_PATH=/work/collector_suite.py
fi
if [[ "$ICAP_SUITE" == collector-container ]]; then
    export TAO_TEST_PATH=/work/collector_container_suite.py
fi
if [[ "$ICAP_SUITE" == token-method ]]; then
    export TAO_TEST_PATH=/work/token_method_suite.py
fi
export TAO_TIME_OUT=210
if [[ "$ICAP_SUITE" == gaps ]]; then
    export TAO_TEST_PATH=/work/gap_suite.py
    export TAO_TIME_OUT=420
fi
export TAO_LOG_DISPLAY=all
export TAO_LOG_LEVEL=INFO
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
