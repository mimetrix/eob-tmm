"""Authored JSON messages and expected observations; not a protocol validator."""

# status, result presence, error presence, code state, code, isError state/value.
# fmt: off
CASES = [
    ('result', '{"jsonrpc":"2.0","id":1,"result":{}}', (1, 1, 0, 0, 0, 7, 0)),
    ('tool-true', '{"result":{"isError":true}}', (1, 1, 0, 0, 0, 1, 1)),
    ('tool-false', '{"result":{"isError":false}}', (1, 1, 0, 0, 0, 1, 0)),
    ('tool-null', '{"result":{"isError":null}}', (1, 1, 0, 0, 0, 10, 0)),
    ('tool-string', '{"result":{"isError":"false"}}', (1, 1, 0, 0, 0, 10, 0)),
    ('tool-number', '{"result":{"isError":0}}', (1, 1, 0, 0, 0, 10, 0)),
    ('result-null', '{"result":null}', (1, 1, 0, 0, 0, 10, 0)),
    ('result-array', '{"result":[]}', (1, 1, 0, 0, 0, 10, 0)),
    ('error-negative', '{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"private"}}', (1, 0, 1, 1, -32601, 0, 0)),
    ('error-zero', '{"error":{"code":0}}', (1, 0, 1, 1, 0, 0, 0)),
    ('error-unfamiliar', '{"error":{"code":7654321}}', (1, 0, 1, 1, 7654321, 0, 0)),
    ('error-min', '{"error":{"code":-2147483648}}', (1, 0, 1, 1, -2147483648, 0, 0)),
    ('error-max', '{"error":{"code":2147483647}}', (1, 0, 1, 1, 2147483647, 0, 0)),
    ('error-overflow', '{"error":{"code":2147483648}}', (1, 0, 1, 4, 0, 0, 0)),
    ('error-underflow', '{"error":{"code":-2147483649}}', (1, 0, 1, 4, 0, 0, 0)),
    ('error-fraction', '{"error":{"code":1.5}}', (1, 0, 1, 4, 0, 0, 0)),
    ('error-exponent', '{"error":{"code":1e3}}', (1, 0, 1, 4, 0, 0, 0)),
    ('error-string', '{"error":{"code":"-32601"}}', (1, 0, 1, 10, 0, 0, 0)),
    ('error-null', '{"error":{"code":null}}', (1, 0, 1, 4, 0, 0, 0)),
    ('error-missing', '{"error":{"message":"private"}}', (1, 0, 1, 7, 0, 0, 0)),
    ('error-array', '{"error":[]}', (1, 0, 1, 10, 0, 0, 0)),
    ('nested-code', '{"error":{"data":{"code":123}}}', (1, 0, 1, 7, 0, 0, 0)),
    ('nested-tool', '{"result":{"content":{"isError":true}}}', (1, 1, 0, 0, 0, 7, 0)),
    ('nested-decoy', '{"result":{"content":{"isError":true},"isError":false}}', (1, 1, 0, 0, 0, 1, 0)),
    ('duplicate-code', '{"error":{"code":0,"code":1}}', (1, 0, 1, 11, 0, 0, 0)),
    ('duplicate-tool', '{"result":{"isError":true,"isError":false}}', (1, 1, 0, 0, 0, 11, 0)),
    ('both', '{"result":{},"error":{"code":-1}}', (11, 0, 0, 0, 0, 0, 0)),
    ('duplicate-result', '{"result":{},"result":{}}', (11, 0, 0, 0, 0, 0, 0)),
    ('duplicate-error', '{"error":{"code":1},"error":{"code":2}}', (11, 0, 0, 0, 0, 0, 0)),
    ('method-result', '{"method":"tools/call","result":{}}', (11, 0, 0, 0, 0, 0, 0)),
    ('neither', '{"jsonrpc":"2.0","id":1}', (0, 0, 0, 0, 0, 0, 0)),
    ('request', '{"method":"tools/call","params":{"result":{"isError":true}}}', (0, 0, 0, 0, 0, 0, 0)),
    ('escaped-root', '{"res\\u0075lt":{"isError":true}}', (0, 0, 0, 0, 0, 0, 0)),
    ('escaped-code', '{"error":{"co\\u0064e":-1}}', (1, 0, 1, 7, 0, 0, 0)),
    ('escaped-tool', '{"result":{"is\\u0045rror":true}}', (1, 1, 0, 0, 0, 7, 0)),
    ('root-budget', '{"result":{},"a":0,"b":0,"c":0,"d":0}', (5, 0, 0, 0, 0, 0, 0)),
    ('field-budget', '{"error":{"code":-1,"a":0,"b":0,"c":0,"d":0}}', (1, 0, 1, 5, 0, 0, 0)),
    ('root-array', '[{"result":{}}]', (10, 0, 0, 0, 0, 0, 0)),
]
# fmt: on


def write_native(path):
    """Write independent expected fields and exact input bytes for the C harness."""
    with path.open("x") as output:
        for _, body, expected in CASES:
            output.write(
                " ".join(map(str, expected)) + " " + body.encode().hex() + "\n"
            )
