"""Authored request/reply bytes; repeated IDs do not imply an association."""
import json

# name, literal value, expected status, kind and bytes (before truncation).
# fmt: off
VALUES = [
    ('number', '1', 1, 2, b'1'),
    ('zero', '0', 1, 2, b'0'),
    ('negative', '-31', 1, 2, b'-31'),
    ('negative-zero', '-0', 1, 2, b'-0'),
    ('large-integer', '9007199254740993', 1, 2, b'9007199254740993'),
    ('number-64', '9' * 64, 1, 2, b'9' * 64),
    ('number-65', '9' * 65, 4, 0, None),
    ('fraction', '0.125', 1, 2, b'0.125'),
    ('exponent', '1e+3', 1, 2, b'1e+3'),
    ('negative-exponent', '-2.5E-30', 1, 2, b'-2.5E-30'),
    ('string-number', '"1"', 1, 1, b'1'),
    ('empty-string', '""', 1, 1, b''),
    ('escaped-value', '"future\\u002eid"', 1, 1, b'future\\u002eid'),
    ('escaped-quote', '"a\\"b"', 1, 1, b'a\\"b'),
    ('unicode', '"資料"', 1, 1, '資料'.encode()),
    ('string-63', '"' + 'x' * 63 + '"', 1, 1, b'x' * 63),
    ('string-64', '"' + 'x' * 64 + '"', 1, 1, b'x' * 64),
    ('string-65', '"' + 'x' * 65 + '"', 2, 1, b'x' * 65),
    ('null', 'null', 1, 3, b'null'),
    ('true', 'true', 10, 0, None),
    ('false', 'false', 10, 0, None),
    ('object', '{"private":"value"}', 10, 0, None),
    ('array', '[1,2]', 10, 0, None),
    ('missing', None, 8, 0, None),
    ('reused-a', '"shared"', 1, 1, b'shared'),
    ('reused-b', '"shared"', 1, 1, b'shared'),
]
SPECIAL = [
    ('duplicate', '{"id":1,"id":2,"method":"tools/list"}', '{"id":1,"id":2,"result":{}}', (11, 0, None), (11, 0, None)),
    ('duplicate-equal', '{"id":1,"id":1,"method":"tools/list"}', '{"id":1,"id":1,"result":{}}', (11, 0, None), (11, 0, None)),
    ('nested-only', '{"method":"tools/list","params":{"id":"private"}}', '{"result":{"id":"private"}}', (8, 0, None), (8, 0, None)),
    ('nested-decoy', '{"params":{"id":"private"},"id":"visible","method":"tools/list"}', '{"result":{"id":"private"},"id":"visible"}', (1, 1, b'visible'), (1, 1, b'visible')),
    ('escaped-key', '{"\\u0069d":1,"method":"tools/list"}', '{"\\u0069d":1,"result":{}}', (8, 0, None), (8, 0, None)),
    ('root-budget', '{"id":1,"a":0,"b":0,"c":0,"d":0}', '{"id":1,"a":0,"b":0,"c":0,"d":0}', (5, 0, None), (5, 0, None)),
    ('root-array', '[{"id":1}]', '[{"id":1}]', (4, 0, None), (4, 0, None)),
    ('type-mismatch', '{"id":1,"method":"tools/list"}', '{"id":"1","result":{}}', (1, 2, b'1'), (1, 1, b'1')),
    ('value-mismatch', '{"id":"sent","method":"tools/list"}', '{"id":"other","result":{}}', (1, 1, b'sent'), (1, 1, b'other')),
]
# fmt: on


def cases():
    """Return exact wire bytes and expected observations for each interval."""
    result = []
    for name, literal, status, kind, value in VALUES:
        member = "" if literal is None else '"id":' + literal + ","
        request = '{"jsonrpc":"2.0",' + member + '"method":"tools/list","params":{}}'
        reply = '{"jsonrpc":"2.0",' + member + '"result":{}}'
        expected = (status, kind, value)
        result.append((name, request.encode(), reply.encode(), expected, expected))
    for name, request, reply, request_expected, reply_expected in SPECIAL:
        result.append(
            (name, request.encode(), reply.encode(), request_expected, reply_expected)
        )
    for _, request, reply, _, _ in result:
        json.loads(request)
        json.loads(reply)
    return result


def write_native(path):
    """Encode test inputs and independent expectations for the native harness."""
    with path.open("x") as output:
        for _, request, reply, request_expected, reply_expected in cases():
            for body, expected in (
                (request, request_expected),
                (reply, reply_expected),
            ):
                status, kind, value = expected
                text = "-" if value is None else value.hex() or "_"
                output.write(f"{status} {kind} {text} {body.hex()}\n")
