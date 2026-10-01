"""Authored request bytes and expected raw target observations."""


def cases():
    rows = []
    for kind, method, key, normal in (
        (1, b"tools/call", b"name", b"inventory.lookup"),
        (2, b"resources/read", b"uri", b"file:///inventory/items"),
    ):
        for label, value in (
            ("known", normal),
            ("unfamiliar", b"future.target:v9"),
            ("escaped", b"future\\u002etarget"),
            ("empty", b""),
            ("limit", b"x" * 64),
            ("truncated", b"y" * 65),
        ):
            body = (
                b'{"jsonrpc":"2.0","id":1,"method":"'
                + method
                + b'","params":{"'
                + key
                + b'":"'
                + value
                + b'"}}'
            )
            rows.append(
                (f"{kind}-{label}", body, 2 if len(value) > 64 else 1, kind, value)
            )
    rows += [
        (
            "params-first",
            b'{"params":{"uri":"file:///first"},"method":"resources/read"}',
            1,
            2,
            b"file:///first",
        ),
        (
            "nested-decoy",
            b'{"method":"tools/call","params":{"arguments":{"name":"private"},"name":"visible"}}',
            1,
            1,
            b"visible",
        ),
        (
            "nested-only",
            b'{"method":"tools/call","params":{"arguments":{"name":"private"}}}',
            11,
            1,
            None,
        ),
        (
            "duplicate-target",
            b'{"method":"tools/call","params":{"name":"first","name":"second"}}',
            1,
            1,
            b"first",
        ),
        (
            "duplicate-params",
            b'{"params":{"uri":"first"},"params":{"uri":"second"},"method":"resources/read"}',
            1,
            2,
            b"first",
        ),
        (
            "duplicate-method",
            b'{"method":"tools/list","method":"tools/call","params":{"name":"private"}}',
            12,
            0,
            None,
        ),
        ("missing-params", b'{"method":"tools/call"}', 11, 1, None),
        ("missing-target", b'{"method":"resources/read","params":{}}', 11, 2, None),
        ("nonstring", b'{"method":"tools/call","params":{"name":7}}', 10, 1, None),
        (
            "params-array",
            b'{"method":"tools/call","params":[{"name":"private"}]}',
            4,
            1,
            None,
        ),
        (
            "escaped-key",
            b'{"method":"tools/call","params":{"na\\u006de":"private"}}',
            11,
            1,
            None,
        ),
        (
            "escaped-method",
            b'{"method":"tools\\/call","params":{"name":"private"}}',
            12,
            0,
            None,
        ),
        (
            "unsupported",
            b'{"method":"future.operation","params":{"name":"private"}}',
            12,
            0,
            None,
        ),
        ("root-budget", b'{"a":0,"b":0,"c":0,"d":0,"method":"tools/call"}', 5, 0, None),
        (
            "params-budget",
            b'{"method":"tools/call","params":{"a":0,"b":0,"c":0,"d":0,"name":"late"}}',
            5,
            1,
            None,
        ),
        (
            "root-array",
            b'[{"method":"tools/call","params":{"name":"private"}}]',
            4,
            0,
            None,
        ),
    ]
    return rows
