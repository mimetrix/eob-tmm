"""Exact fixture bytes for ID/side extraction, including equal-ID overlap."""
from message_id_cases import cases as id_cases


def cases():
    """Sequential inputs include JSON shapes contrary to transport direction."""
    return id_cases() + [
        (
            "client-result",
            b'{"id":17,"result":{}}',
            b'{"id":17,"method":"tools/list"}',
            (1, 2, b"17"),
            (1, 2, b"17"),
        ),
        (
            "both-methods",
            b'{"id":"same","method":"tools/list"}',
            b'{"id":"same","method":"tools/list"}',
            (1, 1, b"same"),
            (1, 1, b"same"),
        ),
    ]


def repeated(prefix, count):
    """Equal IDs are deliberately ambiguous across these fixture exchanges."""
    return [
        (
            f"{prefix}-{i}",
            b'{"id":"shared","method":"tools/list"}',
            b'{"id":"shared","result":{}}',
            (1, 1, b"shared"),
            (1, 1, b"shared"),
        )
        for i in range(count)
    ]


def all_cases():
    """Return every client exchange for independent saved-evidence checks."""
    return cases() + repeated("keep", 3) + repeated("concurrent", 4)
