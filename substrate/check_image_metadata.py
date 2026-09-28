#!/usr/bin/env python3
"""Prove the layer audit sees catalogs hidden by deletion and embedded BTF."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import tarfile
import tempfile

path = Path(__file__).resolve().parents[1] / 'env/scripts/check-image-metadata.py'
spec = importlib.util.spec_from_file_location('image_metadata', path)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


def tar(files):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w') as archive:
        for name, blob in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(blob)
            archive.addfile(info, io.BytesIO(blob))
    return out.getvalue()


def elf_with_btf():
    # Minimal ELF64 section table independent of the audit parser.
    blob = bytearray(64 + 3 * 64)
    blob[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', blob, 40, 64)
    struct.pack_into('<HHH', blob, 58, 64, 3, 1)
    names = b'\0.shstrtab\0.BTF\0'
    struct.pack_into('<IIQQQQ', blob, 128, 1, 3, 0, 0, len(blob), len(names))
    struct.pack_into('<IIQQQQ', blob, 192, 11, 1, 0, 0, len(blob) + len(names), 1)
    return bytes(blob) + names + b'X'


with tempfile.TemporaryDirectory(prefix='ls-image-check-') as tmp:
    for name, layers, refusal in (
        ('clean', [{'usr/share/ls/runtime-identity.json': b'{}'}], False),
        ('catalog', [{'usr/share/ls/hook-index.tsv': b'secret'}], True),
        ('deleted lower-layer catalog', [{'usr/share/ls/signatures.tsv': b'secret'},
                                        {'usr/share/ls/.wh.signatures.tsv': b''}], True),
        ('renamed catalog backup', [{'tmp/hook-map.json.old': b'secret'}], True),
        ('ELF BTF', [{'usr/bin/tmm': elf_with_btf()}], True),
    ):
        members = {str(i) + '/layer.tar': tar(files) for i, files in enumerate(layers)}
        members['manifest.json'] = json.dumps([{'Layers': list(members)}]).encode()
        image = Path(tmp) / 'image.tar'
        image.write_bytes(tar(members))
        failed = False
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                audit.audit(image)
        except ValueError:
            failed = True
        assert failed == refusal, name
        print('ok   ', name)
print('PASS image-layer audit fixtures')
