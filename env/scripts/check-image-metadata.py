#!/usr/bin/env python3
"""Reject bulk TMM catalogs and ELF BTF in every distributable Docker image layer.

Input is docker save's archive. Whiteouts deliberately do not forgive earlier
contents. This is a defined metadata gate, not a claim of symbol concealment or
reduced exploitability. It does not interpret arbitrary nested application archives.
"""
import argparse
import json
from pathlib import PurePosixPath
import struct
import sys
import tarfile

CATALOGS = {'hook-index.tsv', 'signatures.tsv', 'hook-map.json', 'types.json', 'tmm.btf'}


def has_btf(blob):
    if blob[:4] != b'\x7fELF':
        return False
    if len(blob) < 64 or blob[4] != 2 or blob[5] != 1:
        raise ValueError('ELF format outside ELF64 little-endian audit support')
    off = struct.unpack_from('<Q', blob, 40)[0]
    size, count, strings = struct.unpack_from('<HHH', blob, 58)
    if not off and not count:
        return False
    if size != 64 or not count or strings >= count or off + count * size > len(blob):
        raise ValueError('invalid/extended ELF section table')
    name_off, name_size = struct.unpack_from('<QQ', blob, off + strings * size + 24)
    if name_off + name_size > len(blob):
        raise ValueError('truncated ELF section names')
    names = blob[name_off:name_off + name_size]
    for i in range(count):
        start = struct.unpack_from('<I', blob, off + i * size)[0]
        end = names.find(b'\0', start)
        if end < 0:
            raise ValueError('unterminated ELF section name')
        if names[start:end] in (b'.BTF', b'.BTF.ext'):
            return True
    return False


def audit(path):
    bad, files, elfs = [], 0, 0
    with tarfile.open(path, 'r:*') as image:
        manifest = json.load(image.extractfile('manifest.json'))
        layers = sorted({layer for item in manifest for layer in item['Layers']})
        if not layers:
            raise ValueError('image contains no layers')
        for layer in layers:
            with tarfile.open(fileobj=image.extractfile(layer), mode='r|*') as archive:
                for member in archive:
                    name = PurePosixPath(member.name).name
                    if name in CATALOGS or any(name.startswith(n + '.') for n in CATALOGS):
                        bad.append(layer + ':' + member.name)
                    if not member.isfile():
                        continue
                    files += 1
                    stream = archive.extractfile(member)
                    prefix = stream.read(4)
                    if prefix != b'\x7fELF':
                        continue
                    elfs += 1
                    try:
                        if has_btf(prefix + stream.read()):
                            bad.append(layer + ':' + member.name + ' (ELF BTF)')
                    except ValueError as exc:
                        bad.append(layer + ':' + member.name + ' (' + str(exc) + ')')
    if bad:
        raise ValueError('forbidden or unaudited metadata:\n' + '\n'.join(bad))
    print('PASS metadata layer audit: %d layers, %d regular files, %d ELF files; '
          'no named bulk catalogs or ELF BTF' % (len(layers), files, elfs))


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('archive')
    args = ap.parse_args()
    try:
        audit(args.archive)
    except (OSError, ValueError, KeyError, tarfile.TarError, struct.error) as exc:
        sys.exit('FAIL metadata layer audit: ' + str(exc))
