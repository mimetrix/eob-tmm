#!/usr/bin/env python3
"""Pinned build-box checks: actual compiler ELF, runtime parser, independent nm.

No TMM execution; these establish the attachment-record contract, not live arming.
"""
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

from bind_target import sections
from ls_buildid import build_id


def run(args, **kw):
    return subprocess.run([str(x) for x in args], check=True, **kw)


def main():
    here = Path(__file__).resolve().parent
    clang = os.environ.get('CLANG', 'clang-18')
    cc = os.environ.get('CC', 'gcc')
    objcopy = os.environ.get('OBJCOPY', '/usr/lib/llvm-18/bin/llvm-objcopy')
    prevail = os.environ.get('PREVAIL', str(here.parent / 'ebpf-verifier/bin/prevail'))
    with tempfile.TemporaryDirectory(prefix='ls-target-check-') as temp:
        d = Path(temp)
        (d / 'victim.c').write_text('__attribute__((noinline)) int victim(int x) { return x + 1; }\n'
                                    'int main(void) { return victim(0); }\n')
        # TMM's host code is GCC-built. Clang may use a multibyte NOP, which the
        # runtime deliberately does not admit as a five-byte compiler pad.
        run(['gcc', '-g', '-O2', '-no-pie', '-fcf-protection=branch', '-fpatchable-function-entry=5,0',
             '-Wl,--build-id=sha1', d / 'victim.c', '-o', d / 'victim'])
        binary = d / 'victim'
        bid = build_id(str(binary))
        nm = subprocess.check_output(['nm', '-n', str(binary)], text=True)
        entry = int(next(l.split()[0] for l in nm.splitlines() if l.endswith(' T victim')), 16)
        (d / 'index').write_text('#build_id\t' + bid + '\nvictim\t0x%x\tpad\t4\t0\n' % (entry + 4))
        (d / 'probe.c').write_text('__attribute__((section("fentry/victim"), used)) '
                                   'int probe(void *ctx) { (void)ctx; return 0; }\n')
        run([clang, '-O2', '-target', 'bpf', '-c', d / 'probe.c', '-o', d / 'probe.o'])
        run([sys.executable, here / 'bind_target.py', '--prog', d / 'probe.o',
             '--binary', binary, '--index', d / 'index', '--objcopy', objcopy])
        run([prevail, d / 'probe.o', 'fentry/victim', '--termination', '--strict',
             '--no-division-by-zero', '--stack-size', '256'])
        run([cc, '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
             '-I', here, here / 'check_target.c', '-o', d / 'check'])
        blob = (d / 'probe.o').read_bytes()
        sh = next(sh for name, sh in sections(blob) if name == '.ls.target')
        off = sh[4]
        assert struct.unpack_from('<Q', blob, off + 48)[0] == entry, 'patch offset mistaken for entry'

        def check(label, data, expected, build=bid, section='fentry/victim'):
            path = d / 'case.o'
            path.write_bytes(data)
            p = subprocess.run([str(d / 'check'), str(path), section, build, str(binary)],
                               capture_output=True, text=True)
            assert p.returncode == expected, (label, p.returncode, p.stdout, p.stderr)
            print('ok   ', label)

        check('compiler-produced eligible target', blob, 0)
        check('wrong full build, same 32-bit prefix', blob, 1, build=bid[:8] + '0' * 32)
        check('wrong section/hook', blob, 1, section='fentry/other')
        for label, at, replacement in [
            ('bad version', off, b'X'), ('wrong kind', off + 56, b'\1'),
            ('unsupported kind', off + 56, b'\2'), ('unsupported pad', off + 57, b'\2'),
            ('reserved bits', off + 58, b'\1'), ('address outside text', off + 48, struct.pack('<Q', 1)),
            ('patch address instead of entry', off + 48, struct.pack('<Q', entry + 4)),
            ('section table overflow', 40, struct.pack('<Q', 2**64 - 1))]:
            changed = bytearray(blob)
            changed[at:at + len(replacement)] = replacement
            check(label, changed, 1)
        for size in (0, 63, len(blob) - 1):
            check('truncated ELF %d' % size, blob[:size], 1)
        # A +0 pad is a supported target, not an inferred extension of +4.
        run(['gcc', '-g', '-O2', '-no-pie', '-fcf-protection=none', '-fpatchable-function-entry=5,0',
             '-Wl,--build-id=sha1', d / 'victim.c', '-o', d / 'victim0'])
        binary = d / 'victim0'
        bid0 = build_id(str(binary))
        nm = subprocess.check_output(['nm', '-n', str(binary)], text=True)
        entry0 = int(next(l.split()[0] for l in nm.splitlines() if l.endswith(' T victim')), 16)
        (d / 'index').write_text('#build_id\t' + bid0 + '\nvictim\t0x%x\tpad\t0\t0\n' % entry0)
        run([sys.executable, here / 'bind_target.py', '--prog', d / 'probe.o',
             '--binary', binary, '--index', d / 'index', '--objcopy', objcopy])
        check('compiler-produced +0 pad', (d / 'probe.o').read_bytes(), 0, build=bid0)
        (d / 'probe.c').write_text('__attribute__((section("fexit/victim"), used)) '
                                   'int probe(void *ctx) { (void)ctx; return 0; }\n')
        run([clang, '-O2', '-target', 'bpf', '-c', d / 'probe.c', '-o', d / 'probe.o'])
        run([sys.executable, here / 'bind_target.py', '--prog', d / 'probe.o',
             '--binary', binary, '--debug', binary, '--index', d / 'index', '--objcopy', objcopy])
        check('fexit with return/unwind admission', (d / 'probe.o').read_bytes(), 0,
              build=bid0, section='fexit/victim')
        run([prevail, d / 'probe.o', 'fexit/victim', '--termination', '--strict',
             '--no-division-by-zero', '--stack-size', '256'])
        print('PASS target-record fixture checks (ASan/UBSan); no live-TMM claim')


if __name__ == '__main__':
    main()
