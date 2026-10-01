"""Exercise the production loader through Unix sockets and its prepare thread."""
import importlib.util
import os
from pathlib import Path
import select
import socket
import struct
import subprocess


def check(source, output, obj, targets, common, ubpf, run, record):
    client_path = source.parent / "env/scripts/ls-load.py"
    spec = importlib.util.spec_from_file_location("program_client", client_path)
    client = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(client)
    key = output / "native-test-key.pem"
    run("openssl", "genpkey", "-algorithm", "Ed25519", "-out", key)
    key.chmod(0o600)
    run("python3", source / "gen_sig_pubkey.py", key, "-o", output / "ls_sig_pubkey.h")
    server = output / "program-socket"
    # Put the generated test public key before the repository's default key.
    run(common[0], "-I" + str(output), *common[1:], "-fcf-protection=branch",
        "-fno-pie", "-no-pie", "-ffunction-sections", "-fdata-sections", "-Wl,--gc-sections",
        source / "check_program_socket.c", source / "ls_vm_config.c", source / "ls_core_relo.c",
        source / "ls_tramp.c", source / "ls_arm.c", source / "ls_swap.c", source / "ls_sig.c",
        source / "trampoline_x86_64.S", targets, ubpf / "build/lib/libubpf.a",
        "-lm", "-lcrypto", "-lpthread", "-o", server)
    notes = run("readelf", "-n", server)
    bid = next(line.split()[-1] for line in notes.splitlines() if "Build ID:" in line)
    symbols = run("nm", server)
    addresses = {line.split()[-1]: int(line.split()[0], 16) for line in symbols.splitlines()
                 if line.endswith((" program_alpha", " program_beta"))}
    data = struct.pack("<8sII", b"LSTSET1\0", 2, 0)
    for name in ("program_alpha", "program_beta"):
        target = struct.pack("<8s40sQBB6x", b"LSTARG1\0", bid.encode(), addresses[name], 0, 4)
        data += struct.pack("<80s64s", ("fentry/" + name).encode(), target)
    target_file = output / "targets.bin"
    target_file.write_bytes(data)
    program = output / "bound.bpf.o"
    run("/usr/lib/llvm-18/bin/llvm-objcopy", "--add-section=.ls.target=" + str(target_file),
        "--set-section-flags=.ls.target=readonly", obj, program)
    for name in addresses:
        run("/home/starin/eob-tmm-staged/ebpf-verifier/bin/prevail", program, "fentry/" + name,
            "--termination", "--strict", "--no-division-by-zero", "--stack-size", "256")
    signature = output / "program.sig"
    run("python3", source / "sign_shield.py", "--key", key, "--prog", program,
        "--hook", "@program-v1", "--mode-ceiling", "monitor", "--build-min", "0x" + bid[:8],
        "--build-max", "0x" + bid[:8], "-o", signature)
    signed = signature.read_bytes()
    path = output / "program.sock"
    log = output / "socket.stderr"
    record["socket_checks"] = []
    with log.open("w") as stderr:
        process = subprocess.Popen([str(server), str(path), bid], stdout=subprocess.PIPE,
                                   stderr=stderr, text=True)
        try:
            assert select.select([process.stdout], [], [], 10)[0]
            assert process.stdout.readline().strip() == "READY"

            def send(message, fragmented=False):
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                    connection.settimeout(15)
                    connection.connect(str(path))
                    if fragmented:
                        for offset in range(0, len(message), 17):
                            connection.sendall(message[offset:offset + 17])
                    else:
                        connection.sendall(message)
                    connection.shutdown(socket.SHUT_WR)
                    answer = b""
                    while True:
                        chunk = connection.recv(4096)
                        if not chunk:
                            break
                        answer += chunk
                    return answer.decode().strip()

            def load(index, body=None, sig=None):
                sig = signed if sig is None else sig
                return client.msg(0x2001, slot=index, mode=0,
                                  prog=program.read_bytes() if body is None else body,
                                  binding=sig[:112], sig=sig[112:])

            def control(op, index, instance, entry=0, mode=0):
                return client.msg(op, slot=index, mode=mode, prog=struct.pack("<QII", instance, entry, 0))

            def status(response):
                assert response.startswith("OK program="), response
                return {key: int(value) for key, value in
                        (field.split("=") for field in response[3:].split())}

            bad = bytearray(signed)
            bad[-1] ^= 1
            assert send(load(0, sig=bad)).startswith("ERR")
            blob = bytearray(program.read_bytes())
            blob[-1] ^= 1
            assert send(load(0, body=blob)).startswith("ERR")
            assert send(load(0) + b"x").startswith("ERR")
            first = status(send(load(0), fragmented=True))
            second = status(send(load(1)))
            assert first["entries"] == second["entries"] == 2
            assert first["instance"] != second["instance"]
            assert first["mode"] == first["attached"] == 0
            assert send(load(0)).startswith("ERR")
            record["socket_checks"].append("real Ed25519 verification; bad signature/body/framing refused; two disabled programs loaded")
            for index, instance in ((0, first["instance"]), (1, second["instance"])):
                for entry in (0, 1):
                    status(send(control(0x2002, index, instance, entry)))
                assert status(send(control(0x2004, index, instance, mode=1)))["attached"] == 2
                assert send(control(0x2004, index, instance, mode=2)).startswith("ERR")
            assert send(control(0x2002, 0, first["instance"], 0)).startswith("ERR")
            assert send(control(0x2003, 0, second["instance"], 0)).startswith("ERR")
            assert send(control(0x2002, 0, first["instance"], 12)).startswith("ERR")
            assert send(client.msg(4, slot=56)).startswith("ERR")
            assert status(send(control(0x2003, 0, first["instance"], 0)))["attached"] == 1
            assert status(send(client.msg(0x2006, slot=1, mode=0)))["attached"] == 2
            assert status(send(control(0x2005, 0, first["instance"])))["instance"] == 0
            replacement = status(send(load(0)))
            assert replacement["instance"] != first["instance"]
            assert send(control(0x2005, 0, first["instance"])).startswith("ERR")
            record["socket_checks"].append("shared attachments; signed mode ceiling; wrong/stale instance and entry refused; independent revoke/reload")
            env = dict(os.environ, LS_LOAD_SOCKET=str(path), PYTHONDONTWRITEBYTECODE="1")
            run("python3", client_path, "program-status", 0, env=env)
            run("python3", client_path, "program-revoke", 0, replacement["instance"], env=env)
            run("python3", client_path, "program-revoke", 1, second["instance"], env=env)
            assert status(send(client.msg(0x2006, slot=1, mode=0)))["instance"] == 0
            record["socket_checks"].append("CLI status/revoke round trip; final programs empty")
        finally:
            process.terminate()
            process.communicate(timeout=10)
            record["socket_stderr"] = log.read_text()
            record["socket_exit"] = process.returncode
    key.unlink()
