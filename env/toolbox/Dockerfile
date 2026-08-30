# TMM trace toolbox --- an in-cluster pod an engineer execs into to run the trace
# DSL live: gen -> clang -> PREVAIL -> sign, then load into the f5-tmm pod. The
# pinned verifier and the type data ride in the image; the signing key is mounted
# from a Secret (a sign service in production). Ubuntu 24.04 to match the PREVAIL
# build (glibc/libstdc++); clang provides the bpf target.
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 clang curl ca-certificates \
    && curl -fsSL -o /usr/local/bin/kubectl \
        https://dl.k8s.io/release/v1.30.5/bin/linux/amd64/kubectl \
    && chmod +x /usr/local/bin/kubectl \
    && apt-get clean && rm -rf /var/lib/apt/lists/*
COPY prevail tmmtrace.py gen_type_catalog.py sign_shield.py shield_abi.h \
     signatures.tsv types.json hook-map.json /opt/tmmtrace/
COPY tmmtrace /usr/local/bin/tmmtrace
RUN chmod +x /opt/tmmtrace/prevail /usr/local/bin/tmmtrace \
    && python3 -c "import compileall; compileall.compile_file('/opt/tmmtrace/tmmtrace.py')" || true
ENV CLANG=clang PREVAIL=/opt/tmmtrace/prevail \
    LS_SIGS=/opt/tmmtrace/signatures.tsv LS_TYPES=/opt/tmmtrace/types.json \
    LS_HOOKMAP=/opt/tmmtrace/hook-map.json
CMD ["sleep", "infinity"]
