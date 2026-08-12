# TMM build environment — reference

**The commands live in [`bnk-dev-runbook.md`](bnk-dev-runbook.md).** This file is its
companion: the facts behind the steps — which TMM, which build world, what is gated, what
the stacks hold, what was measured. Read this to understand *why* a step exists; run the
runbook to execute it.

Everything here targets **BNK / MBIP** — the containerized data plane. BIG-IP on a VM
(CBIP) is a follow-on effort; what is known about it is at the end.

## Two boxes, and why they are separate

| | `eob-bnk-build-01` | `eob-bnk-datkube-01` |
|---|---|---|
| TMM source + toolchain container | yes | no |
| clang for eBPF shield programs | yes | no |
| gcc, gdb, symbol analysis | yes | no |
| kind, kubectl, helm, datkube CLI | no | yes |
| runs the `f5-tmm` pod | no | yes |
| flavor | `datkube-dev-large` — 16 vCPU / 32 GB / 250 GB | smaller is fine |

Building is not running. The open questions in this proposal are about TMM's *runtime*
cost, and a machine simultaneously compiling 2,039 `.c` files inside the toolchain
cannot produce a citable number. It is also F5's own topology: the fast-cycling procedure
assumes a build machine and a Datkube machine with `scp` between them, which is why
`datpush` exists.

The flavor matters. The template's `m1.dev-large` at 8 GB is too small for a TMM build
plus the toolchain and output images; `datkube-dev-large` is the smallest that comfortably
fits. A completed `make tmm-gdb` leaves ~5 GB of images and a 2.2 GB clone on disk.

**eBPF development belongs on the build box.** The toolchain container has no clang; the
host has clang 18.1.3 with `bpf`, `bpfel` and `bpfeb` targets. Shield programs must
compile *there* regardless, because a shield includes the `ctx` struct definition for its
hook and that layout is generated per build — a hand-copied struct drifts silently from
the build it is loaded into.

## CBIP vs MBIP — the fork that organises everything else

**Read this before anything below it.** There are two TMMs and two build worlds, and most
confusion about this work came from not separating them. F5's own "Build f5-tmm container
image" page draws the line:

> *"In the same way in **CBIP** we use **seadev** to build TMM, in **MBIP** the
> toolchain_container is equivalent to the seadev server in CBIP."*

| | **CBIP** — classic BIG-IP | **MBIP** — containerized (BNK / SPK / CNF) |
|---|---|---|
| source | **Perforce** | **GitSwarm** — `gitswarm.f5net.com/tmm/tmm.git` |
| build machine | the **`seadev`** server | **`toolchain_container`** — pulled from Artifactory |
| TMM runs as | TMOS appliance / VE | a **Kubernetes pod** (`deploy/f5-tmm`, label `app=f5-tmm`) |
| dev environment | — | **Datkube** — a `kind` cluster |

So *"you will need Perforce"* is true for CBIP and false for MBIP. Source is git; the
build machine is a container you pull.

**Datkube is not the build system.** It is a `kind` (Kubernetes-in-Docker) cluster for
*running* TMM. The build uses one plain docker container with no orchestration at all.
Both involve containers and that is the whole of the resemblance.

## One source tree, three form factors

Answering a question asked directly — *can you tell from the clone itself whether the
appliance, VE and containerized builds come from the same source?* Yes, and the answer is
**one tree, three builds**, not three codebases. Evidence, all in `tmm/tmm` at
`10.207.3-main`:

- **`p4git/`** is a Perforce→Git bridge with `make run` / `make run-auto-import` sync
  targets and a `.p4config` client view. The GitSwarm repo is a **sync of the Perforce
  depot**. 25 of the last 400 commits mention P4 or Perforce.
- **`documents/feature-flags.md` carries appliance and VE flags** — `perf_VE_cores`,
  `perf_VE_SSL_offload`, `perf_VE_throughput_Mbps`, `security_appliance_mode`. Runtime
  flags in the shared TMM, so this tree knows about form factors it does not package for.
- **CBIP modules are present verbatim** — `src/modules/hudfilter/http/http_psm.c`, the
  file carrying the real vulnerable pattern behind
  [`../big-ip-live-shield-design.md`](../big-ip-live-shield-design.md) §14, is right here.
- **Only `tmm-mbip.spec` exists.** Appliance and VE packaging lives on the Perforce side.

**What that licenses and what it does not.** It licenses reading TMM *source* here and
expecting the other form factors to compile the same source — so a vulnerable pattern
found here is a pattern in all three, and the mechanism claim spans them. It does **not**
license carrying a *measurement* across: a hookable-set count is a property of one
compilation — flags, inlining, LTO, which modules are configured in. Same source,
different binaries. Counts stay labelled BNK until someone builds the others on `seadev`.

## How a BNK build actually works

BNK is not one program. It is **assembled** from dozens of independently built components,
each with its own repo and CI — closest analogy is a Linux distribution, where each
package builds alone, publishes to a repository, and a manifest names the exact versions
constituting a release.

```
f5ingress/…            L1 — components build themselves, publish to Artifactory
      |
helm chart repos       packaging — k8s deploys charts, not binaries
      |
f5-mbip-build          ASSEMBLY — input-manifest.yml is the bill of materials;
      |                            first point everything coexists, so integration tests run here
f5-stage5-build        FINAL PACKAGING (on gitlab.f5net.com, a different host)
      |
test candidate / release artifact
```

TMM's path: `tmm` → build artifact → `f5-tmm-helm-charts` → referenced in f5ingress's
`input-manifest.yml` → `f5-mbip-build` → `f5-stage5-build`.

**`input-manifest.yml` is the injection point, and that is the useful part.** A change can
be tested in a full BNK build *without merging*: build your component, its artifact lands
in Artifactory as a user build, override that version in the manifest, and assembly runs
integration tests against it. After merge a "stage bot" propagates versions downstream.

It is also the file TMM's own Makefile reads at every build — image coordinates for the
toolchain, the RPM→DEB converter, and the runtime base all come from it via `yq`. That
makes `yq` a hard build prerequisite and the manifest, not any wiki page, the authority on
which toolchain version is current (`tc-tmm:v2.3.1` as of this writing, where the
Confluence page still says `toolchain_container:v2.1.0`).

**Three tiers; we want the first two.**

| goal | what you run |
|---|---|
| iterate on TMM | `make start && make tmm && make unittest` |
| see it running | Datkube fast-cycle: build, `kind load`, delete the pod — **bypasses the pipeline entirely**, which is its stated purpose |
| a full product build | publish artifact → override in `input-manifest.yml` → assembly |

## The dev loop, and why `make tmm-gdb`

```bash
make start        # pulls tc-tmm (2.5 GB) from Artifactory and runs it; then install-libs
make tmm          # builds the binary INSIDE the toolchain container
make unittest     # the docs call this mandatory before integration
make container    # -> docker image tmm:local
```

Two traps, both silent:

- **`make start` is `.next-version _start install-libs`.** If `_start` fails,
  `install-libs` never runs and the build dies much later on a missing header
  (`/usr/include/errdefs/product_codes.h`), which looks nothing like a setup problem.
- **Before any `make container`, delete prior artifacts or your change is absent from the
  new image** — it builds, deploys and runs the old code:
  `sudo rm -rf RPMS SRPMS docker_build/DEBS BUILD_* docker_build/tmm-runtime.*`

**`make tmm-gdb` is the target this project needs**, because everything we want is what
stripping removes:

```
tmm-gdb: make tmm && make clean_rpms && make GDB_INCLUDE=true INSTALL_DEBUG_TMM=TRUE container
```

It yields `tmm:local`, `tmm:local_img`, `tmm_gdb:latest`, and — the one that matters —
`docker_build/DEBS/amd64/tmm-debuginfo_*.deb`, the only place the symbol table exists.

## Why we build our own: the shipped binary is stripped

Extracted `/usr/bin/tmm` from `tmm-img:v0.950.0-0.1.0`. A symlink chain — `tmm` →
`tmm.default` → **`tmm64.no_pgo`** — ending at a 56 MB x86-64 executable.

- **No `.symtab`, no `.debug_*`.** `nm` returns nothing.
- **`.gnu_debuglink` names `tmm64.no_pgo.debug`** — the symbols exist, split into a file
  that is not in the runtime image.
- **Only `.dynsym` survives: 4,648 defined symbols, overwhelmingly OpenSSL exports.**
  `flow_input`, `http2`, `tmm_poll` — zero hits.

**That is evidence for a design decision, not an obstacle to one.** TMM's internal
functions are not exported, so a hook map cannot be derived from a shipped artifact — not
by us, not by a customer. It must be generated **at build time inside F5 from DWARF/BTF
and shipped signed alongside the build**, which is exactly what
[`../development-scope.md`](../development-scope.md) item 5 specifies. The proposal
asserted it; this demonstrates it.

## What was measured

**The hookable set, 2026-08-12, BNK only.** From `make tmm-gdb` via
`tmm-debuginfo_*.deb`: **119,555** out-of-line functions (42,215 global, 77,340 local;
~113,604 excluding obvious statically-linked third party), **92 `.constprop`, 76 `.isra`,
126 `.part`** clones, full DWARF. So the folding and cloning the design warns about is
real and countable. Six figures, against a designed-in catalog of 41 tracepoints.

**Condition 1, verified rather than argued.** §10.1's first condition — the target
function still exists as an out-of-line body after the optimiser has run — had been
argued but never checked. `http_psm_profile_name_lookup`, a **`static bool`** and exactly
the shape most likely to be inlined away, **survived `-O2` as symbol type `t`**. The
condition holding in the unfavourable case, not the easy one.

**Both numbers reproduced on a second, independently provisioned box** — built from
`Ubuntu2404-server-pristine` by following the runbook step by step, with nothing carried
over but the credentials. Identical: 42,215 global / 77,340 local / 119,555 total, 92/76/126
clones, 10 `.debug_*` sections, `http_psm_profile_name_lookup` at type `t`, zero hits for
the fictional symbol. That is what makes the runbook a procedure rather than a narrative:
the measurement is a property of the build, not of one machine's accumulated state.

**One correction belonging in the record: `fw_log_prot_transfer_emit` does not exist.** It
was invented as a plausible-sounding hook target for §14's worked example, and searching
119,555 real symbols returns zero. What is real is the struct
(`fw_log_profile_protocol_transfer`), the field (`prot_transfer_log_profile`), and the
unchecked dereference at `src/modules/hudfilter/http/http_psm.c:806-808` — where every
other use of that field is NULL-checked (`listener.c:1161`, `listener.c:1519`,
`fw_log_profile.c:4551`, `db_fw_log.c:1663`). The example's mechanism stands; its symbol
name was a placeholder and is labelled as one everywhere it appears.

## What Artifactory supplies, and what is gated

`artifactory.f5net.com` is F5's binary repository, and the build depends on it four
separate ways — worth enumerating, because "Artifactory" is otherwise a single word
standing in for four different dependencies. All four are named in `input-manifest.yml`.

| role | what comes from it |
|---|---|
| **the build machine itself** | `f5-f5dev-docker/tc-tmm` — the MBIP equivalent of `seadev`. Plus `tc-alien` (RPM→DEB), `clang-style-check`, `product-gatekeepr`, and a `tao` test image |
| **prebuilt binary dependencies** | `tmstat`, `libbigpacket`, `tcpdump` RPMs, `wget`-ed mid-build (`Makefile:343-345`) and alien-converted. TMM does not compile these — which is why `tmm:local` ships with tmstat and tcpdump in it |
| **generic / npm tarballs** | the protobuf API definitions (`mbip-apis-pb`, `internal-apis-pb`) and `f5auth` |
| **a publish target** | `Makefile:379` logs into `DOCKER_PUBLISH_REGISTRY`; your component's artifact lands there as a *user build*, which is what lets `input-manifest.yml` name your version for assembly without merging |

### Three tiers of access, not two

| tier | what it gets you |
|---|---|
| **anonymous** | `docker pull` of F5-published images — the 18.1 GB `toolchain_container:v2.1.0` and `tmm-img` came down with no credential at all |
| **an identity token** | the RPM and tarball dependencies above, `dockerhub-remote` (where kind's node image lives), and publishing |
| **the REST API** | still **401** — you cannot *list* repos or discover versions at any tier we hold |

**The token is load-bearing for the build, and an earlier note here said otherwise.** It is
true that the toolchain image pulls anonymously, and true that `spk-devmachine`'s
`artifactory_token` variable authenticates nothing (it is only exported into a shell
profile). Neither generalises: probed directly,
`f5-tm_lib-rpm/tmstat/tmstat-1.0.0-0.x86_64.rpm` returns **401 anonymous, 200 with the
token**. So `~/code/tmm/.env` is not optional plumbing — without it `make tmm` dies partway
through on an RPM fetch.

**The registry/API split is still the useful observation.** Images are obtainable if you
know the exact tag; you cannot browse to discover tags. So a current `input-manifest.yml`
is worth more than broad read access — that one *file* names every version.

### The other walls

| what | endpoint | status |
|---|---|---|
| `kind` node images, Calico, Multus | public / cached | works |
| GitSwarm HTTPS / SSH | `gitswarm.f5net.com` | needs an account and a registered key |
| Confluence | `docs.f5net.com` | `permissionViolation=true`; REST 401 |

**All the 401s are one identity: olympus LDAP.** GitSwarm's sign-in page says it outright
— *"Sign in using your olympus(ldap) credentials. Do not use email as username."*
Artifactory and Confluence sit behind the same directory. Two layers, and only the second
needs a human:

1. **Authentication** — an LDAP session. Rarely the obstacle.
2. **Authorization** — project membership. In GitLab a project you cannot see returns
   **404, not 403**, so "repo not found" and "you lack membership" are indistinguishable.
   Check by loading the project page while signed in.

**What unblocked it** was an SSH key registered at
`https://gitswarm.f5net.com/-/user_settings/ssh_keys`. A PAT with `read_repository` works
too, but the key is better: the private half never leaves the box and revoking it is one
click. **Keep the LDAP password out of the environment entirely** — tokens and keys are
per-service and revocable; the account password is not.

So the exercise needs **two credentials, and neither is Perforce or a build host**: a
GitSwarm key for `tmm/tmm`, and an Artifactory identity token for the build's own RPM
dependencies. Perforce is CBIP; the build host is a container you pull.

**One caution.** TMM's Makefile echoes its full `docker run` line, `-e
ARTIFACTORY_TOKEN=…` included, so the token lands in every build log. Filter it out of
anything you share, and rotate it if a log escapes.

## The stacks — SEA and SJC

Measured 2026-08-11, authenticated against both. **Use SEA**, on quota headroom.

| | SJC | SEA |
|---|---|---|
| Project | `starin` (`c0007f99…`) | `starin` (`fc383461…`) — same name, **different project** |
| **Quota: cores** | 20 | **40** |
| **Quota: RAM** | 50 GB | **80 GB** |
| Quota: instances | 10 | 10 |
| Largest flavor that fits | 16 vCPU / 32 GB | 32 vCPU / 64 GB |
| Images | 97 | 220 |
| BNK images | none | `bnk-Ubuntu22.04.3LTS-pristine`, `bnk-latest-…` |
| `AdminNetwork` | IPv4 only | **dual-stack** — `2620:128:e008:4806::/64` + `10.145.32.0/19` |
| Keystone | `keystone.sjc-stack.pdsjc.f5net.com` → `10.197.12.17` | `keystone.sea-stack.pdsea.f5net.com` → `10.145.23.16` |

For a compile-heavy build, cores and RAM bind, so SEA has roughly **2× the usable
ceiling**. Two `datkube-dev-large` boxes are 32 cores / 64 GB and fit; a third does not.

**Four gotchas that cost time:**

- **SEA's dual-stack `AdminNetwork`** puts the IPv6 address first, which is what breaks
  the provisioner's generated inventory. It also changes default-route selection at boot.
- **`AdminNetwork` is directly reachable from this sandbox** — `10.145/16` routes from
  here, no jump host, no floating IP. `auto_ip: false` is correct.
- **Duplicate image names persist on SJC** — two distinct IDs both named
  `BIGIP-tmos-rocky-22.0.0-0.0.570`, so `--image <name>` fails with "More than one Image
  exists". **Always launch with `--image <id>`.**
- **TLS verification fails against both stacks** — their certs chain to `F5 F5NET Issuing
  CA`, which is in neither the system store nor `netskope-ca.pem`. Hence `verify: false`
  in `clouds.yaml`. Getting the real F5 internal CA bundle in would be the clean fix.

Image IDs are stack-local and change on re-upload — re-resolve by name before relying on
them. The ones in use: `Ubuntu2404-server-pristine`
(`efbdf879-1995-474d-b65c-ad92e486d8c7`, SEA) and `Datkube-Devbox-Berge`
(`abecfaf0-4fa1-4519-a1a7-fcd316506f1c`, SEA).

## Credentials

One OpenStack application credential per stack, both named `tmm-build-sandbox`, **both
expiring 2026-11-11** — auth will start failing that day with a 404-style rejection that
reads like a config problem.

| Stack | Credential ID | Expires |
|---|---|---|
| `sjc` | `529ef27c73e54b4895b69342423654e9` | 2026-11-11 |
| `sea` | `cdea13fdf7bf42d58defc8191798fc89` | 2026-11-11 |

Create via Horizon → Identity → Application Credentials, on the stack you want; they are
per-stack and an SJC one will not work against SEA. Leave *Unrestricted* unchecked, set an
expiry, and download the `clouds.yaml` Horizon emits — the secret is shown once.
[`scripts/merge-clouds-yaml.py`](scripts/merge-clouds-yaml.py) stitches the two downloads
into one multi-cloud file at mode 600, forcing `verify: false` and printing only
non-secret fields. A credential is scoped to whichever project was selected at creation
time; switching projects means recreating it.

**Failure modes worth recognising:**

| Symptom | Cause |
|---|---|
| `Could not find Application Credential: <id>. (HTTP 404)` | Wrong/deleted/expired, or created on the *other* stack |
| `The request you have made requires authentication. (HTTP 401)` | Secret mismatch |
| `SSLError` / `CERTIFICATE_VERIFY_FAILED` | `verify: false` missing from that cloud's block |
| `Missing value auth-url required for auth plugin` | `OS_CLOUD` unset or naming a cloud not in the file |
| `You are not authorized to perform the requested action` | Credential inherited too few roles — recreate while scoped to the right project |

## Provisioning — `koenning/spk-devmachine`

**Use this rather than hand-installing or snapshotting an image of our own.** It is
Ansible that provisions an OpenStack VM from **`Ubuntu2404-server-pristine`** with roles
for common packages, docker, golang, git, ssh, shell, security hardening, NFS and repo
cloning. Playbooks: `provision-machine.yml`, `setup-dev-machine-slim.yml`,
`deploy-complete.yml`, `destroy-machine.yml`, plus standalone `install-falcon.yml` /
`install-qualys.yml`.

This is the reproducible artifact the earlier "should we build our own image?" question
was really after. A snapshot has no provenance; this is a diffable recipe, and it already
exists. Its exact invocation, the five things that bite when running it from this sandbox,
and the three ignorable failures are in the runbook.

**Two gaps worth upstreaming:**

- **No `/etc/docker/daemon.json`.** The `docker` role installs and starts Docker CE but
  never constrains the address pool, so any box it provisions on this network cuts itself
  off as soon as someone runs kind. See below. Worth an MR.
- **No `yq`.** Which TMM's Makefile requires to resolve its own toolchain image.

**The image catalogue contains no build environment.** Worth knowing, because the natural
assumption is otherwise. SEA's 220 images are 75 BIG-IP VE appliance images, ~57
licensing-component images, ~19 `*-pristine` clean OSes, and three `ite-el{6,7,8}-chroot`
images that have the shape of an RPM build root but are unverified and CBIP-flavoured.
`BIGIP-tmos-rocky-22.0.0-0.0.570` **runs** TMM and cannot build it — locked-down TMOS, no
compiler, no source.

The closest thing is **`Datkube-Devbox-Berge`**, whose `description` property lists
Datkube, Docker, GCC, GDB, Go, Helm, Kind, Kubectl, yq. Two caveats: it is
`image_type: snapshot`, `owner_user_name: berge`, created 2025-08-20 — "what one engineer
had installed that day", and nobody owns keeping it current. Its on-image datkube clone
was **658 commits behind** when checked. And it is *tools, not source*. Useful as a
run-target reference; not a provenance-bearing build box.

## The docker address-pool trap

**Write `/etc/docker/daemon.json` before docker is installed on any box, or it will
disconnect itself and look dead.** The file and the verification are in the runbook, step
5. The reason is here.

SSH from this sandbox arrives at an instance from **`172.18.105.92`** — we are NATed, so
although the sandbox is `10.88.0.5`, the box sees `172.18.x`. A stock docker install puts
`docker0` on `172.17.0.0/16` and hands kind `172.18.0.0/16` from the default pool. The
moment a cluster is created, the box installs a route for `172.18.0.0/16` pointing at the
docker bridge, **return traffic is routed into the bridge instead of out the default
gateway**, and docker's `REJECT` rules answer with ICMP port-unreachable.

The symptom is a box perfectly healthy on the console — multi-user reached, cloud-init
finished, login prompt — while **every port refuses**. It reads as "sshd died" and is
nothing of the sort. It does not recover, and rescuing the instance does not help, because
the damage is to routing on a box that is otherwise fine.

The collision is wider than SSH: F5's estate sits inside `172.16.0.0/12` — resolver
`172.27.1.1`, GitSwarm `172.31.226.252`, Artifactory `172.25.9.4`, Confluence
`172.25.8.129`.

**`Datkube-Devbox-Berge` already ships this file**, which is why that image survives where
a freshly provisioned box does not. Not a coincidence — whoever built it hit this.

**How it was found**, because the wrong turns are the instructive part. Two boxes died and
five theories were disproved by controlled experiment: a NAC/posture cutoff for missing
Falcon and Qualys (Berge's image has neither and survives), the `nfs` role (box 2 skipped
it and still died), `unattended-upgrades` (enabled *and already run* on the survivor), the
playbook touching `sshd_config` (nothing in any role writes it), and the base image itself
(a bare untouched `Ubuntu2404-server-pristine` survived 80/80 checks over 40 minutes).
What isolated it was noticing the survivor had never had docker or kind run on it, then
reading its route table. Neither Falcon nor Qualys is required for a box to stay
reachable — that hypothesis was tested properly and is dead.

## The sandbox side — verification toolchain

PREVAIL is built from the vendored tree here, and the authoring chain runs end to end:
`clang -O2 -g -target bpf` → `prevail` → `substrate/budget_pass.py`. Two things that cost
time:

- The build needs the **Netskope CA** set (see [`README.md`](README.md)) or `FetchContent`
  fails to clone GSL with a misleading error, **and** Boost headers, which cannot be
  apt-installed here. Download the 1.87.0 tarball, extract only `boost_1_87_0/boost`, and
  pass `-DBOOST_HEADERS_DIR=…`.
- Binaries land in `ebpf-verifier/bin/` **inside the repo tree**, not the build dir. That
  path is gitignored, so an 11 MB `bin/` under a vendored tree is expected.

`prevail --help` confirms from the shipped binary what
[`../development-scope.md`](../development-scope.md) item 3a records from source:
`--termination` *"Default: ignore"*, `--allow-division-by-zero` *"Default: allow"*,
`--strict` off. Pass them explicitly; "verified" otherwise means less than it sounds.

**Running the chain on a real object immediately found a fail-open in our own budget
pass.** It defaulted to reading `.text`, but clang emits an eBPF program into its `SEC()`
section and leaves `.text` present and **zero bytes** — so it priced 0 instructions and
returned "ok, under budget" for a program it had never looked at, in the one component
whose entire job is to fail closed. The self-test missed it because the ELFs it
synthesizes put their payload in `.text`, which is exactly the shape real objects do not
have. Fixed: it locates the executable section, refuses when there is none or several are
ambiguous, and takes `--section` as PREVAIL does.

**The sandbox is ephemeral.** `~/.venvs`, `~/.local/bin` and `~/.config/openstack` are
wiped between sessions — assume the CLI is rebuilt every time via
[`scripts/bootstrap-openstack-cli.sh`](scripts/bootstrap-openstack-cli.sh). This repo is a
*clone* here, not a host mount, and does not survive a reset: commit and push before a
session ends.

## Follow-on: CBIP, and what is known about Perforce

Not needed for BNK. Recorded so the follow-on does not start from zero.

- `perforce.f5net.com` and `perforce.olympus.f5net.com` both resolve to
  **`192.168.13.205`**. **Not reachable from this sandbox** — nothing routes on 1666,
  1667, 22 or 443, and there is no `p4` client here.
- **Both stacks carry a `PerforceAccessNet`** (`10.197.72.0/22` on SJC,
  `10.145.160.0/22` on SEA), so it does not discriminate between them. Attaching a NIC is
  **necessary and not sufficient**: `192.168.13.205` is in neither CIDR, and `host_routes`
  is empty on both, so nothing pushes a route — it has to come from the default route
  leaving that NIC. A build host also wants a management NIC, `AdminNetwork` is also
  DHCP-enabled with its own gateway, and a two-NIC instance therefore boots with **two
  default-route candidates**. "The NIC is attached but p4 times out" is this, not a
  firewall. Fix it deterministically — a static route for the Perforce prefix via that
  subnet's gateway — rather than relying on NIC ordering.
- **The real discriminator may be DNS.** `PerforceAccessNet` pushes an extra resolver,
  **`192.168.180.15`**, which `AdminNetwork` does not, and it is in the same `192.168/16`
  space as Perforce itself. So resolving `perforce.f5net.com` may itself depend on being
  on that network.
- **`DEV TMM Compile and Debug`** — `docs.f5net.com/spaces/~garlapati/pages/936700918/` —
  is presumably the authority on CBIP compile-and-debug and is behind the Confluence auth
  wall. See [`bigip-mcp-server.md`](bigip-mcp-server.md) for the personal-access-token
  route.
- **Kernel/BTF on TMOS is still unverified.** `BIGIP-tmos-rocky-22.0.0-0.0.570` is the
  Rocky-based image [`bigip-ve-boot-2026-07-17.md`](bigip-ve-boot-2026-07-17.md) was
  waiting for, but an image *name* is not proof of kernel version. The cheap probe is to
  boot it and read `openstack console log show` for the kernel line — the console may
  answer without a shell at all, which is why it is the cheapest test available.

## `-fpatchable-function-entry` — the static half, measured

The first experiment `design-review-findings.md` §4 asks for is an A/B build: TMM compiled
normally, and TMM compiled with entry padding, **nothing armed**, to price the cost every
customer pays whether or not a shield ever loads. That experiment has four parts — text
size, throughput, latency tail, instruction-fetch behaviour. **The first is now done. The
other three still need a running TMM at rate and are untouched.**

### How to inject the flag — no source modification required

`Makefile.inc` includes **`$(TOPDIR)/Makefile.overrides`** at line 116, *after* its own
`CFLAGS_OPTIMIZE := -O2` (line 99) and *before* `CFLAGS += $(CFLAGS_OPTIMIZE)` (line 134),
under the comment *"Allow overrides to reset the above variables."* `src/compile/Makefile`
sets `TOPDIR := ../..`, so the file belongs at the repo root:

```make
# Makefile.overrides
CFLAGS_OPTIMIZE := -O2 -fpatchable-function-entry=5,0
```

That is the whole change. It matters that a supported hook exists, because the proposal
claims the mechanism needs no source modification, and here the *experiment* needs none
either.

**Two ways to get this wrong, both of which produce a clean-looking wrong answer.**
Patching the root `gcc.mk` does nothing — it *is* included (`Makefile.inc:93`), but line 99
then reassigns `CFLAGS_OPTIMIZE` with `:=` and clobbers it; the build recompiles 2,893
objects with plain `-O2` and yields a binary byte-identical to baseline, which reads as
"padding is free." And `CMDLINE_VARS` (`Makefile:44`) expands `$(v)=$($(v))` **unquoted**,
so passing a value containing a space splits it into two arguments to the inner make and
applies half of it.

### Result

Both builds are `make tmm-gdb`, same source revision, same `-O2`, comparing
`tmm64.no_pgo` extracted from each `tmm_*.deb`. **The flag compiles cleanly across the
whole tree — 2,039 files under `-Wall -Werror`, zero errors.** That was genuinely open
beforehand.

| | baseline | `+patchable=5,0` | delta |
|---|---|---|---|
| `.text` | 30,099,298 | 30,242,658 | **+143,360 (+0.476%)** |
| whole binary | 56,449,248 | 56,877,952 | **+428,704 (+0.759%)** |
| out-of-line functions | 73,906 | 73,906 | unchanged |
| entries carrying 5 nops (1,200 sampled) | 0 | **48.9%** | — |

**Effective cost is 3.97 bytes per padded entry against a nominal 5 — alignment absorbs
21%.** §4 asks whether pad placement matters because nops "can occupy alignment slack that
already existed"; they do, and this quantifies it.

### The coverage number is the finding, not the size

Only **48.9%** of the functions in the shipped binary got padded, and that is not a
misapplied flag. Mapping sampled entries back to source through DWARF:

| source bucket | padded |
|---|---|
| `src/compile` (the TMM tree) | **82%** |
| `BUILD_x86_64/tmm-10.207` | **97%** |
| `src/tm_lib` | **78%** |
| `BUILD_x86_64/{dedup,tmstat,mcplib,crypto,errdefs,tmjail,aclparser,f5util}-*` | **0%** |
| `builds/{nxdomain,ports,tm_lib,UPSTREAM,afm}` | **0%** |
| bare filenames (`encode_key2any.c`, `psregexp.c`, `arraylist.c.o`) — vendored third party | **0%** |
| no DWARF line info (20% of the sample) | **0%** |

**Roughly half of the functions in the TMM binary are not built by the TMM build.** They
arrive from a couple of dozen separately-built F5 components and vendored third-party
libraries, each with its own build and its own flags, statically linked at the end. Some —
`tmstat`, `libbigpacket`, `tcpdump` — are downloaded from Artifactory as **prebuilt RPMs**
and never compiled here at all.

Three consequences for the design, and they are the reason this measurement was worth
running:

1. **The hookable set and the *paddable* set are different sets.** The 119,555-function
   count is what the optimiser leaves addressable; it is not what one flag can reach.
   Padding the other half means changing each component's build — or, for the prebuilt
   RPMs, getting whoever builds them to change theirs. That is a coordination problem
   across component teams, not a compiler flag, and it belongs in the plan as such.
2. **Where the flag does apply it applies well** — 82–97% inside the TMM tree. The residual
   there is presumably hand-written assembly and functions the compiler never emitted a
   normal prologue for.
3. **The measured +0.476% is roughly half the eventual figure.** Scaling the observed
   effective rate to full coverage gives **~+0.97% `.text`, ~+1.55% binary, about 4,600
   64-byte cache lines of pure nop across the image**. That is an extrapolation from one
   platform and one N, stated as one — but it does bound the static cost at low
   single-digit percent rather than leaving it open.

### Reproducing it

`substrate/measure_entry_padding.py` is the measurement, so it does not have to be
reassembled from shell history:

```bash
python3 substrate/measure_entry_padding.py \
    --baseline BIN --flagged BIN \
    --baseline-debug DBG --flagged-debug DBG
```

It exists because doing this by hand produced **three consecutive wrong answers, every one
clean-looking and favourable**, plus a fourth caught only by computing coverage instead of
assuming it. So the script refuses to price anything it cannot verify: it checks build-ids
before trusting a symbol address, reads bytes from section offsets rather than parsing a
disassembler, accepts the pad at offset 0 **or** after `endbr64`, falls back to a
symbol-free 0x90-run count when a debug file does not match, and prints coverage beside
every size figure. It exits non-zero if the flag did not land, so a size delta can never be
reported for a build that never got the flag.

On its first run it caught a mismatch in this very experiment's *baseline* control — the
saved baseline binary and its debug file came from different builds — which is why the
baseline column above is verified by the symbol-free scan (**28** incidental 5-nop runs
versus **34,924**) rather than by symbol lookup.

### What is still unmeasured

Everything that needs TMM *running*: throughput, latency at p99/p99.9, i-cache MPKI, i-TLB
misses, and whether `.text` is shared or private across TMM instances and whether it lands
on huge pages. Also unmeasured: aarch64, where instruction encoding and alignment differ,
and the armed-at-rate case. **Do not read the size result as the answer to §4** — it is one
of four columns, on one architecture, at 49% coverage.

## The VM inside TMM — the integration, and where it lives

**2026-08-12.** The proposal's central claim is that a verified eBPF program can live inside
TMM and be called from it. Nothing had tested that. This records the integration that does.

**Where the code lives, and why the distinction matters.** The candidate artifacts stay in
this repo — [`../substrate/ls_vm.h`](../substrate/ls_vm.h),
[`ls_vm.c`](../substrate/ls_vm.c), [`vm_stack_policy.h`](../substrate/vm_stack_policy.h),
and the shields. The *working integration* lives in the TMM clone on the build box, not
here. So [`../CLAUDE.md`](../CLAUDE.md)'s statement that nothing in this repo executes a
shield stays true, and this repo does not become the prototype whose earlier version invited
the wrong question. Read the artifacts here as candidates; read the box as the experiment.

### uBPF builds inside TMM's toolchain container

The gating question, because linking needs a matching compiler and C library:

```bash
docker exec -i $C bash -c 'cd /tmm/.ubpf &&
  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DUBPF_ENABLE_TESTS=OFF \
        -DUBPF_SKIP_EXTERNAL=ON -DCMAKE_POSITION_INDEPENDENT_CODE=ON &&
  cmake --build build -j8'
#  -> build/lib/libubpf.a, built by gcc 11.4.0 — the same compiler that builds TMM
```

The container has `gcc cmake make ar python3` and **no clang**, which is consistent with the
earlier finding that shield programs compile on the host.

### The TMM-side change — four places, 30 lines

| # | file | change |
|---|---|---|
| 1 | `Makefile.overrides` | `CFLAGS += -I$(TOPDIR)/.ubpf/vm/inc` and `DEVFS_LIBS += $(TOPDIR)/.ubpf/build/lib/libubpf.a` |
| 2 | `src/compile/filelist` | one line registering `base/ls_vm.c`, **plus a user-defined option carrying the include paths** (below); `filelist.mk` is **generated** by `filelist.py`, so delete it to force a regenerate |
| 3 | `http_psm_init()` | `ls_vm_init()` then `ls_vm_arm(...)`, once per instance, off the data path |
| 4 | `http_psm_profile_name_lookup()` | fill a scratch `ctx`, call, act on the verdict |

`DEVFS_LIBS` is the pattern TMM already uses for static libraries, so this adds no new
mechanism.

**A global `CFLAGS +=` in `Makefile.overrides` does NOT reach most source files, and this is
the trap worth knowing.** It looks like it works — 344 compile lines picked up the added
include path — while the one file that needed it did not. The reason is in `filelist`
line 14:

```make
INSTRUMENT = CFLAGS +=
```

Every file inherits that, so `filelist.mk` emits a **target-specific** `CFLAGS +=` line for
essentially every object, and in that scope the globally-added flag is not visible. The
symptom is a missing header on exactly one file while hundreds of others compile fine, which
reads like a problem with that file.

**The mechanism the build provides is a user-defined option**, alongside `ALLOW_UNDEF`,
`ALLOW_ADR_PKD_MEM` and the rest:

```
# in src/compile/filelist
UBPF = CFLAGS += -I$(TOPDIR)/.ubpf/vm/inc -I$(TOPDIR)/.ubpf/build/vm

base/ls_vm.c                        STDINC UBPF
```

Both paths are needed: `vm/inc` for `ubpf.h`, and `build/vm` for **`ubpf_config.h`, which
cmake generates** and which therefore does not exist until uBPF has been configured.

**And cross-directory includes use the `local/` convention.** `src/compile/local` is a symlink
to `..`, so a module file reaches a header in `src/base` as
`#include <local/base/ls_vm.h>` — not a relative path. Getting this wrong fails only in the
consuming file, after the new file itself has compiled clean.

**One bug worth recording, because the file's shape causes it.** The call site is at line 827
and `http_psm_init` is at 5126, so declaring the slot handle beside the init function put the
declaration 4,300 lines *after* its first use. In a 5,000-line file, "next to the thing it
belongs with" and "before the thing that uses it" are different places.

### The gate nobody had hit: TMM whitelists mutable global state

`make tmm` linked successfully on the first attempt that got the include paths right — and
then **failed a check**, which is where the useful finding is. `src/compile/Makefile:1626`
runs `bin/diff-globals` against a per-architecture, per-build-type whitelist
(`debug_whitelist_x86_64`, 283 entries; `default_whitelist_x86_64`, 276).

Read `bin/print-globals` before assuming what it guards: it extracts symbols from **`.data`,
`.bss` and COMMON** and deliberately **not** functions. This is not an export or ABI check —
it is an allowlist of **mutable global state**, and any new entry fails the link.

That is the right guard for a core-pinned, run-to-completion data plane, where new
process-global mutable state is precisely what breaks per-instance independence. It also
turns a vague design question into a countable one.

**Embedding the VM adds exactly ten pieces of global state — three ours, seven uBPF's:**

| symbol | whose | what it is |
|---|---|---|
| `g_slots`, `g_ready` | ours | the slot table and its init flag |
| `ls_ptlog_slot` | ours | which slot holds this hook's shield |
| `_initialized`, `register_map` | uBPF | lazily-initialised process-global tables |
| `_ubpf_instruction_filter`, `_ubpf_filter_instruction_lookup_table` | uBPF | the instruction filter |
| `ebpf_atomic_store_immediate_enumerated`, `ebpf_movsx_alu{,64}_offset_enumerated` | uBPF | opcode tables |

**Two consequences for the design, not just for the whitelist.**

1. **Our three should not be file-scope statics.** Per-instance VM state belongs in TMM's
   existing per-instance structure, which is exactly what this gate is nudging toward. The
   statics were the shortest path to a working link, not the right shape.
2. **uBPF's `_initialized` and `register_map` are process-global and lazily filled.** Benign
   while each TMM instance is its own process — but a reviewer should be told that rather
   than find it, and it is a constraint on any future move to threads.

All ten were added to both x86_64 whitelists (283→293, 276→286), with `.pre-ubpf` copies kept
so the delta stays recoverable. Using the whitelist is the mechanism's intended purpose:
adding global state should be a deliberate act.

### It builds and links, and the call site is in the machine code

`make tmm` **rc=0**. Verified in `obj_x86_64.no_pgo/tmm.no_pgo` rather than inferred from the
exit code:

```
nm:       ls_vm_init  ls_vm_arm  ls_vm_call  ls_vm_fini  ls_stack_usage
          45 ubpf_* functions, incl. ubpf_create, ubpf_exec, ubpf_load_elf_ex,
          ubpf_register_stack_usage_calculator
          ls_shield_blob present

objdump   http_psm_profile_name_lookup at 0xcbd940:
            call 488680 <flow_get_listener>
            call 4297c0 <ls_vm_call>        <- the data-path function calls the VM
            call *%rbp                      <- append_fn, the original path
```

**State the claim exactly, because it is easy to inflate.** What is true: the VM's code and a
PREVAIL-verified program are **inside the TMM binary**, and a data-path function contains a
`call` to the VM entry point. What is **not** true, and was briefly written here as though it
were: nothing has **run**. `make tmm` compiles and links; it does not execute TMM.

| claim | status |
|---|---|
| uBPF's code is in the TMM binary | verified — 45 functions |
| the verified shield's bytes are in the binary | verified — `ls_shield_blob` |
| a `call ls_vm_call` exists inside a data-path function | verified — `0xcbd9ba` |
| `ubpf_create` / `ubpf_load_elf_ex` ever called | **no** |
| one eBPF instruction executed | **no** |
| the TMM process ever started | **no** |

So the honest sentence is: **TMM now links its own eBPF VM and carries a verified program, with
the call site present in machine code.** Executing it needs TMM running — the pod on the
Datkube box — and that has not been done. A linked call is not an executed one.

### Bytecode actually ran — and what blocked it is a design gap

Building and linking is not running. `make tmm` compiles; it never executes TMM. To get real
execution without the pod, a harness on the build box links **the same `ls_vm.c`** that is
compiled into TMM, the **same `libubpf.a`**, and the **same verified object**, built by the
same gcc. Not TMM, but the same code path.

It failed, and the failure is worth more than the run:

```
ls_vm: arm failed: fentry/http_psm_profile_name_lookup function not found.
```

**PREVAIL selects a program by ELF section name. uBPF selects it by function symbol name.**
`ubpf_loader.c:271` does `strcmp(rf.name, main_function_name)` where `rf.name` comes from the
symbol table — while uBPF's header calls that parameter `main_section_name`, which is exactly
how the mistake gets made. Our object carries section `fentry/http_psm_profile_name_lookup`
and function `shield`: two identities for one artifact, with nothing relating them. Filed as
**O14**; `ls_vm_arm()` now takes both and reads the object's symbol table to refuse unless the
named function is defined in the named section.

With that fixed, the shield's instructions execute:

```
ls_vm_arm -> slot 0
  ptlp==NULL -> SAFE_RETURN (the CVE case)                      ok
  ptlp!=NULL, name==NULL -> SAFE_RETURN                         ok
  name_len==0 -> SAFE_RETURN                                    ok
  all present -> FALLTHROUGH (TMM's own body runs)              ok
  monitor mode: CVE case -> FALLTHROUGH (counted, not applied)  ok
  unarmed slot / out-of-range slot -> FALLTHROUGH               ok
  wrong section, absent symbol, truncated object -> refuse      ok
```

**Two self-inflicted errors in that loop, both of which reported a fixed bug as still broken.**
`gcc … | head -12` masked the compiler's exit status, so a stale binary ran. And the rebuild
script did `cp /tmp/harness.c src/base/`, silently reverting the edit immediately before
compiling it. A pipeline that hides an exit status, and a build step that overwrites its own
input, produce the same symptom: a fix that appears not to work.

### Nothing is packaged and nothing is deployed

Worth stating plainly, because "TMM builds with the VM in it" invites the assumption that
something somewhere is running it. **No container image carries this code, and no cluster
exists.**

- `make tmm` links `obj_x86_64.no_pgo/tmm.no_pgo`. It does **not** produce an image.
  `make container` / `make tmm-gdb` do that, and neither has been run since the integration.
- The earlier `tmm:local`, `tmm:local_img` and `tmm_gdb:latest` images **still exist** — an
  earlier note here said they had been deleted, which was wrong: `rm -rf RPMS SRPMS
  docker_build/DEBS BUILD_*` removes build *artifacts*, not Docker images, which live in
  `/var/lib/docker`. They do, however, **predate the VM**, and that was checked rather than
  inferred from timestamps: `tmm:local`'s binary is 56,877,952 bytes — the
  `-fpatchable-function-entry` build exactly — with **zero** `ubpf_*` symbols and no trace of
  the O14 refusal string.

**What the image list is, since "images on the build box" is ambiguous.** Seven tags, five
distinct images: `tc-tmm` and `tc-alien` are **pulled** from Artifactory (the toolchain and the
RPM→DEB converter — tools, not outputs), and three are **built** here. Two of the built ones
carry a second tag under `publish.artifactory.f5net.com/f5-tmm-docker/…`, which is the build
naming its own output for the publish registry — the user-build path into
`input-manifest.yml`. The build is set up to publish; it simply has not.
- The only image on the build box is the toolchain (`tc-tmm:v2.3.1`); the only running
  container is that toolchain.
- `eob-bnk-datkube-01` has kind, kubectl and helm installed but **no cluster created**.

So the chain from here to a running TMM is: `make tmm-gdb` → `docker save` → `scp` →
`kind load image-archive` → `kubectl delete pod`. None of it done. Every cost question waits
on that, and no performance claim can be made before it.

### Can arbitrary bytecode be loaded? Not today, and the reason is not reassuring

**No external path exists.** The program is a byte array compiled into the binary
(`ls_shield_blob.h`); the only caller in TMM is `http_psm_init`. No message handler, no file
read, no socket. Changing the program means rebuilding TMM.

**Do not read that as a safety property — it is the demonstration's central weakness.**
Rebuilding TMM takes about ten minutes here, so "you would have to rebuild" bounds nothing.
What it actually means is that **a shield compiled into TMM is a strictly worse version of
writing the NULL check in C**: same rebuild, same repackage, same redeploy, plus a VM, a
verifier and an interpreter in the path. Everything established today shows the mechanism
works; none of it shows why anyone would want it.

The value is entirely in the rung we have not built:

| rung | changing a shield requires | status |
|---|---|---|
| 1 · compiled in | rebuild, repackage, redeploy | **where we are** |
| 2 · loaded at startup from a file or message | no rebuild — but a restart | not built |
| 3 · loaded into a **running** TMM | nothing: no rebuild, no restart, no maintenance window | **the actual claim** |

Rung 3 is the proposal: a CVE lands, a signed shield goes to fielded systems, no upgrade
window. Rung 1 is a patch with extra steps. The distance between them is scope items **3**
(loader message handler), **4** (in-TMM signature verification) and **0** (the safe point, so
arming does not mean stopping traffic) — and item 0 is the one this repo already flags as
missing from the original scope list and among the largest.

**But the loader would accept anything handed to it**, and that is the part to be honest about:

| gate | present |
|---|---|
| signature check against a baked-in key | **no** — scope item 4, unwritten |
| any evidence in TMM that these bytes were verified | **no** |
| section-vs-symbol identity check | yes (O14) |
| uBPF structural validation — opcodes, registers, jump targets in range, no jump into a `lddw`, calls resolve, self-loop rejected | yes |
| interpreter runtime bounds checks | yes |
| instruction fuel | yes — 10,000 |

An unverified program today would therefore be **contained but not proven**: it cannot corrupt
memory (the interpreter traps first), cannot run away (fuel), cannot jump outside its own code
— but nothing establishes it is the program someone verified, or that anyone verified it.
PREVAIL ran off-box, and **no artifact ties "these bytes" to "were proved safe."** Closing that
is scope items 3 and 4, and `ls_vm.h` says outright that `ls_vm_arm` trusts its input.

**And the containment above is partly an artefact of the slow choice.** Fuel and bounds checks
are *interpreter* properties; the native-code path drops the instruction limit entirely
(finding O6), so switching for speed removes one of the three.

### What this establishes, and what it does not

It establishes that the VM links into TMM's build, instantiates per instance, and is callable
from a real data-path function — the designed-in call form, in source F5 owns.

It does **not** establish anything about cost, and the shortcuts are deliberate and must not
ship:

- **The shield is embedded as a byte array in a generated header.** The real loader receives a
  **signed** program from the control plane and verifies it first. Nothing here checks a
  signature.
- **No trampoline, no pad rewriting, no safe point.** Those exist to reach functions nobody
  planned for. The designed-in call needs none of them, which is exactly why it is the first
  increment.
- **Interpreter, not native code** — fuel works there and is documented as having no effect
  once compiled (finding O6), and the native prologue opens a 4 KB frame with no guard-page
  probe (O7).
- **Nothing is measured.** A call in a build is not a cost at rate.

## First measured invocation cost — 2026-08-12

The VM is armed in a running TMM pod and a program has been priced. Both were open
questions this morning.

```
ls_vm: init  build=Aug 12 2026 18:30:51  jit=0 fuel=0 timing=1
ls_vm: ARMED slot=0 section=fentry/http_psm_profile_name_lookup function=shield
             mode=2 bytes=4320 origin=builtin
ls_vm: bench slot=0 iters=100000 min=138 mean=375 max=1560772 cycles
ls_vm: bench slot=0 iters=100000 min=126 mean=287 max=1403200 cycles
ls_vm: LOADER LISTENING on /tmp/ls_load.sock
```

Two TMM instances, each armed and each benchmarked. Host: Intel Xeon Gold 6348 @ 2.60 GHz.

| | cycles | ns @ 2.6 GHz |
|---|---|---|
| **min** — the cleanest estimate | 126–138 | **48–53** |
| mean | 287–375 | 110–144 |
| max | ~1.5M | scheduler preemption, not the program |

**What must travel with the number:** interpreter (not JIT), a **9-instruction** program, warm
cache, no contention, `ubpf_exec` only — no `ctx` build, no trampoline, no poll loop. It is a
**floor**, and a floor for the smallest useful program.

### Three things it settles

**The "tens of nanoseconds" claim holds.** `big-ip-live-shield-design.md` §11 says an
invocation is *"order tens of nanoseconds — which is emphatically not 'comparable to a C
`if`'"*. Measured ~50 ns. Both halves survive: it is tens of ns, and against a sub-nanosecond
C `if` it is **roughly two orders of magnitude** more expensive.

**`budget_pass.py` under-predicts by ~6×.** It priced this exact program at **~21 cycles**;
it costs **126–138**. The tool's own docstring already says it is uncalibrated and orders
programs rather than predicting nanoseconds — but "we know it is uncalibrated" and "it is
wrong by 6× on the first real program" are different statements, and only the second is
evidence. This is also the **first calibration point that tool has ever had**, and it should
be recorded as one rather than used to justify the tool.

**Variance is the finding the headline hides.** Mean is 2–3× min *with no traffic*, in a tight
loop on an idle box. A p99 argument has to survive that, and the tail here is not the
program — it is the scheduler. Which is the same observation `engine-hard-problems.md` §1
makes about termination not being a time bound, arriving from the measurement side.

### A defect worth knowing: `%zu` does not work in TMM

The arm line reads `origin=builtin(10e0u)` where it should read `builtin(4320)` — 4320 is
0x10E0, so the format rendered hex and left the `u` behind. TMM builds with
`-fno-builtin-printf` and `-Wno-format`, so **`%zu` is not safe in this codebase**; cast to
`unsigned long` and use `%lu`. Cosmetic here, and the kind of thing that silently corrupts a
number in a log someone later trusts.

## Resource footprint of the embedded VM — measured

Like-for-like: both binaries are `tmm64.no_pgo`, both plain `-O2`, one before the VM and one
after. (A first attempt compared `no_pgo` against `debug` and produced deltas of +11 MB of
`.text` — build-type differences, not the VM. Compare the same build type or the numbers are
noise.)

```
baseline 56,449,248  ->  with VM 56,558,560      +109,312   (+0.19% of the binary)

  .text      +81,920   +0.27%
  .rodata    +14,464   +0.13%
  .data       +6,912   +5.55%
  .bss    +1,313,600  +15.62%
```

### The `.text` number is the one that matters, and it is good

**The entire embedded VM — uBPF's interpreter, ELF loader, relocation, our integration, the
config reader and the load path — costs +81,920 bytes of `.text`, +0.27%.**

For scale, that is *less than the entry-padding flag*, measured earlier at +0.476% for
`-fpatchable-function-entry=5,0` at 48.9% coverage. **The engine is cheaper in code than the
mechanism for attaching to it.** Both are well under one percent, which is the useful headline:
the objection to embedding a VM in TMM is not going to be image size.

### The `.bss` number was a self-inflicted mistake, now fixed

`.bss` grew **1.31 MB, 15.6%**, and the arithmetic is unambiguous: a 1 MB static receive buffer
in the loader plus a 256 KB static file buffer come to 1,310,720 of the 1,313,600.

Two statically-sized worst-case buffers, permanently resident, for memory used **only at load
time** — in a process that runs **one instance per core**. On a 16-core box that is ~21 MB of
zero-filled pages to receive a control message that arrives approximately never.

Both now allocate on demand and free after use. The load path is off the data path, so a
`malloc` there costs nothing that matters, and the file buffer is dead the moment `ls_vm_arm`
returns because uBPF has already copied the program.

**The general rule this is an instance of:** in a per-core process, every static buffer is
multiplied by the core count, and a data plane is exactly where that multiplication is least
affordable. `.bss` is demand-zero so untouched pages may never be resident — but the load
buffer *is* touched on the first load, which makes it real rather than theoretical.

### Still unmeasured

Instruction-cache and i-TLB pressure, for both the VM's `.text` and the padding — the part of
`design-review-findings.md` §4 that needs a running TMM under load. And per-instance heap: each
`ubpf_create` plus its stack, which is small but has not been counted.

## Traffic through the proxy — where this got to

The topology exists and is more complete than expected: `bnk-core` ships a **two-armed test
harness** — `client` (11.11.11.100) and `server` (22.22.22.100) pods on Multus networks either
side of TMM, VLANs `tmm-client` / `tmm-server`, and TMM self-IPs on both. The client image
carries `curl`, `wget`, `nc` and **`ab`**, so load generation needs nothing installed.

**What is configured and accepted:**

```yaml
kind: Pool                     # NOT F5BigCnePool --- that CRD is not in bnk-core
  members: [{address: 22.22.22.100, port: 80}]
kind: F5VirtualServer          # plural f5-virtualservers.k8s.f5net.com
  destinationAddress: 11.11.11.99
  destinationPort: 80
  fastL4: sys-default-fastl4   # a PROFILE --- without one, TMM logs
                               # "Proxy initialization failed ... Defaulting to DENY"
  protocol: tcp
  pool: ltm-pool-basic
  snat: {type: automap}        # lower-case; loadBalancingMethod is UPPER (ROUND_ROBIN)
  vlans: {vlanList: [tmm-client]}
```

TMM commits both — `decl_pool_obj_commit: Add pool name = default-pool-ltm-pool-basic-pool`,
with audit records for the pool and its member list, and no proxy-initialisation error.

**What still does not work:** the connection is refused. The remaining suspect is an
**address conflict** — TMM logged `01190004:4: address conflict detected for 11.11.11.99` and
that address answered ping *before* anything was created, so something else already owns it.
The reference profile (`profiles/virtualserver`) assumes `.99` is free; in this cluster it is
not, and that profile also ships `cnf-values.yaml` and cert-manager resources, suggesting it
expects a different base than `bnk-core`.

**Reference configs worth knowing about**, since deriving them cost time:
`profiles/virtualserver/resources/{virtualserver,pool}.yaml` is the canonical pair;
`profiles/tcpopt-core/resources/virtual.yaml` uses a different CRD (`F5BigContextSecure`) that
is not installed here. Check which CRDs exist before adapting a manifest — `kubectl get crd`
against the kind, not the filename.

**Nothing has reached the hook yet**: `FIRST INVOCATION` has not appeared, and the shield's
`fired` counter is 0. The VM is armed and benchmarked; it has not been driven.

## The JIT, and the shield demonstrated — 2026-08-12, evening

### The JIT is ~4.8× the interpreter, and this is its first real measurement

The previous JIT figure was not the JIT. `ubpf_exec`/`ubpf_exec_ex` **always interpret**; a
compiled program is reachable only through the pointer `ubpf_compile` returns, which the code
was discarding. The benchmark now prints which path it measured, precisely so that cannot recur.

| path | min | mean | max | ns @ 2.6 GHz (min) |
|---|---|---|---|---|
| interpreter | 126 | 240 | 2,471,618 | **48** |
| **JIT** (extended mode) | **26** | **74** | 233,286 | **10** |

Same program, same box, one environment variable apart. The tail improves too — max falls by an
order of magnitude, which matters more for a p99 argument than the floor does.

**Against `big-ip-live-shield-design.md` §11's "order tens of nanoseconds":** the JIT is 10 ns,
at the low end of tens; the interpreter is 48 ns. Both survive the claim. Against a
sub-nanosecond C `if`, the JIT is still **roughly an order of magnitude** more expensive, so the
"emphatically not comparable to a C `if`" half also stands.

**A hypothesis of mine that the measurement killed.** `ubpf_exec` declares its 4 KB program
stack as a local, so every invocation opens a 4 KB frame; this note previously said that was
"very likely a real share of the 126-cycle floor". It is not. Moving to a per-instance stack
left the floor unchanged (126→126, 138→132). Obvious in hindsight: allocating stack is a
`sub rsp, N`, and untouched pages are never faulted in. **The change is still correct** — it
removes O7's unprobed-frame hazard from the call path — but it buys nothing measurable, and the
earlier claim should not be repeated.

### The shield, demonstrated without traffic

`LS_VM_SELFTEST` builds the `ctx` the vulnerable call site would build with a NULL
protocol-transfer log profile, runs it through the armed shield, and at level 2 performs the
dereference if the shield declines. Two runs of **one image**, one environment variable apart:

```
LS_SHIELD_MODE=enforce   SELFTEST cve-condition ptlp=NULL -> verdict=SAFE_RETURN
                         SELFTEST survived --- shield prevented the dereference
                         pods Running, restarts=0

LS_SHIELD_MODE=monitor   SELFTEST cve-condition ptlp=NULL -> verdict=FALLTHROUGH
                         SELFTEST performing the unshielded dereference --- expected fatal
                         <log ends; rollout times out; that pod is replaced>
```

**Monitor mode is the right lever here**, and not merely a substitute for disabling: it is the
real posture an operator uses before enforcing, and it shows the shield *recognising* the
condition — `verdict` reflects the program's decision — while the host declines to act on it.
`LS_SHIELD_ENABLE=0` would skip arming altogether, so the self-test would never run.

**What the evidence supports, precisely.** The code prints `SELFTEST did NOT crash` if the
dereference returns; that line never appeared, the log ends at the attempt, and the pod was
replaced rather than continuing. That is strong, but it is **not** a captured exit code or
signal — the pods churned before one could be inspected, so "the process did not continue past
the dereference" is the defensible statement, not "confirmed SIGSEGV".

**And what it does not show**, unchanged: that the hook is correctly placed in
`http_psm_profile_name_lookup`, or that live traffic reaches it. This synthesises the condition;
it does not drive the path.
