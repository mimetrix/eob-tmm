# TMM build environment — running log

**Goal:** stand up an OpenStack instance that can **build TMM**, then ship
the resulting artifact to a *separate* machine to run it. Every step gets
recorded here as it happens so the whole thing is reproducible from
scratch rather than rediscovered.

Two distinct machines — do not conflate them:

| Role | What it does | Kernel/image requirement |
|---|---|---|
| **Build host** | Compiles TMM. First instance to be stood up. | TBD — awaiting internal guidance. Whatever the TMM build toolchain requires. |
| **Run target** | Receives the built artifact (`scp`) and runs it. | TBD. This is the box whose kernel matters for eBPF (BTF/CO-RE) — see [04](bigip-ve-boot-2026-07-17.md). |

The build host's kernel is largely irrelevant to eBPF *for this project* —
it only needs to satisfy the TMM build. The **run target's** kernel is
the one that determines whether CO-RE eBPF is possible at all.

## Status — 2026-08-11

Awaiting internal guidance on the build procedure. Confirmed so far:

- Both OpenStack stacks are network-reachable from this sandbox (below).
- `python-openstackclient` rebuilt in this sandbox (below).
- **Credentials live on both stacks.** Application credentials merged into
  `~/.config/openstack/clouds.yaml` (mode 600) as clouds `sjc` and `sea`;
  `openstack project list` succeeds against both. Both projects are named
  `starin` but are distinct projects, one per stack.
- **Both stacks inventoried** — quota, flavors, images, networks. See the
  comparison below. **Rocky-based TMOS images exist on both**, which
  resolves the July image blocker in principle.
- Nothing launched yet.

## Open questions (waiting on guidance)

1. ~~**Which stack**~~ — answered by measurement, not guidance: **SEA** has
   2× the usable quota ceiling. See the comparison table. Still worth
   confirming against the recommendation when it arrives, in case the
   build procedure assumes a particular site.
2. **Kernel version / image** for the build host — not yet recommended. Note
   the distinction: an image *name* containing `rocky` is not proof of
   kernel version or BTF support; verify with `uname -r` and
   `/sys/kernel/btf/vmlinux` after first boot.
3. **Specialized VM?** There may be a purpose-built build image or flavor
   rather than a generic Linux one. Unknown. Neither stack's image list has
   an obvious `*build*` image, so if one exists it is either named
   unexpectedly or lives outside these two catalogs.
4. **Build → ship workflow** — current understanding is: build on the VM,
   then `scp` the app elsewhere. Destination, artifact layout, and
   whether anything else (deps, licensing, a specific runtime) has to
   travel with it are all unconfirmed.
5. Where the TMM **source** comes from on the build host (Perforce?
   `PerforceAccessNet` exists on **both** stacks — see the comparison
   table and
   [`openstack-cli-reference.md`](openstack-cli-reference.md#networks-available-this-project)).

## Decision: don't create a dedicated project yet — 2026-08-11

Considered creating a purpose-built OpenStack project for TMM build work
instead of using the existing personal `starin` project. **Deferred.**
Rationale, in order of weight:

1. **A fresh project may not have the networks.** Neutron networks are
   project-scoped unless shared. `starin` demonstrably sees
   `AdminNetwork`, `AllTestVLANs`, and **`PerforceAccessNet`** — the last
   of which is likely how the build host reaches source. A new project
   could come up with none of them, breaking the sync path before it's
   ever been tried. Inheriting known-good network access beats tidiness.
2. **Probably not self-serve.** `openstack project create` needs `admin`
   on the domain; `starin` appears to be a personal project in domain
   `olympus`. This would be a cloud-team ticket, i.e. a slow blocker
   taken on before the build requirements are even known.
3. **Nothing to isolate from.** As of 2026-07-17 `starin` had zero
   servers, zero keypairs, and only an empty `default` security group —
   already effectively a clean room.
4. **The pending guidance may specify a project.** If TMM builds
   conventionally run in a team build project with the image and Perforce
   path already wired, a self-made project is wasted work. **Ask about
   this explicitly** when the recommendation arrives.

**The likely real constraint is quota, not project boundaries.** Measure
it as soon as credentials land, per stack:

```bash
OS_CLOUD=sjc openstack limits show --absolute   # cores/RAM/instances/volumes, used vs max
OS_CLOUD=sjc openstack quota show
```

Raising quota on an existing project is a smaller ask than provisioning a
new one — and "the build needs N vCPU / M GB and this project caps at X"
is a far better ticket than a speculative request.

**Revisit the decision if:** more than one person needs the build host or
artifact; quota can't be raised on `starin`; build churn (images, volumes,
snapshots) warrants independent lifecycle/cleanup; or policy forbids build
artifacts in personal tenancy.

**Gotcha to expect either way:** an application credential is scoped to
whichever project was selected at creation time. Switching projects later
means **recreating the credential** — it does not follow you.

## CBIP vs MBIP — the fork that reorganises this whole document

**Read this before anything below it.** There are two TMMs and two build worlds, and
most of the confusion in earlier revisions of this file came from not separating them.
The distinguishing sentence is in F5's own "Build f5-tmm container image" page:

> *"In the same way in **CBIP** we use **seadev** to build TMM, in **MBIP** the
> toolchain_container is equivalent to the seadev server in CBIP."*

| | **CBIP** — classic BIG-IP | **MBIP** — containerized (BNK / SPK / CNF) |
|---|---|---|
| source | **Perforce** | **GitSwarm** — `gitswarm.f5net.com/tmm/tmm.git` |
| build machine | the **`seadev`** server | **`toolchain_container`** — a container, pulled from Artifactory |
| TMM runs as | TMOS appliance / VE | a **Kubernetes pod** (`deploy/f5-tmm`, label `app=f5-tmm`) |
| dev environment | — | **Datkube** — a `kind` cluster |

**So "you will need Perforce" is true for CBIP and false for MBIP.** If the target is
classic BIG-IP, Perforce and `seadev` are the path. If it is the containerized data
plane, source is git and the build machine is a container you pull. Everything else in
this file, and both Confluence pages this work drew on, is the **MBIP** branch.

**Which branch answers which question.** The worked CVE in
[`../big-ip-live-shield-design.md`](../big-ip-live-shield-design.md) §14 is a TMOS
logging path, so condition 1 of §10.1 for *that function* needs a CBIP build. The
general engineering questions — hookable-set size, whether
`-fpatchable-function-entry` applies cleanly, whether a trampoline works, whether
backtraces survive it — are answerable from MBIP, and MBIP is reachable today while
CBIP is not.

## How a BNK build actually works

BNK is not one program. It is a product **assembled** from dozens of independently
built components, each with its own repo and CI. The pipeline is an assembly line for
combining separately-built things — closest analogy is a Linux distribution, where
each package builds alone, publishes to a repository, and a manifest names the exact
versions that constitute a release.

```
f5ingress/…            L1 — components build themselves, publish artifacts to Artifactory
      |
helm chart repos       packaging — k8s deploys charts, not binaries
      |
f5-mbip-build          ASSEMBLY — input-manifest.yml is the bill of materials;
      |                            first point everything coexists, so integration tests run here
f5-stage5-build        FINAL PACKAGING (note: on gitlab.f5net.com, a different host)
      |
test candidate / release artifact
```

TMM's path through it: `tmm` (core engine) → build artifact → `f5-tmm-helm-charts` →
referenced in f5ingress's `input-manifest.yml` → `f5-mbip-build` → `f5-stage5-build`.

**`input-manifest.yml` is the injection point, and that is the useful part.** A change
can be tested in a full BNK build *without merging it*: build your component, its
artifact lands in Artifactory as a **user build**, override that component's version in
the manifest, and assembly runs integration tests against your build. After merge a
"stage bot" propagates versions downstream.

**Three tiers, and we want the first two.**

| goal | what you run |
|---|---|
| iterate on TMM | `make start && make tmm && make unittest` |
| see it running | Datkube fast-cycle — build, `kind load`, delete the pod. **Bypasses the pipeline entirely**, which is its stated purpose |
| a full product build | publish artifact → override in `input-manifest.yml` → assembly |

## The TMM dev loop, and the one target that matters here

```bash
git clone https://gitswarm.f5net.com/tmm/tmm.git   # ← the only blocked step
cd tmm && git checkout -b my-change
make start        # pulls toolchain_container (18.1 GB) from Artifactory, runs it
                  # …edit source, e.g. src/base/flow_table.c : flow_input()…
make tmm          # builds the binary INSIDE the toolchain container
make unittest     # the docs call this mandatory before integration
make container    # → docker image tmm:local
```

Before `make container`, **delete prior artifacts or your change is silently absent**
from the new image — it builds, deploys, and runs the old code:

```bash
sudo rm -rf RPMS SRPMS docker_build/DEBS BUILD_* docker_build/tmm-runtime.*
```

**`make tmm-gdb` is the target this project needs**, because everything we want comes
from what stripping removes:

```
tmm-gdb: make tmm && make clean_rpms &&          make GDB_INCLUDE=true INSTALL_DEBUG_TMM=TRUE container
```

Deploy on a single box (no `scp`, no `datpush` — those exist because build host and
Datkube host are normally different machines):

```bash
kind load docker-image tmm:local --name datkube
kubectl delete pod -l app=f5-tmm
```

One-time, so the deployment stops pulling from Artifactory:
`kubectl edit deploy/f5-tmm` → `image: tmm:local`, `imagePullPolicy: Never`.

## Stack reachability — verified 2026-08-11

Both stacks answer on Keystone v3. Naming pattern is identical, just
site-swapped (`sjc-stack`/`pdsjc` ↔ `sea-stack`/`pdsea`).

| | SJC | SEA |
|---|---|---|
| Keystone API | `https://keystone.sjc-stack.pdsjc.f5net.com/v3` | `https://keystone.sea-stack.pdsea.f5net.com/v3` |
| Horizon (web UI only) | `https://horizon.sjc-stack.pdsjc.f5net.com` | `https://horizon.sea-stack.pdsea.f5net.com` (assumed, not yet loaded) |
| Resolves to | `10.197.12.17` | `10.145.23.16` |
| Keystone version | v3.14 stable | v3.14 stable |
| HTTP status on `/v3` | 200 | 200 |
| TLS cert CN | `sjc-stack.sjc-stack.pdsjc.f5net.com` | `sea-stack.sea-stack.pdsea.f5net.com` |
| TLS issuer | `DC=com, DC=F5Net, CN=F5 F5NET Issuing CA` | same |
| Cert validity | 2026-05-19 → 2028-05-18 | 2026-05-19 → 2028-05-18 |

TLS note: verification fails against both the system trust store **and**
`~/netskope-ca.pem` — neither chains to `F5 F5NET Issuing CA`. So
`verify: false` in `clouds.yaml` is still required here, same as
[03](openstack-cli-reference.md#credentials--cloudsyaml). Getting the
real F5 internal CA bundle into the sandbox would be the clean fix.

Quick recheck of reachability at any time:

```bash
for h in keystone.sjc-stack.pdsjc.f5net.com keystone.sea-stack.pdsea.f5net.com; do
  printf '%-45s ' "$h"
  curl -sk -m 15 -o /dev/null -w 'http=%{http_code}\n' "https://$h/v3"
done
```

## SSH access to instances — verified 2026-08-11

We will need to SSH into the build host (and `scp` the artifact off it),
so this was checked ahead of having any instance to log into:

- **Client:** OpenSSH 9.2p1, plus `scp`/`sftp`/`ssh-keygen` on PATH.
- **Outbound TCP/22 works.** Confirmed against a real SSH endpoint:
  `ssh -T git@github.com` authenticated successfully. Port 22 is not
  filtered out of this sandbox.
- **`~/.ssh` is a READ-ONLY virtiofs mount** (`ro,relatime`, sourced from
  `<host>/e.starin/.ssh`). Two consequences:
  - New OpenStack keypair private keys **cannot** be written there →
    store under `~/.config/openstack/keys/` (mode 600), as in
    [03](openstack-cli-reference.md#launching-an-instance-big-ip-ve-example).
  - New `Host` entries **cannot** be appended to `~/.ssh/config` → either
    pass `-i`/`-o ProxyJump=` explicitly, or keep a writable alternate
    config elsewhere and use `ssh -F <path>`.
- **Existing jump host works:** `jump-eob` (`10.196.23.236`, user
  `elliott`, key `~/.ssh/id_deploy`) — TCP open and SSH auth succeeds.
  This is the most likely path to reach instances on the internal stack
  networks if they aren't directly routable.
- `ocp-jump` (`10.192.225.243`): connection **refused** on 22 — down or
  moved.
- `build-eob` in `~/.ssh/config` points at `192.0.2.236`, which is in the
  `192.0.2.0/24` TEST-NET-1 documentation range — a placeholder, not a
  real address. No connect, as expected. Worth noting in case a *real*
  build host was meant to land there; that config entry (user `ailab`,
  `ProxyJump jump-eob`) may be the intended shape of the TMM build host.
- Stack controller IPs on port 22: SJC `10.197.12.17` filtered (timeout),
  SEA `10.145.23.16` returns TCP **refused** — i.e. routed and answering,
  just no SSH listener. Neither is meant to be logged into directly.

## Perforce (source access) — probed 2026-08-11

TMM source comes from Perforce. Where the `p4` client lives — the
recommended build VM, or somewhere else — is **not yet confirmed**. What's
known from here:

- **No `p4` client in this sandbox**, and no `P4PORT`/`P4CLIENT`/`P4USER`
  environment variables set.
- `perforce.f5net.com` and `perforce.olympus.f5net.com` both resolve to
  **`192.168.13.205`**. (`p4.f5net.com`, `p4proxy.f5net.com`,
  `perforce-sjc/sea.f5net.com` do not resolve.)
- **Not reachable from this sandbox** — no connect on 1666, 1667, 22, or
  443. DNS resolves but nothing routes.

That last point is consistent with Perforce access being a property of the
**build VM**, not this sandbox: **both** stacks carry a dedicated
`PerforceAccessNet` network (confirmed 2026-08-11 — see the comparison table
and
[`openstack-cli-reference.md`](openstack-cli-reference.md#networks-available-this-project)),
which strongly suggests the build host needs a NIC on it to sync source.
Treat that as the working hypothesis, to be confirmed against the guidance:

- If the recommended image ships `p4` preinstalled and configured →
  attach a `PerforceAccessNet` NIC at launch and sync on the VM.
- If not → we install/configure `p4` on the VM ourselves, and need a
  Perforce credential + client spec (and the depot path for TMM).
- Since the network exists on both stacks, Perforce access does **not**
  discriminate between SJC and SEA.

### What `PerforceAccessNet` actually is — inspected 2026-08-11

The hypothesis above survives, but "attach a NIC and sync" is **necessary and
not sufficient**, and the reason is worth having before the first boot rather
than after it.

| | SJC | SEA |
|---|---|---|
| subnet | `PerforceSub-2731` | `PerforceSub-2867` |
| CIDR | `10.197.72.0/22` | `10.145.160.0/22` |
| gateway | `10.197.75.254` | `10.145.163.254` |
| DHCP | on | on |
| `host_routes` | **empty** | **empty** |
| DNS pushed | `10.196.1.1`, **`192.168.180.15`** | `172.27.1.1`, **`192.168.180.15`** |

Three things follow.

1. **Perforce is not on-link.** `192.168.13.205` falls inside neither CIDR, so
   an instance on this network reaches it only by **routing through the subnet
   gateway**. Being attached is not being connected.
2. **DHCP will not give you the route.** `host_routes` is empty on both, so
   nothing pushes a route for the Perforce prefix. It has to come from the
   **default route** going out this NIC — which is the gotcha, because a build
   host wants a management NIC too, `AdminNetwork` is also DHCP-enabled and also
   offers a gateway (`10.197.63.254` / `10.145.63.254`), and a two-NIC instance
   therefore boots with **two default-route candidates**. Whichever wins decides
   whether Perforce traffic leaves by the right interface. A "the NIC is attached
   but p4 times out" symptom is this, not a firewall.
   *Fix deterministically rather than hoping:* either make `PerforceAccessNet`
   the default route, or add an explicit static route for the Perforce prefix via
   that subnet's gateway. Do not rely on NIC ordering.
3. **The real discriminator is DNS, not routing.** Both networks are ordinary
   internal `shared` networks with a gateway; what makes this one *the Perforce
   network* is that it pushes an **extra resolver, `192.168.180.15`**, which
   `AdminNetwork` does not. That address is in the same `192.168/16` space as
   Perforce itself, so it is very likely the resolver that knows that estate.
   Consequence: **resolving `perforce.f5net.com` may itself depend on being on
   this network**, so DNS and reachability both hinge on the NIC, and a host that
   can route there but resolves via `AdminNetwork`'s server alone may still fail.

**Also noticed while looking:** SEA's `AdminNetwork` is **dual-stack** — an IPv6
`2620:128:e008:4806::/64` alongside the IPv4 `10.145.32.0/19`. SJC's is IPv4 only.
Not in the comparison table above, and it matters at boot: a dual-stack NIC changes
default-route selection and which address SSH lands on.

**Still unverified, and still needs a boot:** that traffic actually reaches
`192.168.13.205:1666` from an instance, and whether any image ships `p4`.

## Image inventory — what is and is not a build environment (2026-08-11)

Checked because the natural assumption is that the image catalogue contains a
ready-to-build TMM environment. **It does not**, and the two families you would
reach for first are opposite ends of what a build needs.

SEA's 220 images, by family:

| family | count | what it is |
|---|---|---|
| `BIGIP-…` | **75** | BIG-IP VE **appliance** images — the shipped product |
| `FN-License-Proxy-…` | ~57 | a licensing component, unrelated |
| `Ubuntu*-pristine`, `Rocky*-pristine` | ~19 | *pristine* means clean OS, no F5 tooling |
| BIG-IQ, Windows, Cirros, `bnk-…` | ~16 | unrelated |
| **`ite-el{6,7,8}-chroot`** | **3** | the only build-shaped images present |

- **`BIGIP-tmos-rocky-22.0.0-0.0.570` runs TMM; it cannot build it.** Locked-down
  TMOS: no compiler, no source tree, no `p4`.
- **`RockyLinux8.10-pristine` is a blank OS.** A starting point, not an
  environment.
- **Corrected 2026-08-11, same day.** An earlier revision of this section concluded
  "no build environment exists in the catalogue." That was wrong, and both reasons
  are worth keeping. The search pattern was `devel`, so **`Datkube-Devbox-*` slipped
  straight through** — `dev` would have caught it. And the search was over image
  *names*, when the manifest is in an image **property**: `Datkube-Devbox-Berge`
  carries its own `description` listing what is installed. Searching names alone
  cannot find that.

| `Datkube-Devbox-…` | SEA | what its own `description` property says |
|---|---|---|
| `Datkube-Devbox-Berge` | `abecfaf0-4fa1-4519-a1a7-fcd316506f1c` | Creator: Michael Berge. **Installed Tools:** Datkube, Docker, GCC, GDB, Go, Helm, iproute2, Kind, Kubectl, net-tools, yq |
| `Datkube-Devbox-050323-Ahanchi` | `1792cb21-9197-46f3-b875-31c769edacaa` | 0.88 GB, `min_disk 0` — too thin to hold much; older |

`Datkube-Devbox-Berge` is 3.74 GB, `min_disk 40 GB`, created 2025-08-20, public,
owned by project `b5139c56…`. **It is a snapshot, not a curated image** —
`image_type: snapshot`, `owner_user_name: berge`, with a `base_image_ref` to
something else. That is "what one engineer had installed on that date", captured.
Nobody owns keeping it current.

**Tools, not source, and not a complete build machine.** The property says
*Installed Tools* and lists no source tree, and — the gap that matters — **no `p4`**.
3.74 GB is consistent with Ubuntu + Docker + Go + k8s tooling; a TMOS source tree
would make it far larger. So the three pieces stay separate: the devbox supplies the
**runtime target** (kind/kubectl/helm/docker) and a **toolchain** (gcc/gdb/go), while
**source still comes from Perforce** and needs a client, a credential, a client spec
and a depot path, none of which are settled.

**`ite-el*-chroot` is the candidate.** EL6 / EL7 / EL8, 3.44 / 4.06 / 6.34 GB
qcow2, `visibility: public`, owned by project `b5139c56d5be4d5fab0ae834d900ae0c`
(not ours), created 2025-06 and 2026-04. Image IDs on SEA:

| image | id |
|---|---|
| `ite-el6-chroot` | `0dc96a6a-dc2d-4625-979e-c32384bae36b` |
| `ite-el7-chroot` | `b4e16837-b352-4c04-aad3-ffb20848220e` |
| `ite-el8-chroot` | `6013a7c4-be93-4c71-9148-db597a69eebf` |

"chroot" plus a per-EL-generation split is the shape of an **RPM build root**, which
is how a product like TMOS is built — inside a versioned chroot so the toolchain is
pinned to the target's base OS, not on the host. The EL6→EL7→EL8 progression tracks
TMOS's own base-OS progression and 6.34 GB is a populated root rather than a minimal
OS. **All of that is inference from name, size and generation.** Unconfirmed: what is
inside one, what `ite` expands to, whether it is meant to be booted or attached and
`chroot`'d into, and whether `p4` is present anywhere.

**Cheap decisive test, not yet run:** boot or attach `ite-el8-chroot` and look for
`gcc`, `rpmbuild` and F5 build macros. If it is the build root, the build-host
question changes from "provision a toolchain" to "boot the one F5 already ships."

## The build procedure — from "Fast cycling tmm builds in a Datkube environment"

Source: internal Confluence page `~smccarthy` / `1162662642`, read from a PDF export
on 2026-08-11. The export is **deliberately not committed** (`.gitignore` covers
`*.pdf`) — it carries internal hostnames and usernames and this repo pushes to
GitHub. What follows is the operational content in our own words.

**The shape, which is the part worth understanding first: TMM builds into a
container image and runs as a Kubernetes pod.** Not an appliance boot. Two machines
are involved and the loop between them is entirely SSH-driven. The page is explicit
that this **deliberately bypasses CI/CD** — "too slow, bloated, error prone" — so it
is the fast path, not the sanctioned one.

### One-time setup

1. **SSH private-key auth from the build machine to the Datkube machine.** Not
   optional: every deploy step runs over `ssh`/`scp`.
2. **On the Datkube machine**, point the deployment at a local image instead of the
   registry — `kubectl edit deploy/f5-tmm`, then set

       image: tmm:local
       imagePullPolicy: Never

   Without this it keeps pulling from Artifactory and your build is ignored.

### The cycle

On the **build machine**:

```bash
# Delete prior build artifacts FIRST. They may be root-owned, and if they
# survive, your changes silently will NOT be in the new container — it builds,
# deploys and runs the old code. This is the failure mode to remember.
sudo rm -rf RPMS SRPMS docker_build/DEBS BUILD_* docker_build/tmm-runtime.*

make tmm container                      # -> docker image 'tmm:local'
docker save tmm:local -o /tmp/tmm-local.tar
scp /tmp/tmm-local.tar dev@<datkube-host>:/tmp
```

On the **Datkube machine**:

```bash
kind load image-archive /tmp/tmm-local.tar --name datkube
kubectl delete $(kubectl get pods -l app=f5-tmm -o name)   # k8s restarts on the new image
```

A `datpush` script chains the save / scp / `kind load` / pod-delete steps, so the
whole cycle is one line:

```bash
sudo rm -rf RPMS SRPMS docker_build/DEBS BUILD_* docker_build/tmm-runtime.* \
  && make tmm container && datpush
```

Its default `DATHOST=10.145.35.215` sits inside **SEA's** `AdminNetwork`
(`10.145.32.0/19`, verified), so Datkube boxes live on SEA — consistent with SEA
being the recommendation on quota.

### A second path, aimed at debugging

Christian Koenning, `gitswarm.f5net.com/koenning/k8s_tmm_gdb` — take a
locally-built TMM **binary** into a Datkube container, with the emphasis on running
it under **gdb**. Not read yet; more directly relevant to this repo's work than the
container-cycling path, because the questions here are about TMM's internals.

### What this does NOT tell us

- **Where the source comes from.** `make tmm` presumes a tree; Perforce is still the
  unresolved half (client, credential, client spec, depot path).
- **What `make tmm` runs inside.** Whether the build happens on the devbox directly
  or inside a chroot — which is where `ite-el*-chroot` may fit, since the Makefile
  clearly produces `RPMS`/`SRPMS`. The page never mentions the chroots, so that
  remains inference.
- **Whether `Datkube-Devbox-Berge` is the build box, the Datkube box, or both.** It
  has the tools for either.

### Where our validation diverges from this loop — and stops earlier

For the questions this repo actually needs answered, **the procedure stops at
`make tmm`.** Everything after it — `container`, `docker save`, `scp`,
`kind load`, `kubectl delete` — exists to *run* TMM in Datkube, and the two cheapest
validations do not need it running at all:

1. **`nm` over the built binary.** How many functions survive `-O2` as their own
   out-of-line body is the real size of the hookable set, and it is what item 5's
   known `hookable()` bug turns on. It also settles whether the worked example's
   `fw_log_prot_transfer_emit` survives — **condition 1 of
   [`../big-ip-live-shield-design.md`](../big-ip-live-shield-design.md) §10.1, the
   one condition that example asserts rather than establishes.** A built binary and
   `nm`. No k8s, no running TMM.
2. **The `-fpatchable-function-entry` build comparison.** Build twice, with and
   without, and compare. The *build* half is cheap and answers whether the flag even
   applies cleanly to this codebase and what it does to size; only the dark-cost
   measurement at rate needs a running TMM.

Both still need source. So Perforce, not Datkube, is the real gate on validating
anything here.

### The authoritative source for compile/debug is a Confluence page we cannot read

`DEV TMM Compile and Debug` — `docs.f5net.com/spaces/~garlapati/pages/936700918/`
— is presumably the real answer to compile-and-debug, and it is **blocked on the
same Confluence auth wall already recorded** for the MCP Server page: reachable at
`172.25.8.129`, redirects to `/login.action?…permissionViolation=true`, and
`/rest/api/content/936700918` returns a clean `401`. See
[`bigip-mcp-server.md`](bigip-mcp-server.md) for the blocker and the
personal-access-token route rather than a second copy of it here. Until that page is
readable, everything in this section is inference and should be replaced by whatever
it says.

## Can we create instances on either stack?

**Yes — as of 2026-08-11 nothing technical blocks it.** Credentials work on
both stacks, the CLI is installed, both Keystone endpoints answer, the SSH
path is proven, keypair storage is settled, and the launch recipe
(flavor/image/`--nic`/`--no-security-group` gotcha) is written up in
[`openstack-cli-reference.md`](openstack-cli-reference.md#launching-an-instance-big-ip-ve-example).
Quota on both projects shows **0 instances used**, so the full allowance is
available.

What's deliberately *not* done: nothing has been launched, because the
build-host **kernel/image recommendation is still outstanding** (open
question 2). Launching a guessed image would burn quota and produce a box we
might have to discard. The one cheap, informative exception worth doing early
is booting a Rocky-based TMOS image purely to **read its kernel version and
check for BTF** — that answers the July blocker directly and can be deleted
immediately after.

First step when resuming, on SEA, using an image **ID** not a name:

```bash
export OS_CLOUD=sea
mkdir -p ~/.config/openstack/keys
openstack keypair create tmm-build > ~/.config/openstack/keys/tmm-build.pem
chmod 600 ~/.config/openstack/keys/tmm-build.pem
# kernel/BTF probe — BIGIP-tmos-rocky-22.0.0-0.0.570 on SEA
openstack server create --flavor F5-BIGIP-large \
  --image d5030127-bed3-480c-8f51-6e1a5a703ec0 \
  --nic net-id=AdminNetwork --no-security-group \
  --key-name tmm-build tmm-kernel-probe
openstack console log show tmm-kernel-probe | grep -i kernel
```

Expect the same first-boot credential problem as
[`bigip-ve-boot-2026-07-17.md`](bigip-ve-boot-2026-07-17.md) documents — the
console log may answer the kernel question without a shell at all, which is
why it's the cheapest probe available.

## SJC vs SEA — differences

**Measured 2026-08-11**, authenticated against both. Recommendation: **SEA
for the build host**, on quota headroom — see below.

| Dimension | SJC | SEA |
|---|---|---|
| Project | `starin` (`c0007f99321f4db98b168b1d17f7d7c2`) | `starin` (`fc383461f577439f84bf4cc4301c43a8`) — same name, **different project** |
| **Quota: cores** | **20** | **40** |
| **Quota: RAM** | **51200 MB (50 GB)** | **81920 MB (80 GB)** |
| Quota: instances | 10 (0 used) | 10 (0 used) |
| Largest flavor that **fits** quota | 16 vCPU / 32 GB (`datkube-dev-large`) | 32 vCPU / 64 GB (`F5-XCIAB-xlarge`) |
| Flavors defined | 43 | 40 |
| Images | 97 | 220 |
| Rocky-based TMOS | `BIGIP-tmos-rocky-22.0.0-0.0.{569,570}` | `…-0.0.{568,569,570}` |
| Rocky Linux base images | `RockyLinux8.10-pristine`, `RockyLinux10-pristine`, `rocky8-cloud`, `rocky9-cloud` | `RockyLinux8.10-pristine`, `RockyLinux9-pristine`, `RockyLinux10-pristine`, `rockylinux_9.2-pristine` |
| BNK images | none | `bnk-Ubuntu22.04.3LTS-pristine`, `bnk-latest-Ubuntu22.04.3LTS-pristine` |
| Networks | `AdminNetwork`, `AllTestVLANs`, `QuarantineNetwork`, `PerforceAccessNet`, `k8s-ext` | same **plus** `CustomerConfig`, `LB-VIP-Net` |
| `PerforceAccessNet` | ✅ | ✅ |

### What follows from this

**The July blocker is resolved — on both stacks.**
`BIGIP-tmos-rocky-22.0.0-0.0.570` is a **Rocky-based TMOS image**, which is
exactly what [`bigip-ve-boot-2026-07-17.md`](bigip-ve-boot-2026-07-17.md)
was waiting for. **Unverified:** its actual kernel version and whether
`CONFIG_DEBUG_INFO_BTF` is set — that needs a boot and
`uname -r` / `ls /sys/kernel/btf/vmlinux`, which is the first thing to do
once a build host exists. Image *name* is not proof of kernel version.

**Quota is the real differentiator, and it favors SEA.** SJC's 50 GB RAM cap
means the 64 GB flavors cannot run there at all, and its 20-core cap rules
out anything above 16 vCPU. SEA's 40 cores / 80 GB admits 32 vCPU / 64 GB.
For a compile-heavy TMM build, cores and RAM are the binding constraint, so
SEA has roughly **2× the usable ceiling**.

**Do we need both stacks?** Strictly no — one is enough to build on. Keeping
both is still worth it: it cost one extra application credential, SEA is
measurably the better build host, SJC holds all the prior groundwork and is
the documented fallback, and SEA additionally carries BNK images relevant to
this project's third form factor. If build and run targets end up on
*different* stacks, note they are separate L3 islands
(`10.197.x` vs `10.145.x`) — cross-stack `scp` would need a routable path,
so prefer keeping both roles on one stack unless there's a reason not to.

**Duplicate image names persist on SJC** — two distinct image IDs both named
`BIGIP-tmos-rocky-22.0.0-0.0.570`
(`f397ba2a-…`, `dfb8e164-…`). This is the same gotcha recorded in
[`openstack-cli-reference.md`](openstack-cli-reference.md#picking-a-big-ip-image):
`--image <name>` fails with "More than one Image exists with the name …".
**Always launch with `--image <id>`.** SEA has a single `0.0.570`
(`d5030127-…`).

### Image IDs, recorded 2026-08-11

| Image | SJC | SEA |
|---|---|---|
| `BIGIP-tmos-rocky-22.0.0-0.0.570` | `f397ba2a-cc04-4879-bcde-2e7d885673b0` **and** `dfb8e164-3191-4843-bb37-dc7ad00e80de` | `d5030127-bed3-480c-8f51-6e1a5a703ec0` |
| `BIGIP-tmos-rocky-22.0.0-0.0.569` | `f9c2d4b1-a30c-44f7-9014-dd260938ad1f` | `57a9942b-933e-48f5-9b1d-f7d89d4075e5` |
| `RockyLinux8.10-pristine` | `f7c34529-5494-43f8-b586-824d60066417` | `3eee4eec-6a45-42a7-8c94-46bed36ecb28` |

IDs are stack-local and can change if images are re-uploaded — re-resolve by
name before relying on them.

Commands used, per stack (read-only, safe):

```bash
export OS_CLOUD=sjc   # or: sea
openstack token issue                      # confirm auth
openstack project list
openstack flavor list -f value -c Name -c VCPUs -c RAM -c Disk
openstack image list -f value -c Name -c Status
openstack network list -f json
openstack limits show --absolute           # quota headroom
```

## Sandbox tooling — rebuild from scratch

The sandbox is ephemeral: `~/.venvs`, `~/.local/bin`, and
`~/.config/openstack` were all wiped between 2026-07-17 and 2026-08-11.
**Assume the CLI has to be rebuilt every session.** Script:
[`scripts/bootstrap-openstack-cli.sh`](scripts/bootstrap-openstack-cli.sh).

**Durability now comes from the git remote, not the filesystem.** This repo
is a *clone* inside the sandbox at `~/eob-tmm` — it is not a host mount and
does **not** survive a sandbox reset. Anything worth keeping must be
committed and pushed before the session ends. (The predecessor arrangement
was the reverse: `eob-bigip/docs` was host-mounted and survived, which is
why the July notes lived there. See
[`archive-eob-bigip/`](archive-eob-bigip/).)

```bash
bash ~/eob-tmm/env/scripts/bootstrap-openstack-cli.sh
```

Rebuilt successfully 2026-08-11 → `openstack 10.2.1`. PyPI and
`bootstrap.pypa.io` egress both work from here (HTTP 200), which is what
makes the bootstrap possible without root.

## Credentials — two clouds

**In place as of 2026-08-11.** One credential per stack, both named
`tmm-build-sandbox`, **both expiring `2026-11-11`** — auth will start failing
that day with a 404-style rejection, which is easy to misread as a config
problem. Confirm what exists at any time (this lists the credentials
themselves, not their secrets):

```bash
OS_CLOUD=sjc openstack application credential list
```

| Stack | Credential ID | Expires |
|---|---|---|
| `sjc` | `529ef27c73e54b4895b69342423654e9` | 2026-11-11 |
| `sea` | `cdea13fdf7bf42d58defc8191798fc89` | 2026-11-11 |

`clouds.yaml` holds **both** stacks so
commands select by `OS_CLOUD=sjc` / `OS_CLOUD=sea`:

```yaml
clouds:
  sjc:
    auth_type: v3applicationcredential
    auth:
      auth_url: https://keystone.sjc-stack.pdsjc.f5net.com/v3
      application_credential_id: "<id>"
      application_credential_secret: "<secret>"
    region_name: "RegionOne"
    interface: "public"
    identity_api_version: 3
    verify: false
  sea:
    auth_type: v3applicationcredential
    auth:
      auth_url: https://keystone.sea-stack.pdsea.f5net.com/v3
      application_credential_id: "<id>"
      application_credential_secret: "<secret>"
    region_name: "RegionOne"   # unconfirmed for SEA
    interface: "public"
    identity_api_version: 3
    verify: false
```

Create each via Horizon → Identity → Application Credentials on that
stack. App credentials are per-stack — an SJC one will not work against
SEA. Secrets stay out of the repo and out of chat; `clouds.yaml` is mode
`600` at `~/.config/openstack/clouds.yaml`.

### Runbook: getting credentials in place

Don't hand-write the YAML above — Horizon emits it for you, and
[`scripts/merge-clouds-yaml.py`](scripts/merge-clouds-yaml.py) stitches the
two downloads into one multi-cloud file.

**Per stack** (`https://horizon.sjc-stack.pdsjc.f5net.com`, then
`https://horizon.sea-stack.pdsea.f5net.com` — both confirmed live, 302 to
`/auth/login/`):

1. Log into Horizon. Confirm the **project selector** (top left) shows the
   project you want to build in, and that you have a `member`-ish role —
   the app credential inherits *your current roles on the current
   project*, nothing more.
2. **Identity → Application Credentials → + Create Application Credential.**
   - *Name*: something traceable, e.g. `tmm-build-sandbox`.
   - *Secret*: leave blank to have one generated.
   - *Expiration*: set one. Long enough to finish the build work.
   - *Roles*: leave default (inherits your roles).
   - *Access Rules*: leave empty (unrestricted within those roles).
   - **Unrestricted**: leave **unchecked**. Only needed if the credential
     must itself create more credentials — we don't.
3. Hit Create. The modal shows the secret **once**. Click
   **Download clouds.yaml**. If you lose the secret, there's no recovery —
   delete the credential and make a new one.
4. Get the two files into this sandbox (any writable path — *not*
   `~/.ssh`, which is a read-only mount). `~/.config/openstack/` is fine.

**Then merge, once:**

```bash
~/.venvs/openstack/bin/python3 ~/eob-tmm/env/scripts/merge-clouds-yaml.py \
    sjc=~/Downloads/sjc-clouds.yaml \
    sea=~/Downloads/sea-clouds.yaml
```

It renames each cloud (`openstack` → `sjc`/`sea`), forces `verify: false`,
writes `~/.config/openstack/clouds.yaml` at mode `600` created-0600 (never
briefly world-readable), preserves any cloud already in the file, and
prints only non-secret fields — auth_url, region, credential **id**, and a
character count for the secret. Safe to paste the output anywhere. Pass
one `name=path` pair if you only have one stack yet.

**Verify** (no secrets in output; avoid `openstack token issue`, which
prints a usable token):

```bash
export PATH="$HOME/.local/bin:$PATH"
OS_CLOUD=sjc openstack project list
OS_CLOUD=sea openstack project list
```

**Auth chain already proven on both stacks** (2026-08-11): the merge script
was exercised with deliberately fake credential IDs, and both stacks
returned `Could not find Application Credential: <id>. (HTTP 404)` with a
Keystone `Request-ID`. A 404 from Keystone means DNS, TLS-with-`verify:false`,
the CLI, `clouds.yaml` parsing, and `v3applicationcredential` auth all work
end to end on **both** SJC and SEA. The only missing piece is a real
credential. Those test artifacts were deleted.

**Failure modes worth recognising:**

| Symptom | Cause |
|---|---|
| `Could not find Application Credential: <id>. (HTTP 404)` | Wrong/deleted/expired credential, or created on the *other* stack |
| `The request you have made requires authentication. (HTTP 401)` | Secret mismatch |
| `SSLError` / `CERTIFICATE_VERIFY_FAILED` | `verify: false` missing from that cloud's block |
| `Missing value auth-url required for auth plugin` | `OS_CLOUD` unset or naming a cloud not in the file |
| `You are not authorized to perform the requested action` | Credential inherited too few roles — recreate while scoped to the right project |

## Decision: BNK / MBIP is the route — 2026-08-11

**BIG-IP on a VM (CBIP) is a follow-on effort.** All work targets the containerized
data plane: source from GitSwarm, built in the `toolchain_container`, run as a pod in a
Datkube `kind` cluster. The consequence for this file is that the Perforce material
above is background rather than a blocker, and the CBIP-only questions — §14's worked
CVE among them — wait for that follow-on.

## Getting access — all three 401s are one identity

GitSwarm's sign-in page says it outright: *"Sign in using your **olympus(ldap)**
credentials. Do not use email as username."* Artifactory and Confluence sit behind the
same directory, so **there is one authentication problem, not three** — and the network
path to all of them already worked.

Two layers, and only the second needs a human:

1. **Authentication** — an olympus LDAP session. A browser session already existed, so
   this was never the obstacle.
2. **Authorization** — project membership. In GitLab a project you cannot see returns
   **404, not 403**, so "repo not found" and "you lack membership" look identical. Check
   by loading the project page while signed in. Membership on `tmm/tmm`,
   `koenning/spk-devmachine` and `datkube/datkube` was already held.

**What actually unblocked it:** an SSH key registered against the account, at
`https://gitswarm.f5net.com/-/user_settings/ssh_keys`. Generate on the box, paste the
public half, and `ssh -T git@gitswarm.f5net.com` answers `Welcome to GitLab, @starin!`
instead of `Permission denied (publickey)`. A Personal Access Token with
`read_repository` works too, but the key is better here: the private half never leaves
the VM, and revoking it is one click.

**Keep the LDAP password out of this environment entirely.** Tokens and keys are
per-service and revocable; the account password is not.

### What that opened

| repo | size / state |
|---|---|
| `tmm/tmm` | **2.5 GB**, HEAD current (`d5fdb0a8c8`, dated the day of the clone) |
| `koenning/spk-devmachine` | 116 KB of Ansible — the dev-machine provisioner, see below |
| `datkube/datkube` | the on-image clone was **658 commits behind** — local 2025-08-18, origin 2026-08-07 |

That last number is the cost of relying on a snapshot: Berge's image froze datkube at
whatever was current the day it was taken.

## Provisioning properly — `koenning/spk-devmachine`

**Use this instead of hand-installing, and instead of snapshotting our own image.** It
is Ansible that provisions an OpenStack VM from **`Ubuntu2404-server-pristine`** — the
curated base — with roles for common packages, docker, golang, git, ssh (including
GitLab key registration via API), shell, security hardening, NFS, and repo cloning.
Playbooks: `provision-machine.yml`, `setup-dev-machine-slim.yml`, `deploy-complete.yml`,
`destroy-machine.yml`, plus standalone `install-falcon.yml` / `install-qualys.yml`.

This is the reproducible artifact the earlier "should we build our own image?" question
was really asking for. A snapshot has no provenance; this is a diffable recipe, and it
already exists.

### Running it from this sandbox — five things that bite

The control machine needs Ansible + `openstacksdk`; both go in the existing
`~/.venvs/openstack`. Then:

1. **It expects a venv named `senf` inside the playbook directory** — its tasks call
   `{{ playbook_dir }}/senf/bin/openstack` literally. `ln -sfn ~/.venvs/openstack senf`.
2. **It expects `clouds.yaml` in the playbook directory**, not `~/.config/openstack/`.
   Copy it there; the repo's `.gitignore` already covers `clouds.yaml` and `vars.yml`.
3. **`--check` cannot work.** The VM is created by shell tasks, which check mode skips,
   so the next task parses empty output and dies in `from_json`. Run it for real.
4. **A pre-existing OpenStack keypair of the same name fails the upload** with *"key
   hash not the same as offered"*. `openstack keypair create NAME > file.pem` generates
   server-side and the derived public half will not match; delete the keypair and let
   the playbook upload ours.
5. **The generated inventory picks the wrong address on SEA.** It takes the *first*
   address, and SEA's AdminNetwork is dual-stack, so it writes the **IPv6** one — which
   this sandbox cannot route, and the playbook then fails "SSH port not available after
   300 seconds" on a VM that is up and answering on IPv4. Rewrite `ansible_host` to the
   `10.145.x` address.

### Variables it requires

`vars.yml` (from `vars.yml.template`, gitignored) must define `olympus_user`,
`olympus_email`, `artifactory_token`, `root_password`, `user_password`. Worth knowing
what they are actually for before hunting for real values:

- **`artifactory_token`** is only ever exported as `$ARTIFACTORY_TOKEN` into the shell
  profile. Nothing authenticates with it, and Artifactory docker pulls work anonymously,
  so a marked placeholder is enough to pass validation and blocks nothing.
- **`root_password` / `user_password`** set account passwords via `password_hash`.
  Access is key-based, so these are console/sudo fallback — generate random ones.

**Falcon and Qualys default to `true` and need more than a variable.** The Falcon role
copies the sensor from `{{ playbook_dir }}/pkgs/falcon-sensor_*.deb`, and `pkgs/` is
**gitignored** — so the package is not in the repo and the role fails at the copy step.
It also wants a `falcon_customer_id` (one value org-wide) for
`falconctl -s -f --cid=…`; without it the role installs the sensor but skips enrolment,
leaving an agent that reports to nothing. Both toggles are therefore set `false` here
until the package and CID are in hand — and `install-falcon.yml` exists standalone
precisely so it can be added to an already-provisioned machine without a rebuild.

### SOLVED — docker's default address pool cuts the box off this sandbox

**Set this before running docker or kind on any dev box, or the box will disconnect
itself and look dead.**

```json
/etc/docker/daemon.json
{
  "bip": "10.0.0.1/24",
  "dns-search": ["pdsea.f5net.com", "f5net.com"],
  "default-address-pools": [{"base": "10.0.0.0/9", "size": 24}]
}
```

**Why.** SSH from this sandbox arrives at an instance from **`172.18.105.92`** — we are
NATed, so although the sandbox is `10.88.0.5`, the box sees `172.18.x`. A stock docker
install puts `docker0` on `172.17.0.0/16` and hands kind `172.18.0.0/16` from the
default pool. The moment a cluster is created, the box installs a route for
`172.18.0.0/16` pointing at the docker bridge, **our return traffic is routed into the
bridge instead of out the default gateway**, and docker's `REJECT` rules answer with ICMP
port-unreachable.

The symptom is a box that is perfectly healthy on the console — multi-user reached,
cloud-init finished, login prompt — while **every port refuses**, which reads as "sshd
died" and is nothing of the sort. It also does not recover, and rescuing the instance
does not help, because the damage is to routing on a box that is otherwise fine.

Note this collides with more than our SSH path: F5's own estate is inside
`172.16.0.0/12` — resolver `172.27.1.1`, GitSwarm `172.31.226.252`, Artifactory
`172.25.9.4`, Confluence `172.25.8.129`.

**`Datkube-Devbox-Berge` already carries this file**, which is why it survives while
freshly provisioned boxes do not. It is not a coincidence — whoever built that image hit
this and fixed it.

**Gap in `spk-devmachine`:** its `docker` role installs Docker CE and starts the service
but never constrains the address pool, so any box it provisions on this network will cut
itself off as soon as someone runs kind. Worth an MR.

**How it was found**, because the wrong turns are instructive. Two boxes died; five
theories were tested and disproved by controlled experiment — a NAC/posture cutoff for
missing Falcon and Qualys (**Berge's image has neither and survives**), the `nfs` role
(box 2 skipped it and still died), `unattended-upgrades` (enabled *and already run* on
the survivor), the playbook touching `sshd_config` (nothing in any role writes it), and
the base image itself (a bare untouched `Ubuntu2404-server-pristine` survived 80/80
checks over 40 minutes). What isolated it was noticing the survivor had never had docker
or kind run on it, and then reading its route table.

### OPEN ISSUE (RESOLVED — see above) — sshd stopped coming up on a provisioned box

**Not understood, recorded so the next person does not rediscover it from scratch.**
The first machine provisioned with `setup-dev-machine-slim.yml` worked for roughly half
an hour, then began refusing on tcp/22 — an active RST, not a timeout. A reboot brought
it back for one connection and then it refused again, permanently. Meanwhile the console
log showed a completely healthy boot: multi-user reached, cloud-init finished, login
prompt present. So the machine was fine and **sshd specifically was not running**.

What was ruled out: nothing in the playbook writes `sshd_config` (checked every role);
no `fail2ban` and no `ufw` anywhere in it; the instance stayed `ACTIVE` with power state
running throughout.

What remains suspected but unproven: the **`security` role**, which installs
`unattended-upgrades`. It is the only thing provisioning adds that acts on its own
afterwards, and an `openssh-server` upgrade is the obvious way for sshd to restart into
a bad state. Notably the earlier box — Berge's snapshot, never touched by this
playbook — ran for hours without this.

**Mitigation taken**, not a fix: disable the `security` role. If a box provisioned that
way stays up, that is evidence for the theory but not proof.

**Disable it with the playbook's own toggles — do not edit the roles list.** Every role
in `setup-dev-machine-slim.yml` is already gated by a flag:

```yaml
configure_security: false    # the unattended-upgrades role
install_qualys: false
install_falcon: false
```

An earlier attempt here commented out the `- role: security` and `- role: qualys` lines
instead, which **orphaned their `when:` clauses onto the preceding entry** — so
`- role: common` inherited `when: configure_security`, that variable was undefined, and
the entire `common` role was silently skipped. The symptom was a box with no development
user at all and a later task failing with *"chown failed: failed to look up user"*, which
points nowhere near the actual cause. A commented-out line in a YAML list leaves its
continuation lines behind; the toggles exist precisely so nobody has to do that.

**To actually diagnose it**, boot the instance with `openstack server rescue`, mount its
disk, and read `journalctl -u ssh` and `/var/log/unattended-upgrades/`. That was not done
here because the box held nothing of value and rebuilding was faster — a reasonable
trade at the time, but it is why this section says "suspected" rather than "caused by".

### The instance this produced

`eob-tmm-dev` on SEA — `Ubuntu2404-server-pristine`, flavor `datkube-dev-large`
(**16 vCPU / 31 GB / 242 GB**, overriding the template's `m1.dev-large` at 8 GB, which
is too small for a TMM build plus a kind cluster plus an 18 GB toolchain image),
one NIC on AdminNetwork, `auto_ip: false` since AdminNetwork is directly reachable from
this sandbox and a floating IP is needless exposure.

## Access matrix — what is actually gated, verified 2026-08-11

The single most useful thing learned this session: **"we need access" is four different
questions, and three of them are already answered.**

| what | endpoint | status |
|---|---|---|
| `kind` node images, Calico, Multus | public / cached | works |
| **`docker pull` from Artifactory** | `artifactory.f5net.com` | **works ANONYMOUSLY** — pulled `toolchain_container:v2.1.0` (18.1 GB) and `tmm-img:v0.950.0-0.1.0` |
| Artifactory REST API | `/artifactory/api/…` | 401 — cannot *list* repos or discover current versions |
| GitSwarm HTTPS | `gitswarm.f5net.com` | 401 → `/users/sign_in` |
| GitSwarm SSH | `git@gitswarm.f5net.com` | publickey denied for all five keys on this box |
| Confluence | `docs.f5net.com` | `permissionViolation=true`; REST 401 |

**The registry/API split is the important one.** Images are obtainable if you know the
exact tag; you just cannot browse to discover tags. So a current `input-manifest.yml`
(which maps profile → component versions) would be enough to pull a current stack
without any credential — that one *file* is worth more than broad access.

**And the whole TMM exercise reduces to one credential:** GitSwarm access to `tmm/tmm`.
Not Perforce (that is CBIP), not Artifactory (anonymous pulls work), not a build host
(the toolchain is a container, already downloaded). F5's own page says how: *"if you do
not have access to f5-tmm repo, please talk to your manager."*

## The Datkube devbox — booted and verified 2026-08-11

Instance `eob-datkube-01`, SEA, image `Datkube-Devbox-Berge`, flavor
`datkube-dev-large` (16 vCPU / 32 GB / 250 GB), **one NIC on AdminNetwork** — one
deliberately, because a second DHCP-enabled NIC creates the two-default-route problem
documented above, and MBIP source is GitSwarm not Perforce, so `PerforceAccessNet` is
not needed.

```bash
openstack --os-cloud sea keypair create eob-datkube > ~/.config/openstack/keys/eob-datkube.pem
chmod 600 ~/.config/openstack/keys/eob-datkube.pem
openstack --os-cloud sea server create \
  --flavor datkube-dev-large --image abecfaf0-4fa1-4519-a1a7-fcd316506f1c \
  --nic net-id=AdminNetwork --no-security-group --key-name eob-datkube eob-datkube-01
```

**What was learned booting it:**

- **Login is `ubuntu`** (and `root`). Cloud-init keypair injection works — the snapshot
  had not consumed cloud-init. `dev` and `berge` are not accounts.
- **SSH is reachable DIRECTLY from the sandbox**, no jump host: the box came up on
  `10.145.38.232`, and `10.145/16` routes from here. `jump-eob` was not needed.
- **AdminNetwork on SEA is dual-stack** — the instance also got
  `2620:128:e008:4806::e0`. SJC's is IPv4 only.
- Ubuntu **24.04.3 LTS**, from base `Ubuntu2404-server-pristine`.
- **The datkube CLI and repo are on the image**: `/usr/local/bin/datkube` (a bash
  wrapper around `datkube.py`) and a real git clone at `~/code/datkube`, ~60 profiles
  including `bnk-core`, with its own `input-manifest.yml`.
- **`datkube create-cluster` works with no credentials** — kind, Kubernetes **v1.32.0**,
  control-plane + worker, Calico and Multus all Ready in about 90 seconds.
- **But the clone is 12 months stale**: HEAD `99deb0a7`, 2025-08-18, datkube 1.21.11.
  It updates by `git pull` from GitSwarm, so it is frozen until that is unblocked.
- Tools present: docker 28.3.3, kind 0.26.0, kubectl, helm, gcc 13.3.0, gdb 15.0.50,
  go, make, git, yq, jq. **No `p4`** — consistent with MBIP not needing it.

**Cluster access.** On the box, `kubectl` just works (context `kind-datkube`). From
elsewhere, kind's API server binds `127.0.0.1:<port>` on the host and its certificate is
issued for `127.0.0.1`, so tunnel the *same* port to keep TLS valid:

```bash
ssh -L 39481:127.0.0.1:39481 ubuntu@<devbox>      # port from: kubectl config view --minify
```

## The shipped TMM binary is stripped — and that is why we must build our own

Extracted `/usr/bin/tmm` from `tmm-img:v0.950.0-0.1.0`. It is a symlink chain —
`tmm` → `tmm.default` → **`tmm64.no_pgo`** — ending at a 56 MB x86-64 executable.

- **No `.symtab`, no `.debug_*`.** `nm` returns nothing.
- **`.gnu_debuglink` names `tmm64.no_pgo.debug`** — the symbols exist, split into a
  separate file that is not in the runtime image. Finding that file would make the
  hookable-set analysis answerable without source.
- **Only `.dynsym` survives: 4,648 defined symbols, overwhelmingly OpenSSL exports**
  (`ACCESS_DESCRIPTION_*`, `ADMISSIONS_*`). `flow_input`, `fw_log_prot_transfer_emit`,
  `http2`, `tmm_poll` — **zero hits**.

**That last point is evidence for a design decision rather than an obstacle to one.**
TMM's internal functions are not exported, so the hook map cannot be derived from a
shipped artifact — not by us, not on the box, not by a customer. It must be generated
**at build time inside F5 from DWARF/BTF and shipped signed alongside the build**, which
is exactly what [`../development-scope.md`](../development-scope.md) item 5 specifies.
The proposal asserted it; this demonstrates it.

It also settles why `make tmm-gdb` is the required target: the hookable set, DWARF
argument layouts, `-fpatchable-function-entry` cost, and the integration itself all need
what stripping removes.

## Build log

Nothing built yet. Append dated entries below as work happens — one entry
per attempt, including failures and their exact error text, since those
are the parts worth not rediscovering.

### 2026-08-11 — first Datkube cluster, and the local verification toolchain

Not a TMM build — still blocked on source. But everything *around* it now stands, and
two things were built locally that did not exist before.

**On SEA:** booted `eob-datkube-01`, brought up a `kind` cluster with
`datkube create-cluster` (Kubernetes v1.32.0, Calico + Multus, ~90 s, no credentials),
and pulled `toolchain_container:v2.1.0` (18.1 GB) and `tmm-img:v0.950.0-0.1.0`
anonymously from Artifactory. So `make start` will not re-pull, and there is a reference
TMM image to compare against. Details in the two sections above.

**In this sandbox:** built **PREVAIL** from the vendored tree and ran the whole authoring
chain end to end for the first time — `clang -O2 -g -target bpf` → `prevail` →
`budget_pass.py`. Two things that cost time and are worth not rediscovering:

- The build needs the Netskope CA set (see [`README.md`](README.md)) or `FetchContent`
  fails to clone GSL with a misleading error, **and** Boost headers, which are not
  installed and cannot be apt-installed here. Download the 1.87.0 source tarball,
  extract only `boost_1_87_0/boost`, and pass `-DBOOST_HEADERS_DIR=…`.
- Binaries land in `ebpf-verifier/bin/` **inside the repo tree**, not the build dir.
  That directory is gitignored, so they stay out of git — but do not be surprised by an
  11 MB `bin/` appearing under a vendored tree.

`prevail --help` confirms from the shipped binary what
[`../development-scope.md`](../development-scope.md) item 3a records from source:
`--termination` *"Default: ignore"*, `--allow-division-by-zero` *"Default: allow"*,
`--strict` off, `--stack-size`, `--max-call-stack-frames`.

**And running the chain on a real object immediately found a fail-open in our own
budget pass.** It defaulted to reading `.text`, but clang emits an eBPF program into its
`SEC()` section and leaves `.text` present and **zero bytes** — so it priced 0
instructions and returned "ok, under budget" for a program it had never looked at, in
the one component whose entire job is to fail closed. The self-test never caught it
because the ELFs it synthesizes put their payload in `.text`, which is exactly the shape
real objects do not have. Fixed: it now locates the executable section, refuses when
there is none or when several are ambiguous, and takes `--section` as PREVAIL does.

### 2026-08-11 — cold-start reproduction of the whole runbook, both stacks

Not a build. A check that the documented path works from an empty sandbox,
which is the claim this file makes and had not itself been tested end to end
in one pass. It does.

From nothing — no venv, no `~/.config/openstack/clouds.yaml`:

1. `bash env/scripts/bootstrap-openstack-cli.sh` → `openstack 10.2.1`. PyPI
   and `bootstrap.pypa.io` both reachable; no pin needed yet, and 10.2.1 is
   the same version recorded above, so the unpinned `pip install` has not
   drifted.
2. `python3 env/scripts/merge-clouds-yaml.py sea=clouds-sea.yaml
   sjc=clouds-sjc.yaml` → `~/.config/openstack/clouds.yaml`, mode 600, both
   clouds present, `verify: false`. The script reported key *names* only, so
   no secret reached the terminal.
3. Authenticated against both. Project IDs match the comparison table:
   sjc `c0007f99…`, sea `fc383461…`.

Elapsed: a few minutes, nearly all of it `pip install`.

**Two things worth recording beyond "it worked."**

- **Neither stack has any instances running** (`server list` empty on both),
  so anything to be tested starts with a boot. The quota lines above are
  therefore fully available, not partly consumed.
- **`keystone` on tcp/443 is open on both** (`10.145.23.16`,
  `10.197.12.17`). Not in tension with the *refused* result recorded under
  SSH access above — that was port **22** on the same addresses. Different
  port, different answer, and the distinction is easy to lose when skimming.

**And a caution about where the credentials sit.** `clouds-sea.yaml` and
`clouds-sjc.yaml` were in the repo working directory for this, which is the
arrangement the standing caution in [`README.md`](README.md) says not to
rely on. `.gitignore` line 23 (`*clouds*.y*ml`) held — repeated `git add -A`
across a long session never staged either file, and `git log --all` over
`*clouds*` is empty. But that is the ignore list doing the work, which is
the fallback and not the rule. Move them out of the tree once merged;
`merge-clouds-yaml.py` has already copied what it needs.
