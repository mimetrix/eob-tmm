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
  discriminate between SJC and SEA. **Still unverified either way:** that the
  network actually routes to `192.168.13.205` from an instance. Test with a
  NIC on it before assuming.

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

## Build log

Nothing built yet. Append dated entries below as work happens — one entry
per attempt, including failures and their exact error text, since those
are the parts worth not rediscovering.

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
