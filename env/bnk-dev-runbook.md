# BNK dev environment — the exact commands

Copy-paste runbook for standing up the **BNK / MBIP** development environment from
nothing: a **build box** (TMM source, toolchain container, eBPF compilation) and a
separate **Datkube box** (kind cluster, runs the TMM pod).

**Status:** every command below was run, in this order, on 2026-08-12. Where something
bites, the reason is stated inline rather than left as folklore. Companion documents:
[`tmm-build-environment.md`](tmm-build-environment.md) for *why* each step exists, and
[`openstack-cli-reference.md`](openstack-cli-reference.md) for the OpenStack basics.

**Two boxes, deliberately.** Building is not running. The proposal's open questions are
about TMM's *runtime* cost, and measuring that on a machine simultaneously compiling
2,039 `.c` files inside the toolchain container gives numbers worth nothing. It is also F5's
own topology — the fast-cycling page assumes a build machine and a Datkube machine with
`scp` between them, which is why `datpush` exists.

| | `eob-bnk-build-01` | `eob-bnk-datkube-01` |
|---|---|---|
| TMM source + toolchain container | yes | no |
| clang for eBPF shield programs | yes | no |
| gcc, gdb | yes | no |
| kind, kubectl, helm, datkube CLI | no | yes |
| runs the `f5-tmm` pod | no | yes |
| flavor | `datkube-dev-large` (16 / 32 GB / 250 GB) | smaller is fine |

---

## 0 · Prerequisites — get these before touching anything

**Access.** All of it is one identity: **olympus LDAP**. Sign in at
`https://gitswarm.f5net.com` with your **LDAP username, not your email**. A project you
lack membership on returns **404, not 403**, so "not found" and "no access" look
identical — check by loading the page while signed in. You need `tmm/tmm`,
`datkube/datkube`, and `koenning/spk-devmachine`.

**Two credentials, created in a browser:**

```
GitSwarm SSH key     https://gitswarm.f5net.com/-/user_settings/ssh_keys
Artifactory token    https://artifactory.f5net.com/ui/  → avatar → Edit Profile
                     → Identity Tokens → Generate  (shown ONCE)
```

Keep the LDAP password out of the environment entirely — tokens and keys are
per-service and revocable.

**Be aware the Artifactory token leaks into build logs.** TMM's Makefile echoes the full
`docker run` line, `-e ARTIFACTORY_TOKEN=…` included. Filter it out of anything you
paste or share, and rotate the token if a log escapes.

**TLS interception.** This sandbox sits behind a Netskope proxy. Without its CA, HTTPS
fails in ways that look like the remote being down — `curl` returns nothing, `git clone`
fails, CMake `FetchContent` reports "Failed to clone repository".

```bash
export CURL_CA_BUNDLE=/home/claude/netskope-ca.pem
export GIT_SSL_CAINFO=/home/claude/netskope-ca.pem
export SSL_CERT_FILE=/home/claude/netskope-ca.pem
export REQUESTS_CA_BUNDLE=/home/claude/netskope-ca.pem
```

**Quota.** SEA allows 40 cores / 80 GB. Two `datkube-dev-large` boxes are 32/64 and fit;
a third does not. `openstack --os-cloud sea limits show --absolute` before provisioning.

---

## 1 · Control machine — OpenStack CLI and Ansible

The sandbox is ephemeral: `~/.venvs` and `~/.local/bin` are wiped between sessions, so
expect to run this every time.

```bash
bash env/scripts/bootstrap-openstack-cli.sh          # -> openstack 10.2.1
export PATH="$HOME/.local/bin:$PATH"

# merge the Horizon-downloaded clouds.yaml files into one multi-cloud config
python3 env/scripts/merge-clouds-yaml.py sea=clouds-sea.yaml sjc=clouds-sjc.yaml
#   -> ~/.config/openstack/clouds.yaml, mode 600, clouds named 'sea' and 'sjc'

# Ansible for the provisioner
~/.venvs/openstack/bin/pip install -q ansible openstacksdk passlib
~/.venvs/openstack/bin/ansible-galaxy collection install \
    openstack.cloud community.general ansible.posix

openstack --os-cloud sea token issue -f value -c project_id    # auth smoke test
```

## 2 · Get the provisioner

```bash
git clone git@gitswarm.f5net.com:koenning/spk-devmachine.git
cd spk-devmachine
```

**Three local adjustments it needs.** None are optional:

```bash
# (a) it calls {{ playbook_dir }}/senf/bin/openstack literally
ln -sfn ~/.venvs/openstack senf

# (b) it wants clouds.yaml in the playbook directory, not ~/.config/openstack
cp ~/.config/openstack/clouds.yaml ./clouds.yaml && chmod 600 clouds.yaml

# (c) vars.yml from the template
cp vars.yml.template vars.yml && chmod 600 vars.yml
```

Edit `vars.yml`:

```yaml
olympus_user: "<your-ldap-username>"
olympus_email: "<you>@f5.com"
artifactory_token: "PLACEHOLDER-not-a-real-token"   # THIS one authenticates nothing — the
                                                    # playbook only exports it to a shell
                                                    # profile. The real token goes in
                                                    # ~/code/tmm/.env at step 8, where the
                                                    # build genuinely needs it.
root_password: "<random>"        # console/sudo fallback only — access is key-based
user_password: "<random>"

configure_security: false        # unattended-upgrades; see note below
install_qualys: false            # no package available (pkgs/ is gitignored upstream)
install_falcon: false            # ditto — needs the .deb AND the org CID
```

**Use the toggles; do not comment out roles.** Every role is already gated by a flag.
Commenting out a `- role:` line orphans its `when:` clause onto the preceding entry — do
that to `security` and `- role: common` inherits `when: configure_security`, which is
undefined, so **`common` is silently skipped** and you get a box with no dev user and a
later failure reading *"chown failed: failed to look up user"*, which points nowhere near
the cause.

**On Falcon and Qualys:** both roles `copy:` their agent from `pkgs/`, which is
gitignored upstream, so the packages are not in the repo and the roles fail at the copy
step. They also need activation IDs — without them the agent installs and skips
enrolment, reporting to nothing. Get the `.deb`s and IDs from whoever maintains the
playbook, then run `install-falcon.yml` / `install-qualys.yml` standalone; no rebuild
needed. (For the record: these are **not** required for the box to stay reachable — a
box with neither ran for hours.)

Edit `instance_config.yml`:

```yaml
image: "Ubuntu2404-server-pristine"      # curated base. A bare one survived 80/80
                                          # reachability checks over 40 minutes.
flavor: "datkube-dev-large"               # 16 vCPU / 32 GB / 250 GB
network: "AdminNetwork"
key_name: "eob-bnk-dev"
public_key_file:  "/home/claude/.config/openstack/keys/eob-bnk-dev.pub"
private_key_file: "/home/claude/.config/openstack/keys/eob-bnk-dev.pem"
auto_ip: false                            # AdminNetwork is directly reachable; a
                                          # floating IP is needless exposure
```

## 3 · Keypair

```bash
mkdir -p ~/.config/openstack/keys
ssh-keygen -t ed25519 -N '' -C 'eob-bnk-dev' -f ~/.config/openstack/keys/eob-bnk-dev.pem
mv ~/.config/openstack/keys/eob-bnk-dev.pem.pub ~/.config/openstack/keys/eob-bnk-dev.pub
chmod 600 ~/.config/openstack/keys/eob-bnk-dev.pem
```

Generate the keypair **locally** and let the playbook upload it. `openstack keypair
create NAME > file.pem` generates server-side, and the public half you derive from it
will not match what OpenStack stored — the playbook then fails with *"key name present
but key hash not the same as offered"*. If that happens, `openstack --os-cloud sea
keypair delete NAME` and let the playbook upload yours.

## 4 · Provision the build box

```bash
export OS_CLOUD=sea PATH="$HOME/.local/bin:$PATH"
~/.venvs/openstack/bin/ansible-playbook provision-machine.yml \
  -e "cloud_name=sea instance_name=eob-bnk-build-01" \
  -e "@vars.yml" -e "@instance_config.yml"
```

**Two things will look like failures and are not.**

`--check` mode cannot work at all — the VM is created by shell tasks, which check mode
skips, so the next task parses empty output and dies in `from_json`. Run it for real.

The final "Test SSH connectivity" task fails with *"SSH port not available after 300
seconds"* on a box that is up and answering. The generated inventory takes the **first**
address, and SEA's AdminNetwork is **dual-stack**, so it writes the IPv6 one, which this
sandbox cannot route. Fix the inventory and carry on:

```bash
IP=$(openstack --os-cloud sea server show eob-bnk-build-01 -f json \
     | python3 -c "import json,sys;print([a for a in json.load(sys.stdin)['addresses']['AdminNetwork'] if '.' in a][0])")
sed -i "s|ansible_host=2620:[0-9a-f:]*|ansible_host=$IP|g" inventory_eob-bnk-build-01.ini
```

## 5 · THE CRITICAL STEP — docker's address pool, before docker is ever used

**Skip this and the box will disconnect itself and look dead.**

```bash
KEY=~/.config/openstack/keys/eob-bnk-dev.pem
ssh -i $KEY ubuntu@$IP 'sudo mkdir -p /etc/docker && sudo tee /etc/docker/daemon.json >/dev/null <<EOF
{
  "bip": "10.0.0.1/24",
  "dns-search": ["pdsea.f5net.com", "f5net.com"],
  "default-address-pools": [{"base": "10.0.0.0/9", "size": 24}]
}
EOF'
```

**Why.** SSH from this sandbox arrives at the instance from **`172.18.105.92`** — we are
NATed, so although the sandbox is `10.88.0.5`, the box sees `172.18.x`. Stock docker puts
`docker0` on `172.17.0.0/16` and hands kind `172.18.0.0/16`. The moment a container
network is created, the box installs a route for that subnet pointing at the docker
bridge, **return traffic to us is routed into the bridge instead of the default
gateway**, and docker's `REJECT` rules answer with ICMP port-unreachable.

The symptom is a machine that is perfectly healthy on the console — multi-user reached,
cloud-init finished, login prompt — while **every port refuses**. It reads as "sshd died"
and is nothing of the sort, does not recover, and rescuing the instance does not help.
It cost most of a day to find. `Datkube-Devbox-Berge` ships exactly this file, which is
why that image survives where a freshly provisioned box does not.

The collision is wider than SSH: F5's estate is inside `172.16.0.0/12` — resolver
`172.27.1.1`, GitSwarm `172.31.226.252`, Artifactory `172.25.9.4`, Confluence
`172.25.8.129`.

**This belongs in `spk-devmachine`'s `docker` role**, which installs and starts Docker CE
but never constrains the pool. Worth an MR.

Write it **before docker is installed**, not after — the file is read at daemon start, so
getting there first means the bridge is never wrong even briefly. Confirm afterwards:

```bash
ssh -i $KEY <ldap-user>@$IP 'ip -4 -o addr show docker0 | awk "{print \$4}"'
# 10.0.0.1/24   <- correct.  172.17.0.1/16 means the file was late; see below.
```

If it says `172.17.0.1/16`, the daemon started before the file existed: `sudo systemctl
restart docker` after writing it, and delete any cluster created in the meantime
(`kind delete cluster`) — a restart re-pools the bridge but does not renumber networks that
already exist.

## 6 · Configure the box

```bash
export ANSIBLE_HOST_KEY_CHECKING=False
~/.venvs/openstack/bin/ansible-playbook -i inventory_eob-bnk-build-01.ini \
  setup-dev-machine-slim.yml -e "@vars.yml" -e "@instance_config.yml"
```

Ten roles, about 12 minutes, most of it apt: `common · security · qualys · git · ssh ·
git_repos · docker · golang · nfs · shell`. Expect **`ok=50 changed=25 failed=0
skipped=37 ignored=3`**.

It installs the toolchain this project needs — `gcc g++ gdb lldb clang cmake
build-essential binutils elfutils pahole valgrind ltrace linux-tools-generic
perf-tools-unstable universal-ctags python3-dev/pip/venv` — plus Docker CE and Go. Note
`clang`, `pahole` and `elfutils` in that list: eBPF compilation and the `nm`/`readelf`
symbol work both land on this box by default, which is why it is the right home for shield
development.

It also **creates a user named after `olympus_user` and disables `ubuntu`**. From here on,
`ssh ubuntu@...` answers *"Permission denied (publickey,password)"* — that is the playbook
having worked, not a lockout. Log in as your LDAP username. It adds that user to the
`docker` group too, so no `usermod` is needed.

**Three tasks fail and are ignored. All three are expected; none needs action:**

1. `common : Add ubuntu user SSH keys to development user` — `common/tasks/main.yml:105` reads
`key: "{{ lookup('file', '/home/ubuntu/.ssh/authorized_keys') }}"`, and **`lookup` runs on
the control node, not the target** — so it looks for that path in the sandbox, where it
does not exist. The task is `ignore_errors`, and the next two — "Ensure SSH directory
exists for development user" and "Copy SSH authorized keys from ubuntu user (alternative
method)" — do the same job over SSH and succeed. Expect:

```
fatal: [...]: FAILED! => ... '/home/ubuntu/.ssh/authorized_keys': File not found
...ignoring
TASK [common : Copy SSH authorized keys from ubuntu user (alternative method)] *** changed
TASK [common : Test SSH connectivity with development user] *** ok
```

2. A `become_user` task fails with *"chmod: invalid mode: 'A+user:starin:rx:allow'"* —
   Ansible's unprivileged-become path wants POSIX ACLs and falls back to an NFSv4-style
   `chmod` the target does not understand. Cosmetic.
3. `shell : Install vim plugins using vim-plug` returns rc=1. Cosmetic; vim works.

**Two things the playbook does not do**, both worth fixing immediately after:

```bash
# (a) it never sets the hostname — the box keeps its cloud-init name, so a renamed
#     instance shows the OLD name and later logs are confusing
ssh -i $KEY <ldap-user>@$IP 'sudo hostnamectl set-hostname eob-bnk-build-01 && \
    sudo sed -i "s/<old-name>/eob-bnk-build-01/g" /etc/hosts'

# (b) the golang role untars Go into $HOME, so GOROOT and Go's default GOPATH collide
#     ("both GOPATH and GOROOT are the same directory") — point GOPATH elsewhere
ssh -i $KEY <ldap-user>@$IP 'echo "export GOROOT=\$HOME/go" >> ~/.profile; \
    echo "export GOPATH=\$HOME/go_workspace" >> ~/.profile; \
    echo "export PATH=\$PATH:\$GOROOT/bin:\$GOPATH/bin" >> ~/.profile'
```

`.profile`, not `.bashrc`: the role wrote its `export PATH` block into `.bashrc`, which
Ubuntu guards at line 8 with `case $- in *i*) ;; *) return;; esac` — so **it never runs in a
non-interactive shell**, and every `ssh host 'go build …'` reports `go: command not found`
on a box where `~/go/bin/go` works fine. Either use `.profile` as above or call the
absolute path in automation.

### 6b · A shell from your own workstation

The provisioning key lives wherever you ran the playbook, which is not necessarily where
you want to work. **Install your workstation's own public key rather than moving the
provisioning private key around** — the private half never transits, and revoking it is
one line on the box.

From the control machine, with your workstation's `.ssh` visible (in this sandbox it is a
read-only virtiofs mount of the operator's real `~/.ssh`, so their public keys are already
present):

```bash
PUB=$(cat ~/.ssh/id_ed25519.pub)          # the workstation's own key, not the provisioning one
ssh -i $KEY <ldap-user>@$IP \
  "grep -qF '$PUB' ~/.ssh/authorized_keys || echo '$PUB' >> ~/.ssh/authorized_keys"
```

Then, from the workstation, with **no `-i`** — `id_ed25519` is a name ssh offers by
default:

```bash
ssh <ldap-user>@<ip>
```

Two things that will look broken and are not:

- **You must be on the F5 network or VPN.** These are `10.145.x` on SEA's AdminNetwork,
  routable internally, with no floating IP by design.
- **The username flips partway through provisioning.** A pristine box takes `ubuntu`; once
  `setup-dev-machine-slim.yml` has run, `ubuntu` is *disabled* and the LDAP-named user
  works instead. So mid-playbook you will find exactly one of the two accounts answering,
  which reads as a broken key and is just the box changing hands:

  | | before the playbook | after |
  |---|---|---|
  | `ubuntu` | works | **refused** |
  | `<ldap-user>` | doesn't exist | works |

  Seed the key into `ubuntu` *before* the playbook and it carries across on its own — the
  `common` role's "Copy SSH authorized keys from ubuntu user" task does it. Seeding after
  means doing both accounts by hand.

Worth keeping a `~/.ssh/config` block so the addresses stop being something to look up:

```
Host bnk-build
    HostName 10.145.42.119
    User <ldap-user>
Host bnk-datkube
    HostName 10.145.35.70
    User <ldap-user>
```

IPs are assigned at boot and change if a box is rebuilt. Re-resolve with:

```bash
openstack --os-cloud sea server list -f value -c Name -c Networks
```

and take the **IPv4** address — SEA's AdminNetwork is dual-stack and lists IPv6 first.

### 6c · Losing the account passwords is recoverable — don't treat them as precious

`provision-machine.yml` sets `root_password` / `user_password` from `vars.yml`, and if that file
lived somewhere ephemeral those values can be lost. **That is not a lockout.** Verified on these
boxes:

- **`sudo` is passwordless** for the dev user (`sudo -n true` succeeds), so the user password is not
  needed for privilege escalation — only for a console login.
- **`openstack server rescue` accepts `--password`**, so root access can be re-established without
  the original: rescue the instance, and the rescue environment gets a password you choose while the
  original disk is attached for chroot.

```bash
openstack --os-cloud sea server rescue --password '<new>' eob-bnk-build-01
# ... chroot the attached disk, `passwd`, then:
openstack --os-cloud sea server unrescue eob-bnk-build-01
```

So keep the passwords in a password manager if convenient, and reprovision or rescue if not. What is
*not* recoverable this way is the SSH key — treat that as the credential that matters. Neither box
runs `qemu-guest-agent`, so there is no API-side password reset; rescue is the path.

## 7 · Credentials on the box

```bash
scp -i $KEY ~/.config/openstack/keys/id_ed25519_gitswarm <ldap-user>@$IP:~/.ssh/
ssh -i $KEY <ldap-user>@$IP 'chmod 600 ~/.ssh/id_ed25519_gitswarm'

# verify — expect "Welcome to GitLab, @you!"
ssh -i $KEY <ldap-user>@$IP \
  'ssh -T -o IdentitiesOnly=yes -i ~/.ssh/id_ed25519_gitswarm git@gitswarm.f5net.com'

# Artifactory: needed for the toolchain container and for dockerhub-remote
ssh -i $KEY <ldap-user>@$IP \
  'echo "<token>" | docker login artifactory.f5net.com -u <ldap-user> --password-stdin'
```

**Note the asymmetry, and do not read it as "the token is optional."** `docker pull` of
F5-published images works **anonymously** — the toolchain container comes down with no
credential. But the build itself `wget`s three RPMs (`tmstat`, `libbigpacket`, `tcpdump`)
from Artifactory with `--user`/`--password`, and those return **401 anonymous, 200 with
the token**. `dockerhub-remote` (kind's node image) needs it too, and the REST API stays
401 regardless. So `make tmm` will die partway through without a real token in `.env`.

## 8 · Build TMM

**`yq` first — the build cannot resolve its own toolchain without it.** The playbook does
not install it, and TMM's Makefile reads every image coordinate out of
`input-manifest.yml` through `yq` (lines 25–30, 62, 189). Missing, those `$(shell …)`
expansions come back empty and `_start` runs `docker run … :v` → **`docker: invalid
reference format`**, which names neither `yq` nor the manifest. Install **mikefarah's Go
`yq`**, not the Python wrapper of the same name:

```bash
curl -sSLo /tmp/yq https://github.com/mikefarah/yq/releases/download/v4.44.5/yq_linux_amd64
sudo install -m0755 /tmp/yq /usr/local/bin/yq && yq --version

# confirm the manifest resolves before starting a 40-minute pull
cd ~/code/tmm && make -n _start | grep -oE 'artifactory[^ ]*tc-tmm[^ ]*'
#   artifactory.f5net.com/f5-f5dev-docker/tc-tmm:v2.3.1
```

Note that version. The Confluence page says `toolchain_container:v2.1.0`; the manifest in
`main` says **`tc-tmm:v2.3.1`**. Trust `input-manifest.yml` — it is the bill of materials
the build actually reads, and it moves.

```bash
ssh -i $KEY <ldap-user>@$IP
export GIT_SSH_COMMAND="ssh -o IdentitiesOnly=yes -i ~/.ssh/id_ed25519_gitswarm"
mkdir -p ~/code && cd ~/code
git clone git@gitswarm.f5net.com:tmm/tmm.git        # ~2.5 GB
cd tmm

# TMM's own .env — separate from every other credential, and gitignored by the repo
umask 077
printf 'ARTIFACTORY_USER=%s\nARTIFACTORY_TOKEN=%s\n' "<ldap-user>" "<token>" > .env

# EVERY docker exec in the Makefile is `docker exec -it`, so the build CANNOT run
# without a pty. Overriding DOCKER_EXEC does not help: a Makefile `export VAR = …`
# beats an environment variable on recursion, and line 185 hardcodes another -it.
script -qec "make start" /dev/null          # pulls tc-tmm (2.5 GB), runs it, install-libs
script -qec "make tmm-gdb" /dev/null        # build WITH debug symbols
```

`make start` is `.next-version _start install-libs`. **If `_start` fails, `install-libs`
silently never runs**, and the build then dies much later on a missing header
(`/usr/include/errdefs/product_codes.h`) that looks nothing like a setup problem. Check
that `make start` completed before building.

If `_start` reports a container-name conflict, clear it: `docker rm -f $(docker ps -aq)`.

`make tmm-gdb` is `make tmm && make clean_rpms && make GDB_INCLUDE=true
INSTALL_DEBUG_TMM=TRUE container`. Before any `make container`, delete stale artifacts or
**your changes are silently absent from the new image** — it builds, deploys and runs the
old code:

```bash
sudo rm -rf RPMS SRPMS docker_build/DEBS BUILD_* docker_build/tmm-runtime.*
```

Outputs: `tmm:local` (with tmstat + tcpdump), `tmm:local_img`, `tmm_gdb:latest`, and
`docker_build/DEBS/amd64/tmm-debuginfo_*.deb` — the last being the only place the symbol
table exists, since the shipped `tmm-img` is stripped to ~4,600 dynsyms, almost all
OpenSSL.

## 9 · Symbol analysis — the hookable set

```bash
cd /tmp && mkdir dbg && cd dbg
dpkg-deb -x ~/code/tmm/docker_build/DEBS/amd64/tmm-debuginfo_*.deb .
B=$(find . -type f -size +10M | head -1)      # ./usr/lib/debug/usr/bin/tmm64.debug

nm --defined-only "$B" | awk '$2=="T"' | wc -l     # global functions
nm --defined-only "$B" | awk '$2=="t"' | wc -l     # local  functions
nm --defined-only "$B" | grep -c constprop         # IPA clones
readelf -S "$B" | grep -c '\.debug_'               # DWARF present?
```

## 10 · eBPF shield programs — same box, host toolchain

**The toolchain container has no clang.** Compile shield programs on the *host*, which
has clang 18 with `bpf`/`bpfel`/`bpfeb` targets:

```bash
clang -O2 -g -target bpf -c shield.bpf.c -o shield.bpf.o
```

Compile them **on this box, against `ctx` headers from `~/code/tmm`** — a shield must
include the struct definition for its hook, and that layout is generated per build. A
hand-copied struct can drift silently from the build you load into.

Verification stays off the box, mirroring the real pipeline (compile in dev/CI, verify
and sign at F5, only *load* on the target). This sandbox has PREVAIL built and
`substrate/budget_pass.py`:

```bash
./ebpf-verifier/bin/prevail shield.bpf.o <section> \
    --termination --strict --no-division-by-zero --stack-size 256
python3 substrate/budget_pass.py --section <section> shield.bpf.o
```

`prevail`'s defaults are permissive — `--termination` is *"Default: ignore"*,
`--allow-division-by-zero` is *"Default: allow"*, `--strict` is off. Pass them
explicitly; "verified" otherwise means less than it sounds.

## 11 · Datkube box — the separate run target

```bash
~/.venvs/openstack/bin/ansible-playbook provision-machine.yml \
  -e "cloud_name=sea instance_name=eob-bnk-datkube-01" \
  -e "@vars.yml" -e "@instance_config.yml"
```

Then **step 5's `daemon.json` first** (kind is exactly what triggers the collision), step
6 to configure, step 7 for credentials, and:

```bash
# tooling the playbook does not install
KV=$(curl -sL https://dl.k8s.io/release/stable.txt)
curl -sLo kubectl "https://dl.k8s.io/release/${KV}/bin/linux/amd64/kubectl" && sudo install -m0755 kubectl /usr/local/bin/
curl -sLo kind https://kind.sigs.k8s.io/dl/v0.26.0/kind-linux-amd64 && sudo install -m0755 kind /usr/local/bin/
curl -sL https://get.helm.sh/helm-v3.16.3-linux-amd64.tar.gz | tar xz linux-amd64/helm && sudo install -m0755 linux-amd64/helm /usr/local/bin/
curl -sLo yq https://github.com/mikefarah/yq/releases/download/v4.44.5/yq_linux_amd64 && sudo install -m0755 yq /usr/local/bin/

git clone git@gitswarm.f5net.com:datkube/datkube.git ~/code/datkube
cd ~/code/datkube && bash scripts/install.sh        # must be non-root; installs the CLI
sudo sysctl -w fs.inotify.max_user_instances=8192
datkube create-cluster                              # kind + Calico + Multus, ~90 s
datkube set-profile bnk-core && datkube install
```

If an apt source fails TLS verification (an image carrying an HTTPS third-party repo such
as `baltocdn.com`), disable it — Ansible's `apt` module treats one failed source as
fatal:

```bash
grep -rl baltocdn /etc/apt/sources.list.d/ | while read f; do sudo mv "$f" "$f.disabled"; done
```

**Cluster access from elsewhere.** kind binds the API to `127.0.0.1:<port>` and its
certificate is issued for `127.0.0.1`, so tunnel the *same* port to keep TLS valid:

```bash
PORT=$(ssh -i $KEY <ldap-user>@$DATKUBE_IP 'kubectl config view --minify -o jsonpath="{.clusters[0].cluster.server}"' | sed 's/.*://')
ssh -L $PORT:127.0.0.1:$PORT -i $KEY <ldap-user>@$DATKUBE_IP
```

## 12 · The cycle — build box to Datkube box

```bash
# one-time, on the Datkube box: stop it pulling from Artifactory
kubectl edit deploy/f5-tmm         #  image: tmm:local
                                   #  imagePullPolicy: Never

# each iteration, on the build box
sudo rm -rf RPMS SRPMS docker_build/DEBS BUILD_* docker_build/tmm-runtime.*
make tmm container
docker save tmm:local -o /tmp/tmm-local.tar
scp /tmp/tmm-local.tar <ldap-user>@$DATKUBE_IP:/tmp

# on the Datkube box
kind load image-archive /tmp/tmm-local.tar --name datkube
kubectl delete $(kubectl get pods -l app=f5-tmm -o name)
```

The fast-cycling page's `datpush` script chains the last four steps. On a single box they
collapse to `kind load docker-image tmm:local --name datkube` with no tarball.

## 12b · Embed the VM in TMM

Everything above builds *stock* TMM. This is the part that puts a verified eBPF VM inside it.
Four places, about 30 lines, and the traps are all in *how the build finds things* rather than
in the code.

**First, build uBPF with the same compiler as TMM.** Linking needs a matching C library, and
the toolchain container is the only place that guarantees it:

```bash
cp -r <ubpf-source> ~/code/tmm/.ubpf            # inside the tree, so /tmm/.ubpf in the container
C=$(docker ps --format '{{.Names}}' | head -1)
script -qec "docker exec -i $C bash -c '
  cd /tmm/.ubpf &&
  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DUBPF_ENABLE_TESTS=OFF \
        -DUBPF_SKIP_EXTERNAL=ON -DCMAKE_POSITION_INDEPENDENT_CODE=ON &&
  cmake --build build -j8'" /dev/null
#  -> .ubpf/build/lib/libubpf.a, built by the same gcc 11.4 that builds TMM
```

**Then the four changes.** Copy `substrate/ls_vm*.{c,h}`, `vm_stack_policy.h` and the generated
`ls_ctx_*.h` into `src/base/`, embed the verified shield as a byte array, and:

```bash
# 1. Makefile.overrides at the repo root --- the library only
cat > ~/code/tmm/Makefile.overrides <<'MK'
DEVFS_LIBS  += $(TOPDIR)/.ubpf/build/lib/libubpf.a
MK

# 2. src/compile/filelist --- register the sources AND carry the include paths.
#    A global `CFLAGS +=` in Makefile.overrides does NOT reach these files (below).
#    Add next to the other user-defined options:
#      UBPF = CFLAGS += -I$(TOPDIR)/.ubpf/vm/inc -I$(TOPDIR)/.ubpf/build/vm
#    then one line per source, tagged with it:
#      base/ls_vm.c            STDINC UBPF
#      base/ls_vm_config.c     STDINC UBPF
#      base/ls_vm_load.c       STDINC UBPF
rm -f ~/code/tmm/src/compile/filelist.mk     # it is GENERATED; delete to regenerate

# 3 + 4. in the hooked module: arm at per-instance init, call at the fault site
```

**The include path is the trap that costs a build.** A global `CFLAGS +=` in
`Makefile.overrides` reached 344 compile lines and **not** the one file that needed it.
`filelist` line 14 is `INSTRUMENT = CFLAGS +=`, which every file inherits, so `filelist.mk`
emits a **target-specific** `CFLAGS` for essentially every object and the global addition is
invisible in that scope. Use a `filelist` option, as above. Two paths are needed: `vm/inc` for
`ubpf.h`, and `build/vm` for **`ubpf_config.h`, which cmake generates** and which therefore
does not exist until uBPF is configured.

**Cross-directory includes use `local/`.** `src/compile/local` is a symlink to `..`, so a module
file reaches `src/base` as `#include <local/base/ls_vm.h>`, never a relative path. Getting this
wrong fails only in the *consuming* file, after the new file has already compiled clean.

### The gate nobody expects: TMM whitelists mutable global state

`src/compile/Makefile:1626` runs `bin/diff-globals` against a per-architecture, per-build-type
list. `bin/print-globals` extracts `.data`, `.bss` and COMMON symbols — deliberately **not**
functions. It is an allowlist of **global mutable state**, and any new entry fails the link.

```bash
# after a failed link, the diff names the new symbols; add them deliberately
cd ~/code/tmm/src/compile
printf '%s\n' g_cfg g_origin g_slots g_ready ... >> debug_whitelist_x86_64
sort -u debug_whitelist_x86_64 -o debug_whitelist_x86_64
# repeat for default_whitelist_x86_64
```

Two things follow. **Predict the symbols and pre-add them** — it saves a 12-minute cycle. And
**give every static a unique name**: `print-globals` truncates at the first dot, so a
`static ... buf[]` enters the permanent allowlist as the entirely generic `buf`.

**Then build normally:** `script -qec "make tmm-gdb" /dev/null`.

## 12c · Load it into the cluster and run it

**Create the cluster on the deploy box.** `datkube` is already installed on it:

```bash
sudo sysctl -w fs.inotify.max_user_instances=8192
datkube create-cluster                  # kind: control-plane + worker, Calico, Multus, ~90 s
printf 'export AF_USERNAME=%s\nexport AF_TOKEN=%s\n' "$U" "$T" > ~/.af_env && chmod 600 ~/.af_env
. ~/.af_env && bash ~/code/datkube/scripts/setup-auth.sh
datkube set-profile bnk-core && datkube install     # ~10 min; creates deploy/f5-tmm
```

`datkube get-profiles` lists them — **not** `list-profiles`, which is not a verb.

**Ship the image. `kind load` does not work here:**

```bash
docker save tmm:local -o /tmp/tmm-local.tar
scp -i ~/.ssh/id_datpush /tmp/tmm-local.tar starin@<deploy>:/tmp/

# kind load image-archive fails: "ERROR: failed to detect containerd snapshotter"
# so do what it does underneath --- and do it for EVERY node
for n in datkube-control-plane datkube-worker; do
  docker exec -i $n ctr --namespace=k8s.io images import - < /tmp/tmm-local.tar
done
```

**Why per node, and why not `docker load`:** there are **two image stores**. `docker images` on
the VM shows only the `kindest/node` image, because docker runs the *nodes*; every workload runs
one level down under each node's own containerd. `docker exec <node> crictl images` is where the
25 real images live. The kubelet asks its node's containerd, so an image in the VM's docker is
invisible to Kubernetes.

**Point the deployment at it and roll:**

```bash
kubectl set image deploy/f5-tmm f5-tmm=docker.io/library/tmm:local
kubectl patch deploy f5-tmm --type=json \
  -p='[{"op":"replace","path":"/spec/template/spec/containers/0/imagePullPolicy","value":"Never"}]'
kubectl rollout status deploy/f5-tmm --timeout=240s
```

**Verify the running binary is yours — and not with `strings` inside the container**, which is
absent there and silently returns zero for everything:

```bash
kubectl cp <pod>:/usr/bin/tmm64.debug /tmp/pod_tmm -c f5-tmm
strings -a /tmp/pod_tmm | grep -c 'does not live in section'    # expect >= 1
```

`nm` will report **zero** uBPF symbols: the shipped binary is stripped, not un-integrated.

## 12d · Turn it on, and measure

Nothing is enabled by default — an unset environment behaves exactly like stock TMM. Everything
below is a `kubectl set env` and a pod restart, roughly ten seconds, versus twenty minutes for a
rebuild:

```bash
kubectl set env deploy/f5-tmm -c f5-tmm \
  LS_VM_VERBOSE=1 \        # arm confirmation, build stamp, first invocation
  LS_VM_BENCH=100000 \     # cycle floor at init, without needing traffic
  LS_VM_TIMING=1 \         # accumulate cycles on the real call path
  LS_LOAD_SOCKET=/tmp/ls_load.sock   # runtime load path (UNVERIFIED --- see below)
```

Others: `LS_SHIELD_ENABLE`, `LS_SHIELD_MODE` (disable|monitor|enforce), `LS_SHIELD_PATH` (load
the program from a file instead of the built-in blob), `LS_SHIELD_SECTION`/`LS_SHIELD_FUNCTION`
(O14's two identities), `LS_VM_FUEL`, `LS_VM_JIT`, `LS_VM_REPORT_EVERY`.

What it prints:

```
ls_vm: init  build=<stamp>  jit=0 fuel=0 timing=1
ls_vm: ARMED slot=0 section=fentry/<hook> function=shield mode=2 bytes=4320
ls_vm: bench slot=0 path=interp iters=100000 min=126 mean=287 max=1403200 cycles
ls_vm: LOADER LISTENING on /tmp/ls_load.sock --- accepts UNVERIFIED programs
```

**`LS_LOAD_SOCKET` has no signature verification** (scope item 4, deferred). It is off unless
set, the socket is 0600, and every load says so. Do not leave it enabled in anything shared.

### Reading the numbers honestly

`min` is the cleanest estimate; `mean` is 2–3× it even on an idle box with no traffic, and `max`
is scheduler preemption rather than the program. It measures the program **only** — no `ctx`
build, no trampoline, no poll loop — so it is a **floor**, for the smallest useful program.

## 13 · Teardown

```bash
openstack --os-cloud sea server delete eob-bnk-build-01 eob-bnk-datkube-01 --wait
```

Deleting the build box costs the 2.2 GB clone and the 2.5 GB toolchain image, so keep it
if you will be back soon.

---

## Gotchas, in one place

| symptom | cause |
|---|---|
| box healthy on console, **every port refuses**, never recovers | docker/kind allocated `172.18.0.0/16`, which is the NATed path back to this sandbox. Step 5. |
| playbook: "SSH port not available after 300 seconds" on a live box | inventory took SEA's IPv6 address; dual-stack AdminNetwork. Step 4. |
| playbook: "key hash not the same as offered" | keypair was generated server-side; delete it and let the playbook upload yours. Step 3. |
| no dev user; later "chown failed: failed to look up user" | a `- role:` line was commented out, orphaning its `when:` onto `common`. Step 2. |
| `--check` dies in `from_json` | VM is created by shell tasks, which check mode skips. Step 4. |
| yq missing → `docker: invalid reference format` / `docker run … :v` | Makefile resolves image names from `input-manifest.yml` via `yq`; install mikefarah's. Step 8. |
| ssh refused as `ubuntu` on a configured box, or as `<ldap-user>` on a pristine one | the playbook disables `ubuntu` and creates the LDAP user; exactly one answers at a time. Step 6b. |
| build: "the input device is not a TTY" | every `docker exec` is `-it`; use `script -qec`. Step 8. |
| build: missing `/usr/include/errdefs/product_codes.h` | `install-libs` never ran because `_start` failed. Step 8. |
| build: "sed: can't read .env" / "username is empty" | TMM needs its own `.env`. Step 8. |
| `kind load` fails: "failed to detect containerd snapshotter" | use `docker exec <node> ctr --namespace=k8s.io images import -` per node. Step 12c. |
| a header is missing on exactly ONE file while hundreds compile | a global `CFLAGS +=` does not reach files that `filelist.mk` gives target-specific flags to — which is nearly all of them. Use a `filelist` option. Step 12b. |
| link fails with a diff of symbol names | TMM whitelists mutable global state (`.data`/`.bss`/COMMON, not functions). Add them deliberately. Step 12b. |
| `strings` inside the f5-tmm container returns 0 for everything | it is not installed there; `kubectl cp` the binary out first. Step 12c. |
| `nm` shows zero `ubpf_*` symbols in the running binary | it is stripped, not un-integrated. Step 12c. |
| `docker images` on the deploy VM shows only `kindest/node` | two image stores; workloads live in each node's containerd. Step 12c. |
| a backgrounded process in `kubectl exec` dies when the exec ends | use something that daemonises, or a long-lived pod command. |
| `F5VirtualServer` rejected: "Unsupported value: round-robin" | the enums are upper-case (`ROUND_ROBIN`); `snat.type` is lower-case (`automap`). |
| virtual server accepted but connections refuse | check TMM's own log for `Proxy initialization failed ... Defaulting to DENY`, and for `address conflict detected` — the VIP may already be taken. |
| `git clone`/`FetchContent` fail as though the remote is down | Netskope CA not trusted. Step 0. |
| apt: "certificate is NOT trusted" | image carries an HTTPS third-party repo; disable it. Step 11. |
| GitLab project returns 404 while signed in | no membership — it is not a missing repo. Step 0. |
