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
| flavor | `datkube-dev-large` (16 / 32 GB / 250 GB) | `datkube-dev-large` — same |
| as actually built | 16 vCPU · 31 GB · 242 GB · Ubuntu 24.04 · 6.8.0-38 | identical, both boxes |

**Both boxes were provisioned identically**, and that is recorded here because the row
above used to read "smaller is fine" for the Datkube box — advice about what would
work, not a record of what exists. Rebuilding from advice gives you a box that is
probably adequate; rebuilding from the line above gives you the one the measurements
were taken on. The image is `Ubuntu2404-server-pristine` (§2), so the kernel comes
with it rather than being chosen.

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

# THE COLLECTION MUST BE 2.6.0 OR NEWER, and this is not a detail --- it is where a replay of this
# runbook stops. Found 2026-08-21 by actually running it: the first provisioning attempt died on
# its first real task, "Upload SSH public key", with
#
#   module 'openstack' has no attribute 'version'
#
# openstacksdk 4.x removed the openstack.version module; openstack.cloud 2.5.0 still imports it.
# The venv ships 2.5.0 bundled with ansible, so a plain `pip install ansible openstacksdk` gives an
# incompatible pair and the error names neither package. `--force` fetches 2.6.0, which knows about
# sdk 4.x, and it installs to ~/.ansible/collections --- which takes precedence only if you say so:
~/.venvs/openstack/bin/ansible-galaxy collection install --force openstack.cloud
export ANSIBLE_COLLECTIONS_PATH="$HOME/.ansible/collections"
~/.venvs/openstack/bin/ansible-galaxy collection list openstack.cloud   # expect 2.6.0 first
#
# Do NOT pin openstacksdk backwards instead. python-openstackclient in the same venv is working
# against 4.18.0, and downgrading the SDK to suit the collection trades a broken playbook for a
# broken CLI. Only one task in provision-machine.yml uses the collection at all --- the VM itself
# is created by shelling out to `senf/bin/openstack server create` --- so the forward fix is small
# and the backward one is not.

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
seconds"* on a box that is up and answering. **Re-confirmed verbatim on 2026-08-21** against a
freshly provisioned box: `elapsed: 300`, `failed=1`, and `ssh ubuntu@<ipv4>` answered throughout.
Worth recording that a documented prediction held, not only the ones that did not — the two
findings this replay produced were elsewhere. The generated inventory takes the **first**
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

**ASSERT §5 FIRST. The order of §5 and §6 is load-bearing and nothing enforces it.** §6 installs
and starts Docker; §5 is what stops Docker choosing an address pool that collides with the
AdminNetwork the box is reached over. Run them the wrong way round and the box disconnects itself
and looks dead. On 2026-08-21 I did exactly that on a rehearsal box — provisioned, then jumped
straight to §6 — and got away with it only because `common`'s long apt phase runs before the
`docker` role, leaving a window to write the file while `systemctl is-active docker` still said
`inactive`. That is luck, not procedure. One line removes the luck:

```bash
ssh -i $KEY ubuntu@$IP 'test -f /etc/docker/daemon.json && echo pool-set' ||   { echo "*** §5 has not been applied. Do it before this playbook starts Docker."; exit 1; }
```

**And use the playbook named here.** The clone also contains `configure-only.yml`, which looks like
the right thing and is not: it lists roles `go` and `vim`, neither of which exists in
`roles/`, so it fails immediately with *"the role 'go' was not found"*. That is an upstream file
that is not on this path — the one this runbook uses is `setup-dev-machine-slim.yml`.

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
perf-tools-unstable universal-ctags python3-dev/pip/venv` — plus Docker CE and Go.

**A correction I made here on 2026-08-21 was wrong, and it is left visible rather than deleted.**
I wrote that Go is *not* installed, on the strength of `ssh box 'command -v go'` returning nothing
and `/usr/local/go` not existing. Both observations were real and the conclusion was false, for two
reasons at once: the `golang` role unarchives Go into **`$HOME`**, not `/usr/local`, so I looked in
the wrong place; and it adds `~/go/bin` to `.bashrc`, which a **non-interactive** `ssh host 'cmd'`
never sources, so `command -v` could not have found it either way. Checked properly on the same
box: `~/go/bin/go version` → **`go1.27.0 linux/amd64`**, 282 MB in `~/go`. I also wrote that the
269 MB `~/go` on the previous build box "came from somewhere else" — it came from exactly this role.

Fourth time in one day I asserted from a single failed probe. The pattern is specific enough to
name: **a negative result from one lookup is evidence about the lookup, not about the system.** Note
`clang`, `pahole` and `elfutils` in that list: eBPF compilation and the `nm`/`readelf`
symbol work both land on this box by default, which is why it is the right home for shield
development.

It also **creates a user named after `olympus_user` and disables `ubuntu`**. From here on,
`ssh ubuntu@...` answers *"Permission denied (publickey,password)"* — that is the playbook
having worked, not a lockout. Log in as your LDAP username. It adds that user to the
`docker` group too, so no `usermod` is needed.

**Replayed 2026-08-21 on a fresh box and the recap matched this line exactly** — `ok=50 changed=25
unreachable=0 failed=0 skipped=37 ignored=3` — on a *different flavour* (`m1.small`), which makes it
a statement about the playbook rather than about one machine. Also confirmed the same run:
`starin` created with groups `starin sudo docker` and passwordless sudo, and `ssh ubuntu@…` refused
with *"Permission denied (publickey,password)"*, which is this playbook having worked.

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

**Do not do this by hand --- use `env/scripts/bnk-package.sh`.** It performs the removal,
verifies it by COUNTING what survived (the files are root-owned and `rm -f` keeps going after
Permission denied, so a script can report success having removed nothing), runs `make
container`, and then checks that the packaged binary actually contains the substrate that was
built. That last check is not redundant with the build-id gate: a stale DEB agrees with
itself, so the ids match and the image ships without the change.

This paragraph existed before the script did, and on 2026-08-19 it was not read --- two `make
container` runs were wasted, one packaging a byte-identical copy of the deployed binary and
one dying with `gcc: fatal error: no input files` from a stale `BUILD_x86_64`. Both are the
sentence above. A step that has to be remembered at the right moment is not a control.

```bash
env/scripts/bnk-package.sh          # clear + build + verify freshness
env/scripts/bnk-package.sh --check  # verify an existing DEB pair only
```

What it removes, for the record:

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

**Do not run this by hand.** `env/scripts/bnk-build-programs.sh` is the stage:

```bash
env/scripts/bnk-build-programs.sh $HOME/lstools/shields
```

It compiles every `substrate/shields/*.bpf.c`, verifies each with PREVAIL, emits **only** what
verifies, and asserts the expected verdict in both directions — programs named `reject_*` must
be refused, and a build where one of them passes fails the stage, because that means the
verifier stopped catching what the program was written to trip. It also reads each object's own
`fentry/<hook>` section rather than a table beside it, so a program cannot be baked against a
different function than the one it was compiled for. Current set: 16 verified, 2 refused.

The single-file invocation, for reference when debugging one program:

```bash
clang -O2 -g -target bpf -I substrate -c shield.bpf.c -o shield.bpf.o
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

**There are TWO copies of this repo on the build box, they are refreshed by different scripts,
and they feed different things.** Getting this wrong costs a whole cycle and the symptom points
somewhere else entirely, so it goes first:

| copy | refreshed by | what reads it |
|---|---|---|
| `code/tmm/src/{base,modules/…}` | `bnk-stage.sh` then `bnk-sync-substrate.sh` | the compiler — these become TMM |
| `~/eob-tmm-staged/` | `bnk-stage.sh` | `bnk-package.sh` freshness checks, and `bnk-bake-tools.sh`, which copies the **tools baked into the image** from here |

On 2026-08-20 the second was three commits behind. The image shipped an `ls-load.py` from before
signatures existed, so it sent no signature, and TMM — working correctly — refused every load.
Nothing in the pipeline read that tree's provenance, and the `-dirty` stamp added that morning
covered `substrate/` only. **Always start a cycle with `bnk-stage.sh`.** It copies the working
tree (not `HEAD`, because the substrate is normally built before it is committed), verifies the
far end by content, and fails if the staged client cannot send a signature.

```bash
env/scripts/bnk-stage.sh            # BOTH trees start here. Verifies by content, not by exit code.
env/scripts/bnk-sync-substrate.sh   # then the sources that get compiled in
```


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

**It is an exact match, not a superset allowlist.** `diff-globals` runs `diff -u` between the
whitelist and the binary's actual globals and fails on a difference in *either* direction — so
**removing** global state breaks the build exactly as adding it does. Moving a `static` buffer
to a `malloc` cost a full build cycle for precisely this: the symbol vanished, the whitelist
still listed it, and the failure reads identically to an unauthorised addition. Read the sign in
the diff: `+name` is new state, `-name` is state you deleted.

Arguably that is the better design — you cannot quietly drop tracked state either — but it means
the whitelist is a *manifest*, not a permission list.

Two more things follow. **Predict the symbols and pre-add them** — it saves a 12-minute cycle,
but only if the prediction is right in both directions; a wrong pre-add costs the cycle it was
meant to save. And **give every static a unique name**: `print-globals` truncates at the first
dot, so a `static ... buf[]` enters the permanent manifest as the entirely generic `buf`.

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
ls_vm: signature verification ARMED --- unsigned programs are refused
ls_vm: LOADER LISTENING on /tmp/ls_load.sock.25 --- programs are signature-checked, the PEER is not
```

**`LS_LOAD_SOCKET` verifies signatures** (scope item 4, built 2026-08-20) and still must not be
left enabled in anything shared. The signature says the program came from the holder of the key;
it says nothing about who asked for it to be armed. The socket is 0600 and off unless set, and
that --- not the signature --- is what keeps it contained. A build compiled without a key refuses
everything, which is the right direction to fail but means an unkeyed build looks broken.

If a load is refused and the signature looks fine, check the CLIENT before the crypto: an image
carrying an `ls-load.py` from before signatures existed sends none, and the refusal is correct.
The one-line tell is in TMM's own log --- `ls_sig: verifying binding ... sig 00000000 ...`.

### Demonstrating the shield without traffic --- `LS_VM_SELFTEST`

The CVE needs a specific misconfiguration to fire naturally (below). `LS_VM_SELFTEST` builds
the `ctx` the vulnerable call site would build with a NULL protocol-transfer log profile, runs
it through the armed shield, and at level 2 performs the dereference if the shield declines.

```bash
# A --- enforce: the shield acts. TMM survives.
kubectl set env deploy/f5-tmm -c f5-tmm LS_SHIELD_MODE=enforce LS_VM_SELFTEST=2
#   SELFTEST cve-condition ptlp=NULL -> verdict=SAFE_RETURN
#   SELFTEST survived --- shield prevented the dereference
#   pod Running, restarts=0

# B --- monitor: the shield SEES it and declines to act. TMM dies at init.
kubectl set env deploy/f5-tmm -c f5-tmm LS_SHIELD_MODE=monitor
#   SELFTEST cve-condition ptlp=NULL -> verdict=FALLTHROUGH
#   SELFTEST performing the unshielded dereference --- expected fatal

# C --- ALWAYS UNSET IT AFTERWARDS
kubectl set env deploy/f5-tmm -c f5-tmm LS_VM_SELFTEST- LS_SHIELD_MODE=enforce
```

**Monitor, not `LS_SHIELD_ENABLE=0`.** Disabling skips arming entirely, so the self-test never
runs. Monitor is also the honest comparison: it is the posture an operator uses before
enforcing, and it shows the shield *recognising* the condition while the host declines to act.

> **Step C is not optional.** The self-test runs at **init**, so with `LS_VM_SELFTEST=2` left
> set in monitor mode **every pod dies at startup and Kubernetes starts another** — a crash loop
> that looks like a broken deployment rather than a successful demonstration. Leaving it set is
> how you lose an afternoon to pod churn and cannot capture any evidence, because every pod you
> try to inspect has already been replaced.

**Two cautions on reading the result.**

The `SELFTEST did NOT crash` line is a **negative control**: it prints only if the dereference
returns. Its absence is the pass condition. If it ever appears, the dereference was survivable
(page zero mapped, or the compiler elided it) and the demonstration proves nothing.

And **the self-test pollutes the hook's own counters.** It calls `ls_vm_call()`, the same entry
point the real hook uses, so it increments `fired` and triggers
`FIRST INVOCATION --- the hook is reached`. With no traffic flowing, that line is **false** ---
the harness reached the hook, not a packet. Do not read it as evidence the hook is live while
`LS_VM_SELFTEST` is set.

### Reading the numbers honestly

`min` is the cleanest estimate; `mean` is 2–3× it even on an idle box with no traffic, and `max`
is scheduler preemption rather than the program. It measures the program **only** — no `ctx`
build, no trampoline, no poll loop — so it is a **floor**, for the smallest useful program.

**`fired` is CUMULATIVE, and a fresh `load` does not reset it.** `gen` increments; the counter
does not. So a `fired` read after a reload includes every earlier run's traffic, and comparing it
against "how many requests did I just send" gives a ratio that is not a ratio. On 2026-08-20 that
read as `fired=34` against 20 requests and looked like it contradicted the once-per-request claim
recorded here. It did not: loading fresh, arming, and sending exactly ten took the counter from 34
to 44. **Take the difference across the interval you drove, never the absolute value** — or
`revoke` the slot first if you want the number to stand on its own.

## 12e · Traffic through the proxy

**BNK uses Gateway API.** Not `F5VirtualServer` — that belongs to the **CNF** profiles, and
adapting one of their manifests leads to `F5BigCnePool`, a CRD `bnk-core` does not install,
whose absence produces a LoadBalancer Service that IPAM never fills. Every symptom then points
at ports and addresses and none of the fixes hold. The reference that works is
**`profiles/bnk-external`**, which exists specifically for traffic testing.

`bnk-core` already ships the harness: `client` (11.11.11.100) and `server` (22.22.22.100) pods
either side of TMM, VLANs `tmm-client`/`tmm-server`, TMM self-IPs on both. The client image
carries `curl`, `wget`, `nc` and **`ab`**, so load generation needs nothing installed.

```bash
# NOT needed --- bnk-core/profile.yaml lines 30-35 already create spk-app-1 .. spk-app-6
# at `datkube install`. They are empty scaffolding: NOTHING runs in them. Every pod that
# matters --- both f5-tmm replicas, and TWO client/server pairs (client, client-lb,
# server, server-lb) --- lives in `default`. A namespace here is only where a Gateway CR
# is placed; it is not a traffic path and adding more does not add load.
# To drive a richer profile than one VIP with one backend and one URL (which is what the
# 2026-08-13 hook measurement used, and too thin to price a per-call cost from), use the
# second client/server pair and more Gateways --- not more namespaces.
kubectl get ns | grep spk-app          # expect six, already Active
kubectl get pods -n default            # this is where the work actually is

cat <<'YAML' | kubectl apply -f -
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata: {name: gateway-class}
spec:
  controllerName: f5.com/default-f5-cne-controller
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: {name: gateway, namespace: spk-app-1}
spec:
  gatewayClassName: gateway-class
  addresses:                       # explicit --- no IPAM needed for this
  - {type: IPAddress, value: "11.11.11.99"}
  listeners:
  - {name: http, protocol: HTTP, port: 80, allowedRoutes: {kinds: [{kind: HTTPRoute}]}}
---
apiVersion: k8s.f5net.com/v1       # kind Pool --- what Gateway routes reference
kind: Pool
metadata: {name: http-pool, namespace: spk-app-1}
spec:
  members: [{address: "22.22.22.100", port: 80}]
  monitors: {tcp: [{}]}
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {name: http-route, namespace: spk-app-1}
spec:
  parentRefs: [{name: gateway, sectionName: http}]
  rules:
  - backendRefs: [{name: http-pool, kind: Pool, group: k8s.f5net.com}]
YAML

# a backend that survives the exec ending
kubectl exec server -- sh -c 'mkdir -p /tmp/www; echo backend > /tmp/www/index.html;
  (setsid python3 -m http.server 80 --directory /tmp/www >/tmp/h.log 2>&1 &)'

kubectl get gateway -n spk-app-1     # expect  PROGRAMMED=True
kubectl exec client -- curl -s http://11.11.11.99/
kubectl exec client -- ab -n 500 -c 10 -q http://11.11.11.99/
```

Measured: `http=200`, 500 requests, **0 failures**, 136 req/s.

### When it does not work, read the reset payload

The single most useful diagnostic, and it should be the *first* move rather than the tenth —
TMM ships with `tcpdump`:

```bash
kubectl exec <tmm-pod> -c f5-tmm --   sh -c 'timeout 12 tcpdump -i any -n -A -c 6 "host 11.11.11.99 and tcp" > /tmp/c.txt' &
kubectl exec client -- curl -s -m 6 -o /dev/null http://11.11.11.99/
kubectl exec <tmm-pod> -c f5-tmm -- grep -a "BIG-IP" /tmp/c.txt
```

TMM writes its reason into the RST payload:

```
BIG-IP: [0x34315a9:136] Port denied ... lis=default-ltm-vs-basic port=1.1
```

`lis=` on the way out names the listener that matched, and `lis=` empty on the way *in* means
nothing matched at SYN time. **`Port denied` means the listener never opened** — not that a port
is blocked — which points at the config model rather than at firewalling.

**Two things that cost hours and are worth checking first.** A `python3 -m http.server` started
inside `kubectl exec` dies when the exec ends; `setsid` it. And controllers here build their
informers at startup — `spk-f5ingress` kept logging `Failed to find lister` for a CRD created
after it started, and only a `kubectl rollout restart` fixed it.

## 12f · What builds am I holding, and where

Ask this rather than remember it. Image sprawl has been a real complaint here twice, and a
frozen list in a document is wrong the day after it is written --- so this section is the
commands, not an inventory.

**A TMM build is identified by its GNU build id, not by a tag.** Four docker tags routinely point
at two images, and `tmm:ls` is rebaked in place, so tags tell you nothing about how many distinct
binaries exist.

```bash
# BUILD BOX --- every TMM image, and the build id inside each one
ssh starin@10.145.42.119 'docker images --format "{{.ID}}  {{.Repository}}:{{.Tag}}  {{.Size}}" | sort'
for T in tmm:ls tmm:local tmm:local_img; do
  printf "%-16s " "$T"
  ssh starin@10.145.42.119 "docker run --rm --entrypoint sh $T -c \
    'R=\$(readlink -f /usr/bin/tmm); python3 /usr/share/ls/ls_buildid.py \$R 2>/dev/null || echo no-ls-tools'"
done

# BUILD BOX --- the linked binary, and the one that actually shipped
ssh starin@10.145.42.119 'cd code/tmm
  python3 ~/eob-tmm-staged/substrate/ls_buildid.py src/compile/obj_x86_64.no_pgo/tmm.no_pgo
  T=$(mktemp -d); dpkg-deb -x docker_build/DEBS/amd64/tmm_10*.deb $T
  python3 ~/eob-tmm-staged/substrate/ls_buildid.py $T/usr/bin/tmm64.no_pgo; rm -rf $T'

# DATKUBE --- kind keeps images per NODE, in containerd, not in the host's docker
ssh -o IdentitiesOnly=yes -i ~/.ssh/id_ed25519 starin@10.145.35.70 '
  for n in $(docker ps --format "{{.Names}}" | grep datkube); do
    echo "--- $n"; docker exec $n ctr -n k8s.io images ls -q | grep -i tmm
  done'
```

**THE LINKED BINARY AND THE SHIPPED ONE ALWAYS DIFFER, and that is not staleness.** `make
container` runs `rpmbuild`, which recompiles from a source tarball inside the toolchain
container, so `obj_x86_64.no_pgo/tmm.no_pgo` carries a different build id from the DEB every
time. Measured 2026-08-19: `aef8cac4` linked, `03c6f0e0` packaged, both containing the same
change. Do not "fix" that difference --- an earlier freshness check required them to be equal
and would have rejected every correct package. Freshness is
`bnk-check-deb-contains-substrate.sh`, which compares the DEB against the SOURCES.

**The debuginfo package ships TWO debug binaries with different build ids** ---
`tmm64.no_pgo.debug` and the PGO `tmm64.debug`. That is F5's packaging. Select by build id
against the runtime DEB, never by size or name; picking the larger one gave a signature index
for a build TMM does not run, differing in 3,132 functions.

**What is safe to delete, and what it costs:**

| artifact | safe? | cost of deleting |
|---|---|---|
| `tmm:ls`, and any tag not currently deployed | yes | one bake (~4 min) |
| `docker_build/DEBS`, `RPMS`, `tmm-runtime.*.tgz`, `BUILD_*` | yes, and `bnk-package.sh` does it | one `make container` |
| `src/compile/obj_x86_64.*` | yes | a FULL rebuild, ~20 min --- this is the incremental state |
| `tmm-img:v10.204.15` in the kind nodes | **no** | the cluster's baseline image, not ours |

## 12g · Before any teardown: what must be IN HAND, not on the boxes

Written 2026-08-21, when a from-nothing replay was proposed and the honest answer to "can these
machines be restored" turned out to be **no**. Not because the software is unrecoverable — that
part was audited and is complete (`env/scripts/bnk-replay-audit.sh`, 15 checks) — but because
**three browser-issued credentials are needed to rebuild, and two of them exist only on the boxes
themselves.**

| needed to rebuild | where it lives today | if the boxes are deleted |
|---|---|---|
| `clouds.yaml` (OpenStack) | **nowhere reachable** — §1 builds it from `clouds-sea.yaml`, downloaded from the Horizon web UI | cannot provision *anything*. This alone is decisive |
| GitSwarm SSH private key | `~/.ssh/id_rsa` on the **build box only** (`git@gitswarm.f5net.com:tmm/tmm.git`) | cannot clone TMM. A new key must be created in the GitSwarm UI |
| Artifactory token | `~/.af_env` on the **datkube box only**, plus `~/.docker/config.json` on both | cannot pull the toolchain container or the BNK images. Tokens are shown **once**, so it must be regenerated in a browser |

**The shape of this is worth naming, because it is the same shape as the vendored-dependency gap
and the stale staging copy: the thing needed to reproduce lives only where the work was done.** A
credential on a machine is not a credential you have; it is a credential the machine has. The
software half was made reproducible by writing it down and checking it. The credential half cannot
be — writing a token into a repository is the failure it would prevent — so what is possible is a
checklist, and this is it.

**Before deleting anything, confirm all three are in hand — and TEST them, do not test for the
presence of a file:**

```bash
# 1. provisioning.  The clouds files live in the REPO DIRECTORY, not $HOME, and are gitignored.
python3 env/scripts/merge-clouds-yaml.py sea=clouds-sea.yaml sjc=clouds-sjc.yaml
openstack --os-cloud sea token issue -f value -c project_id      # expects a project id

# 2. TMM clone.  The key is id_ed25519_gitswarm --- NOT the id_rsa sitting beside it, which is
#    rejected --- and git does not pick it up on its own, because there is no ~/.ssh/config.
GIT_SSH_COMMAND="ssh -i ~/.bnk-creds/gitswarm_id_ed25519"   git ls-remote git@gitswarm.f5net.com:tmm/tmm.git HEAD          # expects a sha

# 3. toolchain + images.  The OLD token still works; it is shown once, so the preserved copy is
#    the only way to keep it.
. ~/.bnk-creds/af_env
curl -s -o /dev/null -w '%{http_code}\n' -u "$AF_USERNAME:$AF_TOKEN"   https://artifactory.f5net.com/artifactory/api/system/ping      # expects 200
```

**CORRECTION, 2026-08-21, recorded rather than rewritten.** The first version of this section
concluded the boxes could not be restored, on the strength of three lookups that all missed. It was
wrong on all three counts:

| I said | actually |
|---|---|
| "`clouds.yaml` nowhere reachable" | the clouds files are in the **repo directory**; I looked only in `$HOME`. They carry an *application credential*, so no password is needed, and `openstack --os-cloud sea token issue` authenticates |
| "GitSwarm key on the build box only" | true, and preservable — `scp` it off first. But it is **`id_ed25519_gitswarm`**, not the `id_rsa` beside it. I tested `id_rsa`, got `Permission denied (publickey)`, and concluded the key did not work |
| "token must be regenerated" | the **old** token still works: `api/system/ping` returns 200 and the `tc-tmm` tag list comes back |

Three lookups, three wrong conclusions, one shape: **I tested for the existence of a file rather
than for the capability, and asserted absence from a single failed probe.** The `id_rsa` case is the
sharpest — a real key, in the right place, that authenticates nowhere, sitting next to the one that
works.

**What is still genuinely open: access to a NEWLY provisioned box.** `spk-devmachine` grants the
LDAP user whatever key booted the instance (`roles/common/tasks/main.yml` copies
`/home/ubuntu/.ssh/authorized_keys`, which Nova fills from `--key-name`). The existing keypairs
`eob-bnk-dev` and `eob-datkube` share a fingerprint that matches **none** of the private keys on
this machine, so provisioning with either would produce a box nobody here can log into. The fix is
one command, and it changes nothing that exists:

```bash
openstack --os-cloud sea keypair create --public-key ~/.ssh/id_ed25519.pub eob-bnk-restore
```

**Prove the provisioning path on a THROWAWAY box first.** This is not in the original runbook and
it should be. There is a `m1.small` flavour (1 vCPU / 2 GB / 20 GB) that fits inside the 8 cores and
16 GB left over while both real boxes are running, so the whole of §2–§6 — the provisioner, the
keypair injection, the LDAP user, `sudo`, ssh from the workstation, the docker address pool — can be
exercised against a box that matters to nobody, *before* anything is deleted. It cannot build TMM;
it does not need to. What it answers is the only question a teardown really turns on: **can I get
into a machine I have just created.**

```bash
# in spk-devmachine, with instance_config.yml pointing at m1.small and a keypair you hold
~/.venvs/openstack/bin/ansible-playbook provision-machine.yml   -e "cloud_name=sea instance_name=eob-bnk-test-01" -e "@vars.yml" -e "@instance_config.yml"
# then, and this is the assertion:
ssh -i ~/.ssh/id_ed25519 starin@<ip> 'id; sudo -n true && echo sudo-ok'
openstack --os-cloud sea server delete eob-bnk-test-01 --wait    # costs nothing to throw away
```

**Keypair, and the trap §3 warns about applies here too.** `openstack keypair create NAME` with no
`--public-key` generates the key *server-side*, and the public half you derive locally will not
match what OpenStack stored — the playbook then fails with *"key name present but key hash not the
same as offered"*. Uploading your own public half is the form that works:

```bash
openstack --os-cloud sea keypair create --public-key ~/.ssh/id_ed25519.pub eob-bnk-restore
openstack --os-cloud sea keypair show eob-bnk-restore -f value -c fingerprint   # must equal:
ssh-keygen -E md5 -lf ~/.ssh/id_ed25519 | awk '{print $2}'
```

The two existing keypairs, `eob-bnk-dev` and `eob-datkube`, share one fingerprint that matches
**none** of the private keys on the workstation — so provisioning with either would produce a box
nobody can log into. That is worth knowing *before* the box that can log in has been deleted.

**And the quota is exact, so plan around it rather than discovering it:** 40 cores / 81920 MB total,
**32 and 65536 in use** by the two live boxes. A `datkube-dev-large` is 16 / 32768. Nothing else
fits — a replay must free a box before it can create one. Rebuild **one at a time**, build box
first: the cluster survives while the harder half is proven, and the surviving box keeps a copy of
every credential above.

If any line fails, a teardown is one-way. What survives regardless: this repository, the TMM tree
delta (`substrate/.tree-expected-delta`, verified complete both ways), the vendored pins and
`bootstrap.sh`, the traffic path (`env/scripts/bnk-traffic-path.sh`), and `~/lstools`, which the
bake regenerates. What does not survive: the ability to get back to a machine where any of that
can run.

---

## 13 · Teardown

```bash
openstack --os-cloud sea server delete eob-bnk-build-01 eob-bnk-datkube-01 --wait
```

Deleting the build box costs the 2.2 GB clone and the 2.5 GB toolchain image, so keep it
if you will be back soon.

---

## Gotchas, in one place

### The six empty `spk-app-*` namespaces are ours, and are supposed to be there

`kubectl get ns` on datkube shows `spk-app-1` … `spk-app-6`, all empty, and they look like someone
else's leftovers on a shared cluster. They are not. **The `bnk-core` profile creates them in its
own `install:` step** — six `kubectl create ns spk-app-N || true` lines, with matching deletes in
`uninstall:` (`~/code/datkube/profiles/bnk-core/profile.yaml`; `ai-tokenomics-core` has the same
block).

They are a fixed set of tenant namespaces for SPK multi-tenancy demos. Nothing in this work deploys
into them, so each holds only what Kubernetes and the profile add automatically: `default`
serviceaccount, `kube-root-ca.crt`, and an `artifactory-credentials` image-pull secret.

Check the creation timestamps if you doubt it — they appear within seconds of the
`f5-ipam-controller` helm install, in the middle of the profile run, not at cluster creation.
**Everything this work uses lives in `default`.**

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
| `F5VirtualServer` never programs a listener; TMM resets with `Port denied` | wrong model — BNK uses Gateway API; `F5VirtualServer` is CNF. Step 12e. |
| a controller ignores a CRD you just created | it built its informers at startup; `kubectl rollout restart` it. Step 12e. |
| `kubectl apply` of a CRD: `ShortNamesConflict` | two F5 chart sets claim the same short name. Do not file the edges off — use one CRD set. |
| `kind load` fails: "failed to detect containerd snapshotter" | use `docker exec <node> ctr --namespace=k8s.io images import -` per node. Step 12c. |
| a header is missing on exactly ONE file while hundreds compile | a global `CFLAGS +=` does not reach files that `filelist.mk` gives target-specific flags to — which is nearly all of them. Use a `filelist` option. Step 12b. |
| link fails with a diff of symbol names, and the diff shows `-name` | you *removed* global state; the whitelist is an exact match, not a superset. Delete the entry. Step 12b. |
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
