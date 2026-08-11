# OpenStack CLI reference (sjc-stack and sea-stack)

Everything needed to talk to F5's internal OpenStack environments from this
(or any similarly bare) sandbox. **Both stacks are configured**, selected by
`OS_CLOUD=sjc` / `OS_CLOUD=sea`; this document was written against
`sjc-stack` and every command in it works unchanged against `sea-stack`,
because the only difference is which cloud `OS_CLOUD` names.

Where a *result* below is stack-specific — the image list, the network list,
the flavor names — read it as sjc's and take the side-by-side comparison from
[`tmm-build-environment.md`](tmm-build-environment.md#sjc-vs-sea--differences)
instead. SEA is not a subset: it carries `CustomerConfig` and `LB-VIP-Net`
that sjc does not, and roughly twice the images.

## One-time setup

This sandbox has no root/sudo and no system `pip`/`python3-venv`
(`ensurepip` isn't installed and apt needs privileges we don't have), so
the client is installed into a manually-bootstrapped venv instead of via
the OS package manager:

```bash
# Bootstrap pip inside a venv created without ensurepip
python3 -m venv --without-pip ~/.venvs/openstack
curl -sS https://bootstrap.pypa.io/get-pip.py -o /tmp/get-pip.py
~/.venvs/openstack/bin/python3 /tmp/get-pip.py

# Install the CLI
~/.venvs/openstack/bin/pip install python-openstackclient python-glanceclient

# Put it on PATH
mkdir -p ~/.local/bin
ln -sf ~/.venvs/openstack/bin/openstack ~/.local/bin/openstack
```

Verify: `openstack --version`.

## Credentials — `clouds.yaml`

Location: `~/.config/openstack/clouds.yaml` (mode `600`).

Uses an **application credential** (scoped, revocable — created via
Horizon → Identity → Application Credentials), not the account password:

```yaml
clouds:
  openstack:
    auth_type: v3applicationcredential
    auth:
      auth_url: https://keystone.sjc-stack.pdsjc.f5net.com/v3
      application_credential_id: "<id>"
      application_credential_secret: "<secret>"
    region_name: "RegionOne"
    interface: "public"
    identity_api_version: 3
    # No F5-internal CA bundle provisioned in this sandbox; TLS verification
    # disabled per explicit user decision (internal network, no CA available here).
    verify: false
```

Notes:
- Horizon (`https://horizon.sjc-stack.pdsjc.f5net.com/project/`) is only
  the web dashboard — it is *not* the API endpoint. The actual Keystone
  identity API is `https://keystone.sjc-stack.pdsjc.f5net.com/v3`
  (discovered by GETting the bare host, which returns the version
  document).
- `verify: false` is required here because the Keystone cert is issued by
  an internal CA (`F5 F5NET Issuing CA`, under `DC=com,DC=F5Net`) that
  isn't in this sandbox's trust store. This disables TLS verification —
  acceptable only because this is an internal, trusted network; do not
  carry this setting to an untrusted network without re-evaluating.
- Select the cloud for every command via `export OS_CLOUD=openstack`, or
  pass `--os-cloud openstack` explicitly.

## Read-only exploration commands

```bash
export OS_CLOUD=openstack

# Confirm auth works at all
openstack token issue

# Images
openstack image list -f value -c Name -c Status
openstack image show <name-or-id>              # human table
openstack image show <name-or-id> -f json       # full JSON incl. properties

# Flavors (instance sizes)
openstack flavor list -f value -c Name -c VCPUs -c RAM

# Networks
openstack network list -f json                          # names + IDs
openstack network show <name> -f json                   # shared/port_security_enabled/description etc.

# Resolve a project ID to a name (useful for image `owner` fields)
openstack project show <project-id> -f value -c name -c description
```

## Picking a BIG-IP image

`openstack image list` returns every TMOS release uploaded to this stack
(15.1.x through 21.1.x, plus `tmos-tier2-*` engineering/nightly builds).
To find the current active release: list all `BIGIP-*` names, then for
the top few candidates compare `created_at`/`updated_at` via
`openstack image show <id> -f value -c name -c created_at -c updated_at`
— **name/version number is not enough on its own**, since e.g.
`BIGIP-tmos-tier2-*` builds have their own much-higher internal build
counters (`0.0.1804`) that don't compare against release build numbers
(`0.0.26`) on the same scale. Cross-checking both version number and
upload timestamp agreed on **`BIGIP-21.1.0.1` (build `0.0.26`)** as the
current active release as of 2026-07-17.

Gotcha: more than one image can share the exact same name (two entries
both named `BIGIP-21.1.0.1-0.0.26`, same size/timestamp — presumably a
duplicate upload or sync artifact). `openstack server create --image
<name>` fails with "More than one Image exists with the name ..." in
that case — resolve the specific image ID first via `openstack image
list -f json` and use `--image <id>`.

## Networks available (this project)

| Network | port_security_enabled | Purpose (from description / inference) |
|---|---|---|
| `AdminNetwork` | `False` | "Main instance mgmt network" — used for mgmt/control plane |
| `AllTestVLANs` | `False` | General-purpose test network — used for dataplane traffic |
| `QuarantineNetwork` | — | "Test traffic out to Internet only" (egress-only) |
| `PerforceAccessNet` | — | Perforce (source control) access, not relevant here |
| `k8s-ext` | — | Tied to the separate OCP cluster, not this project |
| `public` | — | General internet-routable network |

**Important gotcha:** both `AdminNetwork` and `AllTestVLANs` have
`port_security_enabled: False` — Neutron will refuse to attach *any*
security group (even the empty `default` one) to a port on these
networks, and `openstack server create --security-group <x>` (or the
implicit default) will fail scheduling with:

```
Exceeded maximum number of retries. ... Last exception: Network requires
port_security_enabled and subnet associated in order to apply security
groups.
```

Fix: pass `--no-security-group` explicitly. This is actually correct for
a device like BIG-IP that needs raw L2/L3 visibility on its dataplane
NICs rather than Neutron filtering it.

## Launching an instance (BIG-IP VE example)

```bash
export OS_CLOUD=openstack

# One-time: SSH keypair. ~/.ssh is a read-only mount in this sandbox
# (holds the github deploy key) — store OpenStack keys elsewhere.
mkdir -p ~/.config/openstack/keys
openstack keypair create eob-bigip > ~/.config/openstack/keys/eob-bigip.pem
chmod 600 ~/.config/openstack/keys/eob-bigip.pem

# Launch — two NICs (mgmt + dataplane), no security group (see gotcha above)
openstack server create \
  --flavor F5-BIGIP-small \
  --image <specific-image-id> \
  --nic net-id=AdminNetwork \
  --nic net-id=AllTestVLANs \
  --no-security-group \
  --key-name eob-bigip \
  bigip-ve-test

# Poll status
openstack server show bigip-ve-test -f value -c status

# If it lands in ERROR, get the reason:
openstack server show bigip-ve-test -f json | python3 -c \
  "import json,sys; print(json.load(sys.stdin)['fault'])"

# Console access (BIG-IP VE onboarding/default creds happen here, not
# necessarily via the SSH keypair — TMOS has its own first-boot flow):
openstack console log show bigip-ve-test
openstack console url show bigip-ve-test

# Cleanup
openstack server delete bigip-ve-test
```

Notes:
- `openstack server create` returns an `adminPass` field (Nova's
  generated guest password) — whether TMOS actually consumes this
  depends on whether the image supports Nova's password-injection
  mechanism; BIG-IP VE conventionally uses its own default credentials
  (`root`/`default` via console, `admin`/`admin` for the GUI) until
  reset. Confirm via the console log rather than assuming either works.
- Flavors seen in this project purpose-built for BIG-IP:
  `F5-BIGIP-small` (4096MB/2vCPU), `-medium` (8192MB/2vCPU), `-large`
  (16384MB/4vCPU), `-xlarge` (32768MB/8vCPU).
- This project (`starin`) started with **zero** existing keypairs,
  security groups (beyond empty `default`), or servers — nothing to
  reuse, everything below was created from scratch.

## Two-NIC default route — read before launching with `PerforceAccessNet`

The launch recipe above attaches two NICs. Both `AdminNetwork` and
`PerforceAccessNet` run DHCP and both offer a gateway, so the instance boots with
**two default-route candidates** and the winner is not something to leave to NIC
ordering. Perforce (`192.168.13.205`) is **not** on the `PerforceAccessNet` subnet
and that subnet pushes **no** `host_routes`, so if the default route goes out the
management NIC, `p4` fails with a timeout that looks like a firewall and is not.

Set it explicitly — make `PerforceAccessNet` the default route, or add a static
route for the Perforce prefix via that subnet's gateway (`10.197.75.254` on sjc,
`10.145.163.254` on sea). See
[`tmm-build-environment.md`](tmm-build-environment.md#what-perforceaccessnet-actually-is--inspected-2026-08-11)
for the subnets and the DNS consequence, which is the less obvious half.

## Security groups

Only needed for networks where `port_security_enabled: True` (i.e. not
`AdminNetwork`/`AllTestVLANs` — see above).

```bash
openstack security group create eob-bigip --description "..."
openstack security group rule create eob-bigip --protocol tcp --dst-port 22 --ingress --remote-ip 0.0.0.0/0
openstack security group rule create eob-bigip --protocol tcp --dst-port 443 --ingress --remote-ip 0.0.0.0/0
openstack security group rule create eob-bigip --protocol icmp --ingress --remote-ip 0.0.0.0/0
```

## Still to do / not yet used

- `openstack server ssh`-equivalent — actually confirming SSH/console
  login works and what the real first-boot credentials are.
- Client/server test VM creation (generic Linux images, on
  `AllTestVLANs`) to generate continuous traffic through the proxy.
- BIG-IP `tmsh`/iControl REST commands for actual dataplane config
  (self-IP, virtual server, pool) — these run *on* the instance, not via
  the OpenStack CLI, so they'll get their own reference once we're in.
