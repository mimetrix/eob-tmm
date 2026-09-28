# Separate collector container

**2026-09-28 — MEASURED in the isolated one-worker fixture.** The reader, journal
writer and replay service now run in their own container. That container was
replaced after a normal stop and after SIGKILL. TMM forwarded a request during
each outage. Both queued values reached two separate test consumer containers.

The original IDEA gate was registered before the checks. Its text remains in
the build and live receipts. [Evidence and hashes](../../SOURCES.md#separate-collector-container-2026-09-28).

```text
BUILD / TEST CONTROLLER — off the traffic path
  Verify and sign probe -> program artifact
  Check TMM identity -> read-only source.json

TMM CONTAINER — traffic path
  Getter-return probe -> bounded method record -> shared ring
  No journal, API or collector code in this container

COLLECTOR CONTAINER — off the traffic path
  C reader -> copied record -> SQLite commit -> ring acknowledgement
  Journal -> bounded replay page -> Unix socket in API volume

CONSUMER A / CONSUMER B — separate containers
  Read-only API-volume mount -> HTTP request over Unix socket
  Each saves its own next_cursor; neither mounts the journal or ring
```

## Boundary

- Give the collector its own image, read-only root filesystem, CPU/memory/process
  limits and persistent journal volume. TMM mounts neither the journal nor the API.
- Share the existing ring volume with TMM. Keep commit-before-ACK unchanged.
- Keep direct source checks. Join only TMM's PID namespace, not the host namespace.
  Pin PID, start time, boot, namespace and executable hash in a read-only source
  file supplied by the test controller. The reader still checks the mapped inode.
- Drop capabilities except `SYS_PTRACE`, needed to inspect a privileged TMM's
  process identity/mappings. This is operational separation, not a strong security
  boundary: this capability grants process access. Removing it needs a different
  source-registration design and threat review; do not silently weaken checks.
  **Correction after attempt 01:** this capability alone is insufficient under
  Docker's default AppArmor profile. The pinned TMM is unconfined; the default
  collector profile denies access to its executable. The diagnostic passes with
  `apparmor=unconfined` and refuses a wrong start time. This test deployment now
  uses that setting, while retaining seccomp and no-new-privileges. A restricted
  AppArmor policy is still required for a stronger boundary. See the
  [retained failure and diagnostic](../../SOURCES.md#separate-collector-container-2026-09-28).
- Give consumers HTTP over a Unix socket in a separate API volume. No network
  listener, Docker socket, loader socket, certificates or signing keys in the collector.
- A small supervisor stops the other service if either writer or API exits.
  The container can restart independently. A stopped API must not look like a
  healthy source with no events.

## Pre-registered checks and falsifiers

1. Build a dedicated image from a digest-pinned Python runtime. Retain all source
   and executable hashes. Run the existing native collector gate and Unix API check.
2. Confirm separate container identities, mounts, resource limits and process
   placement. Refuse wrong source identity. Retain the result without `SYS_PTRACE`.
3. Compare exact live method values through the socket from the fixture container.
   Also run two test consumers in separate containers. Mount only the API volume
   there, read-only. Keep each consumer's cursor separate. The fixture has loader
   access for test control; these two consumers must not have it.
4. Stop the collector while TMM remains armed. Send a request during the stop.
   Confirm forwarding succeeds and no reader advances the ring. Restart only the
   collector. Read that value from the same journal/cursor, then send more traffic.
5. Kill the collector container once. Recreate it with the same journal volume.
   Both consumers must see the same records without duplicate event identities.
6. Check the same TMM process, binary, container and hook before/after collector
   replacement. Restore the hook; archive the journal and receipts before cleanup.

Falsifiers: a TMM restart caused by collector restart, missing/duplicate values,
wrong source accepted, consumer access to the journal or loader, collector code
running in the TMM container, hidden loss, or unbounded resource configuration.

This gate does not establish Kubernetes deployment, production throughput,
multiworker ownership, power-loss durability or a completed threat review.

## Measured result

- Native build 04 passes eleven checks. The added check covers Unix-socket replay,
  competing API ownership and recovery from a stale socket after process death.
- Image build 02 uses the resolved Python base digest recorded in its receipt.
  Collector image: `sha256:26f3184a4e3fe96b61f780761497933facc385f3d62d6f1cf66f04e56abd5054`.
- Docker reports a read-only root, 0.5 CPU limit, 128 MiB combined RAM/swap limit,
  32-process limit and 8 MiB temporary filesystem. The collector has no network.
  These are configured limits, not measured sustained capacity.
- Source validation refuses a wrong process start time. The reader also checks
  that the pinned TMM process maps the ring's exact file identity.
- Ten requests produce eight method records. Exact values and statuses match
  the [method cases](COLLECTOR.md#measured-result), including unfamiliar bytes,
  an empty value, escaped bytes, truncation and two status-only records.
- There are three successive collector container identities and one unchanged
  TMM container/process/binary. The hook witness records attachment and restoration.
- Both separate consumers receive the same ten journal events: one source boundary,
  one ring-health event and eight method records. Record identities and replay
  cursors are unique. No reported drops or new probe errors occur.

| Collector outage | Request sent during outage | Ring positions before replacement | Result after replacement |
|---|---|---|---|
| Normal stop | Empty method string | Producer 368 → 552; consumer stays 368 | Empty value recovered from the same journal |
| SIGKILL | Literal `future\u002evariant` | Producer 552 → 736; consumer stays 552 | Escaped bytes recovered from the same journal |

The fixture JSON and Tao report both pass. The journal passes its SQLite integrity
check. All 12 probe slots are inactive and the method hook is restored. The evidence
was archived before the project was removed. Other Docker identities and state
stayed unchanged. The image and build inputs remain on the build box.

**Failures retained:** attempt 01 exposed the AppArmor restriction. Attempt 02
expected `SYS_PTRACE` in Docker's report; Docker uses `CAP_SYS_PTRACE`. Attempt 03
completed traffic and replacement, then the final report check expected `event_id`
on a source-boundary event. That event has `source_id`. The corrected check uses
cursor uniqueness for all events and `event_id` uniqueness for records.
Evidence-only recovery rechecked the saved consumers, journal, fixture reports and
kernel state. It sent no new traffic. The original failed receipt remains immutable.

Test controllers and comparisons are SELF witnesses. Process access, mapped file
identity and hook bytes use kernel observations. Docker supplies container identity
and resource settings. These tests do not prove complete observation history.

## Reproduce on the prepared build box

This procedure requires the existing pinned TMM/SSA fixture, signed method build 02,
and current collector sources staged under `/home/starin/eob-config-20260925`.
The repository alone does not supply that environment. Use a new name for each run.

```sh
ROOT=/home/starin/eob-config-20260925
python3 "$ROOT/collector_build.py" --output "$ROOT/collector-build-NEXT"
python3 "$ROOT/collector_image_build.py" \
  --native "$ROOT/collector-build-NEXT" --output "$ROOT/collector-image-NEXT"
```

Set `IMAGE` to the full image ID printed by the successful build. Create an empty
source-binding directory. The live controller writes the checked identity there.

```sh
mkdir "$ROOT/collector-source-NEXT"
python3 "$ROOT/lifetime_fixture.py" create \
  --collector-image "$IMAGE" --collector-source "$ROOT/collector-source-NEXT" \
  --output "$ROOT/collector-container-create-NEXT.json"
python3 "$ROOT/collector_container_live.py" \
  --run collector-container-live-NEXT \
  --image-build "$ROOT/collector-image-NEXT/image-build.json" \
  --source-dir "$ROOT/collector-source-NEXT" \
  --output "$ROOT/collector-container-live-NEXT.json"
```

After a successful result, archive and remove the isolated fixture:

```sh
python3 "$ROOT/lifetime_fixture.py" archive-cleanup \
  --collector-image "$IMAGE" --collector-source "$ROOT/collector-source-NEXT" \
  --output "$ROOT/collector-container-cleanup-NEXT.json" \
  --archive "$ROOT/collector-container-evidence-NEXT.tar.gz" \
  --live "$ROOT/collector-container-live-NEXT.json"
```

For a local check of the saved evidence, run
`python3 env/ai-traffic/collector_verify.py`. This checks both collector deployments
and their archived journals. It also reports that the live driver changed after
attempt 03; the final assertion was corrected without another traffic run.

## Consumer interface

Mount only the collector's API volume at `/api`, read-only. The socket is mode
0600; the measured test consumers run as root with all capabilities dropped.
They share neither TMM's PID namespace nor the collector's journal volume.

```python
from collector_client import page

batch = page("/api/events.sock", cursor=None)
cursor = batch["next_cursor"]
# Save this consumer's cursor after processing its events.
next_batch = page("/api/events.sock", cursor=cursor, wait_ms=10000)
```

Save progress outside the collector. Handle retention gaps as described in
[COLLECTOR.md](COLLECTOR.md). The test consumers are separate clients, not a
production analytics application. General user permissions, authenticated off-box
delivery, full health history and sustained load remain work to complete.
