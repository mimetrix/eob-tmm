"""Trusted-controller guard for a closed observation window, not gap detection."""
from correlation_join import join


class ObservationWindow:
    """A reported gap is permanent for this window. A new window starts closed."""

    def __init__(self, run, instances, *, fresh=False):
        self.run = run
        self.instances = dict(instances)
        self.reason = None
        self.changes = []
        self.closed = False
        if (
            fresh is not True
            or type(run) is not int
            or run <= 0
            or set(instances) != {"init", "parse", "fini", "candidate"}
            or any(not value for value in instances.values())
        ):
            self.invalidate("missing_fresh_window_evidence")

    def invalidate(self, reason):
        """Call before an attachment change; never clear this window's reason."""
        self.changes.append(reason)
        if self.reason is None:
            self.reason = reason

    def close(self, instances):
        """Seal once, with the same four program instances still installed."""
        if self.closed or instances != self.instances:
            self.invalidate("changed_window_identity")
        self.closed = True

    def match(self, lifetimes, candidates, ledger, accounting):
        """No provisional identities; refuse a gap, capacity or changed run."""
        if any(e["run"] != self.run for e in lifetimes + candidates):
            self.invalidate("changed_run_token")
        if any(e["kind"] == 1 and e["flags"] & 4 for e in lifetimes) or any(
            e["flags"] & 256 for e in candidates
        ):
            self.invalidate("tracking_capacity")
        result = join(lifetimes, candidates, ledger, accounting)
        reason = self.reason or (None if self.closed else "window_not_closed")
        if reason:
            for row in result:
                row.update(status="unknown", reason=reason, actor=None, operation=None)
                for key in ("authority_attempt", "originator", "parent"):
                    row.pop(key, None)
        return result
