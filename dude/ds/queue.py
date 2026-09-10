import random
from typing import NamedTuple

from ..session import Record, Session
from ..store.ops import Transaction
from .plaintext_map import PlaintextMap


class Claim(NamedTuple):
    job_id: bytes
    payload: bytes
    worker: bytes
    deadline: int


def _lease_key(deadline: int, job_id: bytes) -> bytes:
    return b"%016d/%b" % (deadline, job_id)


def _parse_lease_key(key: bytes) -> tuple[int, bytes]:
    deadline_bytes, job_id = key.split(b"/", 1)
    return int(deadline_bytes), job_id


class Queue:
    __slots__ = ("_prefix", "_session", "lease", "pending")

    def __init__(self, prefix: bytes, session: Session) -> None:
        self._prefix = prefix
        self._session = session
        self.pending = PlaintextMap(prefix + b"pending/", session)
        self.lease = PlaintextMap(prefix + b"lease/", session)

    def active_map(self, worker: bytes) -> PlaintextMap:
        return PlaintextMap(self._prefix + b"active/" + worker + b"/", self._session)

    def pending_count(self) -> int:
        return self.pending.count()

    def active_count(self, worker: bytes) -> int:
        return self.active_map(worker).count()

    def submit(self, job_id: bytes, payload: bytes) -> Transaction:
        return self.pending.tx_put(job_id, payload, absent=True)

    def _claim_job(
        self, worker: bytes, deadline: int, job_id: bytes, payload: bytes, rec: Record
    ) -> tuple[Claim, Transaction]:
        active = self.active_map(worker)
        tx = (
            self.pending.tx_delete(job_id, expect=rec)
            + active.tx_put(job_id, payload, absent=True)
            + self.lease.tx_put(_lease_key(deadline, job_id), worker, absent=True)
        )
        return Claim(job_id, payload, worker, deadline), tx

    def claim(
        self, worker: bytes, deadline: int, *, index: int = 0
    ) -> tuple[Claim, Transaction] | None:
        result = self.pending.nth(index)
        if result is None:
            return None
        job_id, rec = result
        return self._claim_job(worker, deadline, job_id, rec.value, rec)

    def claim_job(
        self, worker: bytes, deadline: int, job_id: bytes
    ) -> tuple[Claim, Transaction] | None:
        rec = self.pending.get(job_id)
        if rec.absent:
            return None
        return self._claim_job(worker, deadline, job_id, rec.value, rec)

    def claim_random(self, worker: bytes, deadline: int) -> tuple[Claim, Transaction] | None:
        n = self.pending.count()
        if n == 0:
            return None
        return self.claim(worker, deadline, index=random.randrange(n))

    def complete(self, claim: Claim) -> Transaction:
        active = self.active_map(claim.worker)
        rec = active.get(claim.job_id)
        lk = _lease_key(claim.deadline, claim.job_id)
        lease_rec = self.lease.get(lk)
        return active.tx_delete(claim.job_id, expect=rec) + self.lease.tx_delete(
            lk, expect=lease_rec
        )

    def renew_lease(self, claim: Claim, new_deadline: int) -> tuple[Claim, Transaction]:
        old_lk = _lease_key(claim.deadline, claim.job_id)
        old_rec = self.lease.get(old_lk)
        tx = self.lease.tx_delete(old_lk, expect=old_rec) + self.lease.tx_put(
            _lease_key(new_deadline, claim.job_id), claim.worker, absent=True
        )
        return claim._replace(deadline=new_deadline), tx

    def reclaim_expired(self, now: int, *, limit: int = 1) -> tuple[list[bytes], Transaction]:
        tx = Transaction(())
        ejected: list[bytes] = []
        for i in range(self.lease.count()):
            if len(ejected) >= limit:
                break
            result = self.lease.nth(i)
            if result is None:
                break
            key, lease_rec = result
            deadline, job_id = _parse_lease_key(key)
            if deadline > now:
                break
            worker = lease_rec.value
            active = self.active_map(worker)
            active_rec = active.get(job_id)
            tx = (
                tx
                + self.lease.tx_delete(key, expect=lease_rec)
                + active.tx_delete(job_id, expect=active_rec)
                + self.pending.tx_put(job_id, active_rec.value)
            )
            ejected.append(job_id)
        return ejected, tx
