"""Read-only inventory under one exact ordinary-work drain; no cleanup authority."""
from dataclasses import asdict, dataclass, field
import hashlib
import json

from proofpack.evidence.inventory import InventoryLimits, InventoryPass, InventoryReadSet, InventoryHeld, collect, reconcile
from proofpack.evidence.privacy_admission import PersistentAdmission, DrainProof, AdmissionHeld
from proofpack.evidence.repository import StoreConflict, StoreUnavailable
from proofpack.runtime.ownership import ResourceOwner


MAXIMUM = 2**63-1


class HeldInventoryHeld(RuntimeError):
    pass


@dataclass(frozen=True)
class HeldInventoryLimits:
    inventory: InventoryLimits
    max_snapshot_batches: int
    max_payload_bytes: int

    def __post_init__(self):
        if (type(self.inventory) is not InventoryLimits or any(type(value) is not int
                or not 1 <= value <= MAXIMUM for value in (self.max_snapshot_batches,self.max_payload_bytes))):
            raise ValueError('explicit typed inventory and private snapshot/payload bounds required')


@dataclass(frozen=True)
class HeldInventory:
    proof: DrainProof
    inventory: InventoryPass
    read_set: InventoryReadSet = field(repr=False)
    binding_sha256: str


def _binding(proof, inventory):
    value = {'schema_version':1,'proof':asdict(proof),'deployment':inventory.deployment,
        'tables':inventory.tables,'inventory_sha256':inventory.summary_sha256,
        'summary_bytes':inventory.summary_bytes}
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()


class HeldInventoryReader:
    def __init__(self, admission, resource_owner, *, limits, tick):
        if (type(admission) is not PersistentAdmission or type(resource_owner) is not ResourceOwner
                or type(limits) is not HeldInventoryLimits or not callable(tick)):
            raise ValueError('exact admission, shared resource owner, finite limits and trusted clock required')
        self.admission = admission
        self.resource_owner = resource_owner
        self.limits = limits
        self.tick = tick
        self.release_pending = False

    def read(self, *, request_id, scope_sha256, deadline_ns):
        if type(deadline_ns) is not int or not 1 <= deadline_ns <= MAXIMUM:
            raise ValueError('original positive absolute inventory deadline required')
        if self.release_pending:
            raise HeldInventoryHeld('prior control read completion remains unconfirmed')
        admission = self.admission; owner = self.resource_owner; limits = self.limits; tick = self.tick
        ticket = None; uncertain = False; last_tick = -1
        def checked_tick():
            nonlocal last_tick
            now = tick()
            if (type(now) is not int or not 0 <= now < deadline_ns or now < last_tick):
                raise HeldInventoryHeld('original inventory deadline or monotonic clock invalid')
            last_tick = now
            return now
        try:
            ticket = owner.acquire()  # Before the first coordinator/SDK read.
            proof = admission.drained(request_id=request_id,scope_sha256=scope_sha256)
            repository = admission.repository
            def checkpoint():
                if (self.admission is not admission or self.resource_owner is not owner
                        or self.limits is not limits or self.tick is not tick):
                    raise HeldInventoryHeld('control read configuration changed')
                admission.assert_drained(proof)
                checked_tick()
                admission.assert_drained(proof)
            checkpoint()
            inventory = collect(repository,limits=limits.inventory,deadline_ns=deadline_ns,
                checkpoint=checkpoint,tick=checked_tick)
            controls = {entry.key:entry for entry in inventory.entries}
            for reference in (proof.gate,proof.registry,proof.runtime):
                entry = controls.get(reference.key)
                if (entry is None or entry.kind != 'live' or entry.revision != reference.revision
                        or entry.payload_sha256 != reference.sha256):
                    raise HeldInventoryHeld('enumerated control does not match the original drain proof')
            private = reconcile(repository,inventory,limits=limits.inventory,
                max_snapshot_batches=limits.max_snapshot_batches,max_payload_bytes=limits.max_payload_bytes,
                deadline_ns=deadline_ns,checkpoint=checkpoint,tick=checked_tick)
            digest = _binding(proof,inventory)
            checkpoint()
            return HeldInventory(proof,inventory,private,digest)
        except (AdmissionHeld,InventoryHeld,StoreConflict,StoreUnavailable):
            raise HeldInventoryHeld('exact held inventory is unavailable') from None
        except BaseException as error:
            if not isinstance(error,Exception):
                uncertain = True
                self.release_pending = True
            raise
        finally:
            if ticket is not None and not uncertain:
                try:
                    owner.release(ticket)
                except BaseException:
                    self.release_pending = True
                    raise
