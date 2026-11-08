"""Wiring of the service objects on top of a :class:`~ironmesh_ota.container.Container`."""

from __future__ import annotations

from dataclasses import dataclass

from .container import Container
from .controller import RolloutController
from .ingest import StatusIngestor
from .services.campaigns import CampaignService
from .services.firmware import FirmwareService
from .services.rollout import Rollout


@dataclass
class ServiceBundle:
    container: Container
    firmware: FirmwareService
    rollout: Rollout
    campaigns: CampaignService
    ingestor: StatusIngestor
    controller: RolloutController

    @classmethod
    def build(cls, container: Container) -> ServiceBundle:
        firmware = FirmwareService(container)
        rollout = Rollout(container, firmware)
        return cls(
            container=container,
            firmware=firmware,
            rollout=rollout,
            campaigns=CampaignService(container, firmware, rollout),
            ingestor=StatusIngestor(container, rollout),
            controller=RolloutController(container, rollout),
        )
