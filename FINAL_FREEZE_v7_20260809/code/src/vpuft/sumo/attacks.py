from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from hashlib import sha256
from pathlib import Path
from typing import Any

from ..domain import AttackType, MobilitySnapshot, V2XMessage


@dataclass(frozen=True)
class AttackSchedule:
    vehicle_id: str
    attack_type: AttackType
    start: float
    end: float
    parameters: dict[str, Any] = field(default_factory=dict)

    def active(self, now: float) -> bool:
        return self.start <= now <= self.end


def load_attack_schedules(path: str | Path) -> list[AttackSchedule]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    schedules = []
    for item in raw:
        item = dict(item)
        vehicle_id = item.pop("vehicle_id")
        attack_type = AttackType(item.pop("attack_type"))
        start = float(item.pop("start"))
        end = float(item.pop("end"))
        schedules.append(AttackSchedule(vehicle_id, attack_type, start, end, item))
    return schedules


def _digest(text: str) -> str:
    return sha256(text.encode("utf-8")).hexdigest()


class AttackInjector:
    def __init__(self, seed: int, schedules: list[AttackSchedule], scenario_id: str = "scenario") -> None:
        self.seed = seed
        self.scenario_id = scenario_id
        self.by_vehicle = {schedule.vehicle_id: schedule for schedule in schedules}
        self.history: dict[str, list[V2XMessage]] = {}
        self.counter: dict[str, int] = {}

    def schedule_for(self, vehicle_id: str, now: float) -> AttackSchedule | None:
        schedule = self.by_vehicle.get(vehicle_id)
        return schedule if schedule and schedule.active(now) else None

    def _case_id(self, vehicle_id: str, schedule: AttackSchedule | None) -> str:
        # Transport/message stream identity is deliberately independent of the
        # injected attack label and schedule boundaries. Ground truth remains in
        # the attack schedule/evaluation outputs only.
        return f"stream-{self.scenario_id}-{self.seed}-{vehicle_id}"

    def _base_message(self, snapshot: MobilitySnapshot, now: float, schedule: AttackSchedule | None) -> V2XMessage:
        index = self.counter.get(snapshot.vehicle_id, 0)
        self.counter[snapshot.vehicle_id] = index + 1
        attack_type = schedule.attack_type if schedule else AttackType.BENIGN
        case_id = self._case_id(snapshot.vehicle_id, schedule)
        original_id = f"cam-{self.seed}-{snapshot.vehicle_id}-{index:06d}"
        root = f"root-{_digest(original_id)[:24]}"
        pseudonym = f"ps-{_digest(f'{self.seed}|{snapshot.vehicle_id}')[:16]}"
        return V2XMessage(
            message_id=original_id,
            original_message_id=original_id,
            case_id=case_id,
            observation_root_id=root,
            seed=self.seed,
            sender_vehicle_id=snapshot.vehicle_id,
            pseudonym=pseudonym,
            message_type="CAM",
            generated_at=now,
            true_x=snapshot.x,
            true_y=snapshot.y,
            true_speed_mps=snapshot.speed_mps,
            true_acceleration_mps2=snapshot.acceleration_mps2,
            reported_x=snapshot.x,
            reported_y=snapshot.y,
            reported_speed_mps=snapshot.speed_mps,
            reported_acceleration_mps2=snapshot.acceleration_mps2,
            nonce=f"nonce-{_digest(original_id)[:20]}",
            certificate_valid=True,
            denm_claimed=False,
            attack_type=attack_type,
            ground_truth_malicious=schedule is not None,
            payload={
                "lane_id": snapshot.lane_id,
                "road_id": snapshot.road_id,
                "case_opened_at": schedule.start if schedule else now,
                "attack_ended_at": schedule.end if schedule else now,
            },
        )

    def generate(self, snapshot: MobilitySnapshot, now: float) -> list[V2XMessage]:
        schedule = self.schedule_for(snapshot.vehicle_id, now)
        base = self._base_message(snapshot, now, schedule)
        if schedule is None:
            messages = [base]
        elif schedule.attack_type == AttackType.POSITION_OFFSET:
            offset = float(schedule.parameters.get("position_offset_m", 50.0))
            messages = [replace(base, reported_x=base.true_x + offset, reported_y=base.true_y + offset * 0.25)]
        elif schedule.attack_type == AttackType.SPEED_OFFSET:
            offset = float(schedule.parameters.get("speed_offset_mps", 8.0))
            messages = [replace(base, reported_speed_mps=max(0.0, base.true_speed_mps + offset))]
        elif schedule.attack_type == AttackType.CERTIFICATE_TAMPER:
            messages = [replace(base, certificate_valid=False)]
        elif schedule.attack_type == AttackType.FALSE_DENM:
            period = max(1.0, float(schedule.parameters.get("denm_period_seconds", 5.0)))
            claimed = int(now - schedule.start) % max(1, int(period)) == 0
            messages = [replace(base, message_type="DENM" if claimed else "CAM", denm_claimed=claimed)]
        elif schedule.attack_type == AttackType.REPLAY:
            delay = max(1, int(schedule.parameters.get("replay_delay_steps", 3)))
            history = self.history.get(snapshot.vehicle_id, [])
            if len(history) >= delay:
                old = history[-delay]
                replay_id = f"replay-{base.message_id}"
                messages = [replace(
                    old,
                    message_id=replay_id,
                    case_id=base.case_id,
                    attack_type=AttackType.REPLAY,
                    ground_truth_malicious=True,
                    retransmission_index=old.retransmission_index + 1,
                )]
            else:
                messages = [base]
        elif schedule.attack_type == AttackType.FLOOD:
            count = max(2, int(schedule.parameters.get("messages_per_step", 5)))
            messages = [replace(base, message_id=f"{base.message_id}-f{i}", retransmission_index=i) for i in range(count)]
        elif schedule.attack_type == AttackType.MIXED:
            count = max(2, int(schedule.parameters.get("messages_per_step", 4)))
            position_offset = float(schedule.parameters.get("position_offset_m", 40.0))
            speed_offset = float(schedule.parameters.get("speed_offset_mps", 7.0))
            mixed = replace(
                base,
                reported_x=base.true_x + position_offset,
                reported_y=base.true_y + position_offset * 0.2,
                reported_speed_mps=base.true_speed_mps + speed_offset,
                denm_claimed=True,
                message_type="DENM",
            )
            messages = [replace(mixed, message_id=f"{base.message_id}-m{i}", retransmission_index=i) for i in range(count)]
        else:
            messages = [base]
        self.history.setdefault(snapshot.vehicle_id, []).extend(messages)
        self.history[snapshot.vehicle_id] = self.history[snapshot.vehicle_id][-20:]
        return messages
