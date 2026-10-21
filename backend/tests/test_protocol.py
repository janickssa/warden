from __future__ import annotations

import pytest

from warden.dispatch.protocol import ProtocolError, StepFinished, encode, parse_agent, parse_enroll


def test_parses_known_message() -> None:
    msg = parse_agent(
        '{"type":"step_finished","plan_id":"p","n":1,"exit_code":0,"timed_out":false,'
        '"killed":false,"refused":null,"duration_ms":5,"truncated":false}'
    )
    assert isinstance(msg, StepFinished)


@pytest.mark.parametrize(
    "frame",
    [
        '{"type":"hello","agent_version":"1","policy_version":1,"approve":true}',  # unknown field
        '{"type":"approve","plan_id":"p"}',  # unknown type
        '{"type":"output","plan_id":"p","n":1,"stream":"stdin","data":"","truncated":false}',
        "not json",
        b'{"type":"run_finished","plan_id":"p"}',  # binary frames refused
        '{"type":"heartbeat","agent_version":"1","policy_version":1,"disk_free_mb":1,"load1":-1}',
    ],
)
def test_refuses(frame: str | bytes) -> None:
    with pytest.raises(ProtocolError):
        parse_agent(frame)


def test_oversized_frame_refused() -> None:
    with pytest.raises(ProtocolError):
        parse_agent('{"type":"run_finished","plan_id":"' + "x" * (5 * 1024 * 1024) + '"}')


def test_enroll_strict() -> None:
    parse_enroll('{"type":"enroll","token":"t","public_key":"k","agent_version":"0.1.0"}')
    with pytest.raises(ProtocolError):
        parse_enroll('{"type":"enroll","token":"t","public_key":"k","agent_version":"0.1.0","x":1}')


def test_encode_adds_type() -> None:
    assert encode("kill", plan_id="p") == '{"type":"kill","plan_id":"p"}'
