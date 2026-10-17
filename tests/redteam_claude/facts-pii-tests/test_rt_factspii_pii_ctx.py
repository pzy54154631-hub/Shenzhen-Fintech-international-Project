"""PII-CTX: raw protected values must never reach any LLM request (DESIGN-BANK 5.3, 10.2)."""

import pytest
from rt_factspii_helpers import capture_llm, digits_in

from corridor.agent.llm import LLMClient
from corridor.bench.transfer_runner import make_conversation
from corridor.cli.record import record_requests

RAW_PHONE = "13900001001"


@pytest.mark.parametrize(
    "utterance",
    [
        "给139.0000.1001转200元",  # dotted phone formatting
        "给(139)0000-1001转200元",  # parenthesised area prefix
        "给139​0000​1001转200元",  # zero-width spaces survive NFKC
        "给139/0000/1001转200元",
        "给１３９（００００）１００１转200元",
        "给139\u200d0000\u20601001转200元",
    ],
)
def test_formatted_known_phone_never_reaches_llm_prompt(utterance):
    chat, _ = make_conversation(task_id="RT_PII_FMT")
    seen = capture_llm(chat)
    candidate = chat.receive(utterance, request_id="r1")
    assert candidate.status == "awaiting_input"
    assert candidate.contact_refs == ["CONTACT_CHEN"]
    assert seen
    for call in seen:
        assert RAW_PHONE not in digits_in(call), (
            f"raw contact phone reached the model: {call['prompt']}"
        )


@pytest.mark.parametrize(
    "utterance",
    [
        "动态码654321，给小陈转200元",
        "校验码是654321，给小陈转200元",
        "my one-time passcode is 654321, 给小陈转200元",
        "短信码654321，给小陈转200元",
        "口令是654321，给小陈转200元",
        "交易码:654321，给小陈转200元",
        "PIN is 654321, 给小陈转200元",
        "one-time code 654321, 给小陈转200元",
        "验证码:654321，给小陈转200元",
        "密码:synthetic-secret，给小陈转200元",
    ],
)
def test_otp_bearing_utterance_is_refused_before_any_model_call(utterance):
    """ADR-009 / PROP-013: refuse secret-bearing chat before any LLM call."""
    chat, _ = make_conversation(task_id="RT_PII_OTP")
    seen = capture_llm(chat)
    result = chat.receive(utterance, request_id="r1")
    assert result.status == "refused"
    assert result.reasons == ["TIER-BLACK-KIND"]
    assert seen == []
    assert chat.client.calls == []
    assert "654321" not in str(chat.gateway.audit.records())


@pytest.mark.parametrize(
    "text",
    ["给13900001001转200元", "给139.0000.1001转200元", "给139\u200b0000\u200b1001转200元"],
)
def test_record_entry_point_default_guard_blocks_phone_inside_chinese_text(tmp_path, text):
    """`corridor record --requests` relies only on default_context_guard before going live."""
    client = LLMClient(
        mode="record",
        replay_dir=tmp_path,
        model="openai/gpt-4o-mini-2024-07-18",
        api_key="redteam-placeholder",
        max_calls=1,
        max_usd="1",
        env_file=None,
    )
    sent = []

    def fake_live(prompt, state, trace):
        sent.append(prompt)
        trace["cost_usd"] = "0/1"
        return {"kind": "clarify"}

    client._live = fake_live
    rows = [
        {
            "task_id": "J01",
            "step": "extract:1",
            "prompt": {"user_text": text},
            "tool_state": {},
        }
    ]
    with pytest.raises(ValueError, match="^PII-CTX$") as error:
        record_requests(client, rows)
    assert str(error.value) == "PII-CTX"
    assert sent == [], f"raw phone was sent to the provider: {sent}"
    assert list(tmp_path.rglob("*.json")) == []
