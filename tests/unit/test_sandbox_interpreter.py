"""Bounded AST-language tests use hand-calculated results and attack twins."""

import json
from fractions import Fraction

import pytest

from corridor.gateway.sandbox_interpreter import SandboxError, evaluate, validate_program

DATASET = [
    {
        "tx_id": "TX1",
        "category": "dining",
        "amount": "10/1",
        "net_amount": "10/1",
        "booked_at": "2026-10-16T02:00:00Z",
        "day_of_week": 4,
        "is_weekend": False,
    },
    {
        "tx_id": "TX2",
        "category": "dining",
        "amount": "7/1",
        "net_amount": "7/1",
        "booked_at": "2026-10-17T02:00:00Z",
        "day_of_week": 5,
        "is_weekend": True,
    },
    {
        "tx_id": "TX3",
        "category": "dining",
        "amount": "2/1",
        "net_amount": "-2/1",
        "booked_at": "2026-10-18T02:00:00Z",
        "day_of_week": 6,
        "is_weekend": True,
    },
    {
        "tx_id": "TX4",
        "category": "transport",
        "amount": "3/1",
        "net_amount": "3/1",
        "booked_at": "2026-10-17T02:00:00Z",
        "day_of_week": 5,
        "is_weekend": True,
    },
]


def test_weekday_weekend_dining_net_matches_hand_calculation():
    program = """result = {
        'weekday': sum_money(filter_rows(
            filter_rows(dataset, 'category', '==', 'dining'), 'is_weekend', '==', False)),
        'weekend': sum_money(filter_rows(
            filter_rows(dataset, 'category', '==', 'dining'), 'is_weekend', '==', True))
    }"""
    assert evaluate(program, DATASET) == {"weekday": "10/1", "weekend": "5/1"}


def test_category_groups_counts_and_exact_rational_arithmetic():
    assert evaluate(
        "{'groups': group_sum(dataset, 'category'), 'count': count(dataset)}", DATASET
    ) == {"groups": {"dining": "15/1", "transport": "3/1"}, "count": "4/1"}
    assert evaluate(
        "result={'third':1/3,'value':(1/3+1/7)*21,'difference':sum_money(dataset)-20,'day':day_of_week('2026-10-16T16:00:00Z')}",
        DATASET,
    ) == {"third": "1/3", "value": "10/1", "difference": "-2/1", "day": "5/1"}


def test_empty_inputs_and_filtered_sets_have_exact_zero():
    assert evaluate(
        "{'sum':sum_money(dataset),'count':count(dataset),'groups':group_sum(dataset,'category')}",
        [],
    ) == {"sum": "0/1", "count": "0/1", "groups": {}}
    assert evaluate(
        "{'sum':sum_money(filter_rows(dataset,'category','==','missing'))}", DATASET
    ) == {"sum": "0/1"}


def test_select_fields_subscripts_comparisons_and_numeric_helpers_are_closed():
    assert evaluate(
        "{'value':sum_money(select_fields(dataset,['net_amount'])),'first':sum_money([dataset[0]]),'days':day_of_week('2026-10-18')}",
        DATASET,
    ) == {"value": "18/1", "first": "10/1", "days": "6/1"}
    assert evaluate(
        "{'count':count(filter_rows(dataset,'day_of_week','in',[5,6])),'value':(2+3)*4/2}", DATASET
    ) == {"count": "3/1", "value": "10/1"}
    validate_program("result={'ok':count(dataset)}")


@pytest.mark.parametrize(
    "program",
    [
        "import os",
        "from os import environ",
        "while True: pass",
        "for x in dataset: pass",
        "{'x': open('probe','w')}",
        "{'x': socket()}",
        "{'x': os.getenv('KEY')}",
        "{'x': subprocess.run('x')}",
        "{'x': getattr(dataset,'x')}",
        "{'x': dataset.__class__}",
        "{'x': (lambda: 1)()}",
        "{'x': [x for x in dataset]}",
        "{'x': (count if True else sum_money)(dataset)}",
        "{'x': globals()}",
        "{'x': __import__('os')}",
        "{'x': eval('1')}",
        "{'x': compile('1','','eval')}",
        "{'x': 2**10}",
        "{'x': dataset[0:1]}",
        "result={}; result={'x':1}",
        "x={'a':1}",
        "result=other={'a':1}",
        "{'x':count(*[dataset])}",
        "{'x':sum_money(dataset, field='net_amount')}",
    ],
)
def test_all_nonwhitelisted_language_capabilities_are_rejected(program):
    with pytest.raises(SandboxError) as caught:
        evaluate(program, DATASET)
    assert caught.value.rule == "SBX-SYNTAX"


@pytest.mark.parametrize(
    "program",
    [
        "{'x':'/tmp/file'}",
        "{'x':'C:\\\\secret.txt'}",
        "{'x':'../secret'}",
        "{'x':'.env'}",
        "{'x':dataset[0]['tx_id']}",
        "{'PII_SECRET':1}",
        "{'__class__':1}",
        "{'12345678901':1}",
        "{'x':'do a transfer'}",
        "{'x':True}",
        "1/3",
    ],
)
def test_paths_tokens_arbitrary_prose_and_nonmapping_outputs_cannot_escape(program):
    with pytest.raises(SandboxError):
        evaluate(program, DATASET)


def test_zero_division_is_controlled():
    with pytest.raises(SandboxError) as caught:
        evaluate("{'x':1/0}", [])
    assert caught.value.rule == "SBX-SYNTAX" and caught.value.reason == "division_by_zero"


def test_numeric_bit_budget_accepts_boundary_and_rejects_overflow():
    largest = (1 << 128) - 1
    assert evaluate("{'value':" + str(largest) + "}", []) == {"value": str(largest) + "/1"}
    for program in (
        "{'value':" + str(1 << 128) + "}",
        "{'value':" + str(largest) + "+1}",
        "{'value':" + str(largest) + "*2}",
        "{'value':1/(" + str(largest) + "*2)}",
    ):
        with pytest.raises(SandboxError) as caught:
            evaluate(program, [])
        assert caught.value.rule == "SBX-LIMIT"


@pytest.mark.parametrize(
    "program", ["{'x':'a'*1000000}", "{'x':[1]*1000000}", "{'x':(1,)*1000000}"]
)
def test_sequence_amplification_is_never_allocated(program):
    with pytest.raises(SandboxError):
        evaluate(program, [])


def test_code_ast_depth_and_string_limits():
    programs = [
        " " * 8193 + "{'x':1}",
        "{'x':[" + ",".join("1" for _ in range(260)) + "]}",
        "{'x':" + "[" * 22 + "1" + "]" * 22 + "}",
        "{'x':'" + "a" * 257 + "'}",
    ]
    for program in programs:
        with pytest.raises(SandboxError) as caught:
            evaluate(program, [])
        assert caught.value.rule == "SBX-LIMIT"


def test_dataset_rows_float_path_unknown_field_and_input_budget():
    for rows in (
        [{}] * 1001,
        [{"amount": 1.1}],
        [{"memo": "untrusted"}],
        [{"tx_id": "/tmp/secret"}],
    ):
        with pytest.raises(SandboxError):
            evaluate("{'count':count(dataset)}", rows)
    oversized = [
        {"category": "a" * 256, "merchant_ref": "b" * 256, "tx_id": "c" * 256, "net_amount": "1/1"}
        for _ in range(1000)
    ]
    with pytest.raises(SandboxError) as caught:
        evaluate("{'count':count(dataset)}", oversized)
    assert caught.value.rule == "SBX-LIMIT"


def test_output_scalar_and_byte_limits_apply_to_nested_results():
    rows = [{"category": "A" + str(i), "net_amount": "1/1"} for i in range(1000)]
    assert len(evaluate("{'values':group_sum(dataset,'category')}", rows)["values"]) == 1000
    with pytest.raises(SandboxError) as caught:
        evaluate("{'values':group_sum(dataset,'category'),'extra':1}", rows)
    assert caught.value.rule == "SBX-LIMIT"
    rows = [{"category": "A" * 60 + str(i), "net_amount": "1/1"} for i in range(500)]
    with pytest.raises(SandboxError) as caught:
        evaluate("{'values':group_sum(dataset,'category')}", rows)
    assert caught.value.rule == "SBX-LIMIT"


def test_step_budget_limits_nested_filters_on_large_dataset():
    rows = [{"net_amount": "1/1", "category": "dining"} for _ in range(1000)]
    expression = "dataset"
    for _ in range(13):
        expression = "filter_rows(" + expression + ",'category','==','dining')"
    with pytest.raises(SandboxError) as caught:
        evaluate("{'sum':sum_money(" + expression + ")}", rows)
    assert caught.value.rule == "SBX-LIMIT"
    assert caught.value.reason == "steps"


def test_output_uses_only_canonical_fraction_strings():
    result = evaluate("{'list':[1,2/4,-3],'nested':{'zero':0}}", [])
    assert result == {"list": ["1/1", "1/2", "-3/1"], "nested": {"zero": "0/1"}}
    assert json.loads(json.dumps(result)) == result
    assert Fraction(result["list"][1]) == Fraction(1, 2)


@pytest.mark.parametrize(
    "program",
    [
        "{'count':count(filter_rows(dataset,'unknown','==',1))}",
        "{'count':count(filter_rows(dataset,'amount','in',1))}",
    ],
)
def test_empty_rows_do_not_skip_fixed_helper_argument_validation(program):
    with pytest.raises(SandboxError) as caught:
        evaluate(program, [])
    assert caught.value.rule == "SBX-SYNTAX"


def test_standalone_worker_protocol_is_exact_bounded_json():
    import subprocess
    import sys
    from pathlib import Path

    from corridor.gateway import sandbox_interpreter

    path = Path(sandbox_interpreter.__file__).resolve()
    for payload, expected in (
        (
            {"program": "{'third':1/3,'count':count(dataset)}", "dataset": []},
            {"status": "ok", "results": {"third": "1/3", "count": "0/1"}},
        ),
        ({"program": "import os", "dataset": []}, None),
    ):
        result = subprocess.run(
            [sys.executable, "-I", str(path)],
            input=json.dumps(payload).encode("utf-8"),
            capture_output=True,
            timeout=3,
            check=True,
        )
        output = json.loads(result.stdout)
        assert result.stderr == b""
        if expected is not None:
            assert output == expected
        else:
            assert set(output) == {"status", "rule", "reason"}
            assert output["status"] == "rejected" and output["rule"] == "SBX-SYNTAX"


@pytest.mark.parametrize(
    "payload",
    [
        b'{"program":"{}","dataset":[{"amount":1.5}]}',
        b'{"program":"{}","program":"{}","dataset":[]}',
        b"[" * 2000 + b"]" * 2000,
        b" " * 280000,
    ],
    ids=["float", "duplicate", "deep", "oversized"],
)
def test_worker_malformed_float_duplicate_deep_and_oversized_input_is_controlled(payload):
    import subprocess
    import sys
    from pathlib import Path

    from corridor.gateway import sandbox_interpreter

    result = subprocess.run(
        [sys.executable, "-I", str(Path(sandbox_interpreter.__file__).resolve())],
        input=payload,
        capture_output=True,
        timeout=3,
        check=True,
    )
    output = json.loads(result.stdout)
    assert output["status"] == "rejected" and set(output) == {"status", "rule", "reason"}
    assert result.stderr == b""


def test_file_probe_is_unchanged_and_no_socket_capability_is_called(tmp_path, monkeypatch):
    import builtins
    import socket

    probe = tmp_path / "probe.txt"
    probe.write_text("unchanged", encoding="utf-8")
    attempted = []

    def forbidden(*args, **kwargs):
        attempted.append(True)
        raise AssertionError("Interpreter attempted an external capability")

    with monkeypatch.context() as patched:
        patched.setattr(builtins, "open", forbidden)
        patched.setattr(socket, "socket", forbidden)
        for program in (
            "{'x':open('probe.txt','w')}",
            "{'x':socket()}",
            "{'x':__import__('socket').socket()}",
        ):
            with pytest.raises(SandboxError):
                evaluate(program, [])
    assert attempted == []
    assert probe.read_text(encoding="utf-8") == "unchanged"
