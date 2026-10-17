"""Bounded Python-surface analysis language; user AST is interpreted, never executed.

This file intentionally imports only standard-library modules so an isolated
worker can launch it directly without loading the banking application.
"""

import ast
import json
import re
import sys
from datetime import date, datetime, timedelta
from fractions import Fraction
from typing import Any, cast

MAX_CODE_BYTES = 8 * 1024
MAX_AST_NODES = 256
MAX_DEPTH = 20
MAX_INPUT_BYTES = 256 * 1024
MAX_ROWS = 1000
MAX_STRING = 256
MAX_BITS = 128
MAX_STEPS = 100000
MAX_OUTPUT_BYTES = 32 * 1024
MAX_OUTPUT_SCALARS = 1000
MAX_WIRE_BYTES = MAX_INPUT_BYTES + MAX_CODE_BYTES + 1024

_FIELDS = frozenset({
    "tx_id",
    "merchant_ref",
    "category",
    "amount",
    "net_amount",
    "booked_at",
    "business_date",
    "day_of_week",
    "is_weekend",
})
_FUNCTIONS = frozenset({
    "filter_rows",
    "group_sum",
    "sum_money",
    "count",
    "day_of_week",
    "select_fields",
})
_RATIONAL = re.compile(r"-?(?:0|[1-9][0-9]*)(?:/[1-9][0-9]*|\.[0-9]+)?\Z")
_LABEL = re.compile(r"[A-Za-z0-9_]{1,64}\Z")
_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}\Z")
_ALLOWED = (
    ast.Module,
    ast.Expression,
    ast.Expr,
    ast.Assign,
    ast.Name,
    ast.Constant,
    ast.List,
    ast.Dict,
    ast.Tuple,
    ast.Subscript,
    ast.Compare,
    ast.BoolOp,
    ast.UnaryOp,
    ast.BinOp,
    ast.Call,
    ast.Load,
    ast.Store,
    ast.Add,
    ast.Sub,
    ast.Mult,
    ast.Div,
    ast.UAdd,
    ast.USub,
    ast.Not,
    ast.And,
    ast.Or,
    ast.Eq,
    ast.NotEq,
    ast.Lt,
    ast.LtE,
    ast.Gt,
    ast.GtE,
    ast.In,
    ast.NotIn,
)


class SandboxError(ValueError):
    def __init__(self, rule: str, reason: str) -> None:
        self.rule = rule
        self.reason = reason
        super().__init__(rule + ":" + reason)


def _syntax(reason: str) -> None:
    raise SandboxError("SBX-SYNTAX", reason)


def _limit(reason: str) -> None:
    raise SandboxError("SBX-LIMIT", reason)


def _integer(value: int) -> int:
    if abs(value).bit_length() > MAX_BITS:
        _limit("integer_bits")
    return value


def _text(value: str) -> str:
    if len(value) > MAX_STRING:
        _limit("string_length")
    if (
        not value.isascii()
        or any(ord(character) < 32 for character in value)
        or "__" in value
        or "\\" in value
        or ".." in value
        or value.lower() == ".env"
        or value.upper().startswith("PII_")
        or ("/" in value and _RATIONAL.fullmatch(value) is None)
        or (":" in value and _TIMESTAMP.fullmatch(value) is None)
    ):
        _syntax("forbidden_text")
    return value


def _label(value: str) -> str:
    if (
        _LABEL.fullmatch(value) is None
        or "__" in value
        or value.upper().startswith("PII_")
        or (value.isdigit() and len(value) >= 11)
    ):
        _syntax("output_key")
    return value


def _number(value: Any) -> Fraction:
    if isinstance(value, bool):
        _syntax("numeric_operand")
    if isinstance(value, Fraction):
        result = value
    elif type(value) is int:
        result = Fraction(_integer(value))
    elif isinstance(value, str) and _RATIONAL.fullmatch(value):
        _text(value)
        # Bounds precede parsing, including denominator and decimal expansion.
        parts = re.split(r"[/\.]", value.lstrip("-"))
        if any(len(part) > 39 for part in parts) or ("." in value and len(parts[-1]) > 38):
            _limit("integer_bits")
        try:
            result = Fraction(value)
        except (ValueError, ZeroDivisionError) as exc:
            raise SandboxError("SBX-SYNTAX", "invalid_rational") from exc
    else:
        _syntax("numeric_operand")
        raise AssertionError
    _integer(result.numerator)
    _integer(result.denominator)
    return result


def _json_size(value: Any, maximum: int, reason: str) -> None:
    size = 0
    for chunk in json.JSONEncoder(ensure_ascii=True, separators=(",", ":")).iterencode(value):
        size += len(chunk.encode("utf-8"))
        if size > maximum:
            _limit(reason)


def validate_program(program: str) -> ast.AST:
    if not isinstance(program, str):
        _syntax("program_type")
    if len(program) > MAX_CODE_BYTES or len(program.encode("utf-8")) > MAX_CODE_BYTES:
        _limit("code_bytes")
    try:
        tree = ast.parse(program, mode="exec")
    except (SyntaxError, ValueError, RecursionError) as exc:
        raise SandboxError("SBX-SYNTAX", "invalid_program") from exc
    if len(tree.body) != 1 or not isinstance(tree.body[0], (ast.Expr, ast.Assign)):
        _syntax("single_result")
    statement = tree.body[0]
    if isinstance(statement, ast.Assign) and (
        len(statement.targets) != 1
        or not isinstance(statement.targets[0], ast.Name)
        or statement.targets[0].id != "result"
    ):
        _syntax("result_assignment")
    pending: list[tuple[ast.AST, int]] = [(tree, 1)]
    count = 0
    while pending:
        node, depth = pending.pop()
        count += 1
        if count > MAX_AST_NODES:
            _limit("ast_nodes")
        if depth > MAX_DEPTH:
            _limit("ast_depth")
        if not isinstance(node, _ALLOWED):
            _syntax("forbidden_node")
        if isinstance(node, ast.Name):
            if node.id not in {"dataset", "result", *_FUNCTIONS} or "__" in node.id:
                _syntax("forbidden_name")
        if isinstance(node, ast.Call) and (
            not isinstance(node.func, ast.Name) or node.func.id not in _FUNCTIONS or node.keywords
        ):
            _syntax("forbidden_call")
        if isinstance(node, ast.Dict) and any(key is None for key in node.keys):
            _syntax("dictionary_unpack")
        if isinstance(node, ast.Constant):
            if type(node.value) is int:
                _integer(node.value)
            elif isinstance(node.value, str):
                _text(node.value)
            elif type(node.value) is not bool:
                _syntax("constant_type")
        pending.extend((child, depth + 1) for child in ast.iter_child_nodes(node))
    return tree


class _Interpreter:
    def __init__(self, dataset: list[dict[str, Any]]) -> None:
        self.steps = 0
        self.dataset = dataset
        if not isinstance(dataset, list) or len(dataset) > MAX_ROWS:
            _limit("dataset_rows")
        for row in dataset:
            if not isinstance(row, dict) or not set(row) <= _FIELDS:
                _syntax("dataset_fields")
            for key, value in row.items():
                if key in {"amount", "net_amount"}:
                    _number(value)
                elif key == "is_weekend":
                    if type(value) is not bool:
                        _syntax("dataset_field_type")
                elif key == "day_of_week":
                    if type(value) is not int or not 0 <= value <= 6:
                        _syntax("dataset_field_type")
                elif not isinstance(value, str):
                    _syntax("dataset_field_type")
        self.bounded(dataset)
        _json_size(dataset, MAX_INPUT_BYTES, "input_bytes")

    def tick(self, amount: int = 1) -> None:
        self.steps += amount
        if self.steps > MAX_STEPS:
            _limit("steps")

    def bounded(self, value: Any, depth: int = 0) -> Any:
        self.tick()
        if depth > MAX_DEPTH:
            _limit("value_depth")
        if type(value) is int:
            _integer(value)
        elif isinstance(value, Fraction):
            _number(value)
        elif isinstance(value, str):
            _text(value)
        elif type(value) is bool:
            pass
        elif isinstance(value, (list, tuple)):
            if len(value) > MAX_ROWS:
                _limit("container_size")
            for item in value:
                self.bounded(item, depth + 1)
        elif isinstance(value, dict):
            if len(value) > MAX_ROWS:
                _limit("container_size")
            for key, item in value.items():
                if not isinstance(key, str):
                    _syntax("dictionary_key")
                _text(key)
                self.bounded(item, depth + 1)
        else:
            _syntax("value_type")
        return value

    def expression(self, node: ast.AST) -> Any:
        self.tick()
        if isinstance(node, (ast.Module, ast.Expression)):
            body = node.body[0] if isinstance(node, ast.Module) else node.body
            return self.expression(body)
        if isinstance(node, (ast.Assign, ast.Expr)):
            return self.expression(node.value)
        if isinstance(node, ast.Constant):
            return self.bounded(node.value)
        if isinstance(node, ast.Name):
            if node.id != "dataset":
                _syntax("name_value")
            return self.bounded(self.dataset)
        if isinstance(node, (ast.List, ast.Tuple)):
            return self.bounded([self.expression(item) for item in node.elts])
        if isinstance(node, ast.Dict):
            result: dict[str, Any] = {}
            for key_node, value_node in zip(node.keys, node.values, strict=True):
                if key_node is None:
                    _syntax("dictionary_key")
                    raise AssertionError
                key = self.expression(key_node)
                if not isinstance(key, str) or key in result:
                    _syntax("dictionary_key")
                result[key] = self.expression(value_node)
            return self.bounded(result)
        if isinstance(node, ast.Subscript):
            container, index = self.expression(node.value), self.expression(node.slice)
            if isinstance(container, dict) and isinstance(index, str):
                if index not in container:
                    _syntax("missing_field")
                return self.bounded(container[index])
            if (
                isinstance(container, (list, tuple))
                and type(index) is int
                and -len(container) <= index < len(container)
            ):
                return self.bounded(container[index])
            _syntax("subscript")
        if isinstance(node, ast.BinOp):
            left, right = _number(self.expression(node.left)), _number(self.expression(node.right))
            if isinstance(node.op, ast.Add):
                numeric = left + right
            elif isinstance(node.op, ast.Sub):
                numeric = left - right
            elif isinstance(node.op, ast.Mult):
                numeric = left * right
            elif isinstance(node.op, ast.Div):
                if right == 0:
                    _syntax("division_by_zero")
                numeric = left / right
            else:
                _syntax("binary_operator")
                raise AssertionError
            return self.bounded(numeric)
        if isinstance(node, ast.UnaryOp):
            operand = self.expression(node.operand)
            if isinstance(node.op, ast.Not):
                if type(operand) is not bool:
                    _syntax("boolean_operand")
                return not operand
            numeric = _number(operand)
            return self.bounded(-numeric if isinstance(node.op, ast.USub) else numeric)
        if isinstance(node, ast.Compare):
            left = self.expression(node.left)
            for operator, comparator in zip(node.ops, node.comparators, strict=True):
                right = self.expression(comparator)
                if not self.compare(left, operator, right):
                    return False
                left = right
            return True
        if isinstance(node, ast.BoolOp):
            values = [self.expression(value) for value in node.values]
            if any(type(value) is not bool for value in values):
                _syntax("boolean_operand")
            return all(values) if isinstance(node.op, ast.And) else any(values)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            return self.bounded(
                self.call(node.func.id, [self.expression(arg) for arg in node.args])
            )
        _syntax("unsupported_expression")
        raise AssertionError

    def compare(self, left: Any, operator: ast.AST, right: Any) -> bool:
        self.tick()
        if isinstance(operator, (ast.In, ast.NotIn)):
            if not isinstance(right, (list, tuple)):
                _syntax("membership_operand")
            found = any(self.compare(left, ast.Eq(), item) for item in right)
            return not found if isinstance(operator, ast.NotIn) else found
        numeric_types = (int, Fraction)
        numeric_left = type(left) is not bool and (
            isinstance(left, numeric_types) or isinstance(left, str) and _RATIONAL.fullmatch(left)
        )
        numeric_right = type(right) is not bool and (
            isinstance(right, numeric_types)
            or isinstance(right, str)
            and _RATIONAL.fullmatch(right)
        )
        if numeric_left and numeric_right:
            left, right = _number(left), _number(right)
        elif type(left) is not type(right) or not isinstance(left, (str, bool)):
            _syntax("comparison_operands")
        if isinstance(operator, ast.Eq):
            return bool(left == right)
        if isinstance(operator, ast.NotEq):
            return bool(left != right)
        if isinstance(operator, ast.Lt):
            return bool(left < right)
        if isinstance(operator, ast.LtE):
            return bool(left <= right)
        if isinstance(operator, ast.Gt):
            return bool(left > right)
        if isinstance(operator, ast.GtE):
            return bool(left >= right)
        _syntax("comparison_operator")
        raise AssertionError

    def rows(self, value: Any) -> list[dict[str, Any]]:
        if (
            not isinstance(value, list)
            or len(value) > MAX_ROWS
            or any(not isinstance(row, dict) for row in value)
        ):
            _syntax("rows_argument")
        self.tick(len(value))
        return cast(list[dict[str, Any]], value)

    def field(self, row: dict[str, Any], name: Any) -> Any:
        self.tick()
        if not isinstance(name, str) or name not in _FIELDS:
            _syntax("field_argument")
        if name in row:
            return row[name]
        if name in {"day_of_week", "is_weekend"} and "booked_at" in row:
            day = self.weekday(row["booked_at"])
            return day >= 5 if name == "is_weekend" else day
        _syntax("missing_field")
        raise AssertionError

    def weekday(self, value: Any) -> int:
        self.tick()
        if not isinstance(value, str):
            _syntax("date_argument")
        try:
            if _TIMESTAMP.fullmatch(value):
                return (
                    datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ") + timedelta(hours=8)
                ).weekday()
            if _DATE.fullmatch(value):
                return date.fromisoformat(value).weekday()
        except ValueError as exc:
            raise SandboxError("SBX-SYNTAX", "date_argument") from exc
        _syntax("date_argument")
        raise AssertionError

    def call(self, name: str, args: list[Any]) -> Any:
        self.tick()
        if name == "day_of_week" and len(args) == 1:
            return self.weekday(args[0])
        if name == "count" and len(args) == 1:
            return len(self.rows(args[0]))
        if name == "filter_rows" and len(args) == 4:
            rows, field, operator, expected = self.rows(args[0]), args[1], args[2], args[3]
            operations = {
                "==": ast.Eq,
                "!=": ast.NotEq,
                "<": ast.Lt,
                "<=": ast.LtE,
                ">": ast.Gt,
                ">=": ast.GtE,
                "in": ast.In,
                "not in": ast.NotIn,
            }
            if not isinstance(operator, str) or operator not in operations:
                _syntax("filter_operator")
            if not isinstance(field, str) or field not in _FIELDS:
                _syntax("field_argument")
            if operator in {"in", "not in"} and not isinstance(expected, (list, tuple)):
                _syntax("membership_operand")
            if operator not in {"in", "not in"} and not isinstance(
                expected, (str, int, Fraction, bool)
            ):
                _syntax("comparison_operands")
            selected = []
            for row in rows:
                self.tick(6)
                if self.compare(self.field(row, field), operations[operator](), expected):
                    selected.append(row)
            return selected
        if name == "sum_money" and 1 <= len(args) <= 2:
            rows, field = self.rows(args[0]), args[1] if len(args) == 2 else "net_amount"
            if field not in {"amount", "net_amount"}:
                _syntax("money_field")
            total = Fraction()
            for row in rows:
                self.tick(3)
                total = _number(total + _number(self.field(row, field)))
            return total
        if name == "group_sum" and 2 <= len(args) <= 3:
            rows, group, field = (
                self.rows(args[0]),
                args[1],
                args[2] if len(args) == 3 else "net_amount",
            )
            if group not in {
                "category",
                "merchant_ref",
                "day_of_week",
                "is_weekend",
            } or field not in {"amount", "net_amount"}:
                _syntax("group_fields")
            groups: dict[str, Fraction] = {}
            for row in rows:
                self.tick(5)
                key = _label(str(self.field(row, group)))
                groups[key] = _number(groups.get(key, Fraction()) + _number(self.field(row, field)))
            return dict(sorted(groups.items()))
        if name == "select_fields" and len(args) == 2:
            rows, fields = self.rows(args[0]), args[1]
            if (
                not isinstance(fields, list)
                or not 1 <= len(fields) <= len(_FIELDS)
                or any(not isinstance(field, str) or field not in _FIELDS for field in fields)
            ):
                _syntax("selected_fields")
            return [{field: self.field(row, field) for field in fields} for row in rows]
        _syntax("function_signature")
        raise AssertionError

    def output(self, value: Any) -> dict[str, Any]:
        if not isinstance(value, dict):
            _syntax("output_shape")
        scalars = 0

        def encode(item: Any, depth: int = 0) -> Any:
            nonlocal scalars
            self.tick()
            if depth > MAX_DEPTH:
                _limit("output_depth")
            if isinstance(item, dict):
                return {_label(key): encode(part, depth + 1) for key, part in item.items()}
            if isinstance(item, (list, tuple)):
                return [encode(part, depth + 1) for part in item]
            if type(item) is not int and not isinstance(item, Fraction):
                _syntax("numeric_output")
            scalars += 1
            if scalars > MAX_OUTPUT_SCALARS:
                _limit("output_scalars")
            number = _number(item)
            return f"{number.numerator}/{number.denominator}"

        result = cast(dict[str, Any], encode(value))
        _json_size(result, MAX_OUTPUT_BYTES, "output_bytes")
        return result


def evaluate(program: str, dataset: list[dict[str, Any]]) -> dict[str, Any]:
    """Return only bounded canonical numerical results or a symbolic rejection."""
    try:
        tree = validate_program(program)
        interpreter = _Interpreter(dataset)
        return interpreter.output(interpreter.expression(tree))
    except SandboxError:
        raise
    except (ValueError, TypeError, KeyError, IndexError, ArithmeticError, RecursionError) as exc:
        raise SandboxError("SBX-SYNTAX", "invalid_operation") from exc


def _reject_number(_: str) -> Any:
    raise SandboxError("SBX-SYNTAX", "json_number")


def _parse_integer(value: str) -> int:
    if len(value.lstrip("-")) > 39:
        _limit("integer_bits")
    return _integer(int(value))


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _syntax("duplicate_json_key")
        result[key] = value
    return result


def main() -> None:
    try:
        raw = sys.stdin.buffer.read(MAX_WIRE_BYTES + 1)
        if len(raw) > MAX_WIRE_BYTES:
            _limit("input_bytes")
        payload = json.loads(
            raw,
            parse_float=_reject_number,
            parse_constant=_reject_number,
            parse_int=_parse_integer,
            object_pairs_hook=_object,
        )
        if not isinstance(payload, dict) or set(payload) != {"program", "dataset"}:
            _syntax("input_shape")
        response: dict[str, Any] = {
            "status": "ok",
            "results": evaluate(payload["program"], payload["dataset"]),
        }
        _json_size(response, MAX_OUTPUT_BYTES, "output_bytes")
    except SandboxError as exc:
        response = {"status": "rejected", "rule": exc.rule, "reason": exc.reason}
    except (ValueError, TypeError, ArithmeticError, RecursionError):
        response = {"status": "rejected", "rule": "SBX-SYNTAX", "reason": "invalid_input"}
    sys.stdout.write(json.dumps(response, ensure_ascii=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
