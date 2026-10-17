"""The only model entry point: offline by default, explicitly budgeted when live."""

import logging
import os
import re
from collections.abc import Callable, Generator, Mapping
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
from fractions import Fraction
from hashlib import sha256
from pathlib import Path
from threading import RLock
from typing import Any
from urllib.parse import urlsplit

from corridor.crypto.jcs import H, jcs_bytes
from corridor.gateway.privacy import PIIVault
from corridor.schemas.base import loads_exact
from corridor.schemas.models import JsonValue

SCHEMA_VERSION = "bank-llm-v1"
_SDK_LOCK = RLock()
_MODES = {"scripted", "strict", "fallback", "live", "record"}
_ENV_FIELDS = {
    "LLM_API_KEY",
    "LLM_API_BASE",
    "LLM_API",
    "LLM_MODEL",
    "LLM_MODEL_CHEAP",
    "LLM_MODEL_WEAK",
    "LLM_REASONING_EFFORT",
    "LLM_MAX_CALLS",
    "LLM_MAX_USD",
    "LLM_ASSUMED_PRICE_IN",
    "LLM_ASSUMED_PRICE_OUT",
}
_RESPONSE_INPUT_PADDING = 1024
_USAGE_FIELDS = ("input_tokens", "output_tokens", "reasoning_tokens", "total_tokens")
_WEALTH_TOOL_NAMES = {
    "capture_goal",
    "start_risk_profile",
    "compare_products",
    "explain_fact",
    "why_not",
    "propose_allocation",
    "adjust",
    "execute_plan",
    "handoff_to_advisor",
}
_IGNORED_ENVELOPE_NUMBERS = {
    "temperature",
    "top_p",
    "created_at",
    "completed_at",
    "frequency_penalty",
    "presence_penalty",
}
_SAFE_ENVELOPE_FIELDS = _IGNORED_ENVELOPE_NUMBERS | {
    "output",
    "usage",
    "input_tokens",
    "output_tokens",
    "total_tokens",
    "input_tokens_details",
    "output_tokens_details",
    "reasoning_tokens",
    "cached_tokens",
    "reasoning",
    "summary",
    "content",
    "moderation",
    "category_scores",
    "categories",
    "results",
    "error",
    "metadata",
    "logprobs",
    "top_logprobs",
    "token",
    "text",
    "arguments",
    "score",
    "scores",
    "value",
    "status",
    "model",
    "type",
    "id",
}
_ERROR_TYPES = {
    "APIError",
    "APIConnectionError",
    "APITimeoutError",
    "APIStatusError",
    "BadRequestError",
    "AuthenticationError",
    "PermissionDeniedError",
    "NotFoundError",
    "ConflictError",
    "UnprocessableEntityError",
    "RateLimitError",
    "InternalServerError",
    "ConnectError",
    "ConnectTimeout",
    "ReadTimeout",
    "WriteTimeout",
    "PoolTimeout",
    "ReadError",
    "WriteError",
    "RemoteProtocolError",
    "ProxyError",
    "SSLError",
    "SSLCertVerificationError",
    "TimeoutError",
    "ValueError",
    "TypeError",
    "LLMConfigurationError",
    "LLMOutputError",
    "BudgetExceeded",
}
_PROVIDER_ERROR_FIELDS = {
    "code": {
        "invalid_request_error",
        "unsupported_parameter",
        "unsupported_value",
        "invalid_json_schema",
        "invalid_value",
        "missing_required_parameter",
        "model_not_found",
        "permission_denied",
        "insufficient_quota",
        "rate_limit_exceeded",
        "invalid_api_key",
        "context_length_exceeded",
        "server_error",
        "timeout",
    },
    "type": {
        "invalid_request_error",
        "authentication_error",
        "permission_error",
        "not_found_error",
        "rate_limit_error",
        "server_error",
        "insufficient_quota",
    },
    "param": {
        "model",
        "input",
        "tools",
        "tools[0]",
        "tools[0].parameters",
        "tools[0].strict",
        "tools[0].name",
        "reasoning",
        "reasoning.effort",
        "max_output_tokens",
        "temperature",
        "top_p",
        "text",
        "text.format",
        "parallel_tool_calls",
        "tool_choice",
        "store",
        "stream",
    },
}
_WIRE_TOKEN = re.compile(
    r'"(?:[^"\\\x00-\x1f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"'
    r"|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?"
    r"|true|false|null|[{}\[\]:,]"
)
_SENSITIVE = {
    "password",
    "passwd",
    "pin",
    "otp",
    "api_key",
    "private_key",
    "phone",
    "phone_number",
    "account_number",
    "full_name",
    "raw_text",
    "passport",
    "email",
}


class LLMConfigurationError(ValueError):
    pass


class BudgetExceeded(RuntimeError):
    pass


class ReplayMiss(RuntimeError):
    pass


class ReplayCorrupt(ValueError):
    pass


class LLMOutputError(ValueError):
    pass


def _api_base(value: str) -> str:
    """Permit the fixed OpenAI service or an explicitly configured local adapter."""
    try:
        parsed = urlsplit(value)
        allowed = value.rstrip("/") == "https://api.openai.com/v1" or (
            parsed.scheme == "http"
            and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
            and parsed.path.rstrip("/") == "/v1"
            and parsed.port is not None
        )
        if not allowed or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError
    except (ValueError, TypeError):
        raise LLMConfigurationError(
            "API base must be OpenAI or an explicit loopback endpoint"
        ) from None
    return value.rstrip("/")


@contextmanager
def _quiet_provider_logging() -> Generator[None, None, None]:
    """SDK debug messages can contain headers; suppress them during credential use."""
    prefixes = ("openai", "httpx", "httpcore", "litellm", "LiteLLM")
    names = set(prefixes) | {
        name
        for name in logging.Logger.manager.loggerDict
        if any(name == prefix or name.startswith(prefix + ".") for prefix in prefixes)
    }
    previous = []
    for name in names:
        logger = logging.getLogger(name)
        previous.append((logger, logger.disabled, logger.level))
        logger.disabled = True
        logger.setLevel(logging.CRITICAL + 1)
    try:
        yield
    finally:
        for logger, disabled, level in previous:
            logger.disabled = disabled
            logger.setLevel(level)


@dataclass(frozen=True)
class LLMResult:
    output: dict[str, JsonValue]
    source: str
    replay_key: str


def _hash(value: object) -> str:
    """Hash all request fields, including fields named sig inside untrusted prompts."""
    return sha256(jcs_bytes(value)).hexdigest()


def _usage_metadata(value: object) -> dict[str, int]:
    """Validate persisted provider counts without treating replay as new inference."""
    if (
        not isinstance(value, dict)
        or set(value) != set(_USAGE_FIELDS)
        or any(type(value[field]) is not int for field in _USAGE_FIELDS)
        or value["input_tokens"] < 1
        or value["output_tokens"] < 1
        or not 0 <= value["reasoning_tokens"] <= value["output_tokens"]
        or value["total_tokens"] != value["input_tokens"] + value["output_tokens"]
    ):
        raise ValueError("Invalid recorded usage metadata")
    return {field: value[field] for field in _USAGE_FIELDS}


def default_context_guard(value: object) -> None:
    """Reject recognizable raw secrets/PII; a caller vault guards known private names."""
    PIIVault().ensure_safe(value, rule="PII-OUT")
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(key, str) and key.lower() in _SENSITIVE:
                raise ValueError("PII-OUT")
            default_context_guard(key)
            default_context_guard(item)
    elif isinstance(value, list):
        for item in value:
            default_context_guard(item)


def _object(value: object) -> dict[str, JsonValue]:
    result = loads_exact(jcs_bytes(value))
    if not isinstance(result, dict):
        raise ValueError("Expected a JSON object")
    return result


def _fingerprints(value: object, path: str = "$") -> dict[str, str]:
    result = {path: _hash(value)}
    if isinstance(value, dict):
        for key, item in sorted(value.items()):
            label = key if re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]{0,63}", key) else _hash(key)[:12]
            result.update(_fingerprints(item, f"{path}.{label}"))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            result.update(_fingerprints(item, f"{path}[{index}]"))
    return result


def _environment(path: Path | None) -> dict[str, str]:
    values: dict[str, str] = {}
    if path is not None and path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, value = stripped.split("=", 1)
            if key.strip() in _ENV_FIELDS:
                values[key.strip()] = value.strip().strip("\"'")
    return {**values, **{key: value for key, value in os.environ.items() if key.startswith("LLM_")}}


def _strict_schema(schema: object) -> dict[str, Any]:
    """Close every tool object; arbitrary maps narrow to the empty object."""

    def close(value: object) -> Any:
        if isinstance(value, list):
            return [close(item) for item in value]
        if not isinstance(value, dict):
            return value
        result: dict[str, Any] = {}
        for key, item in value.items():
            if key == "default":
                continue
            if key in {"properties", "$defs"} and isinstance(item, dict):
                result[key] = {name: close(child) for name, child in item.items()}
            else:
                result[key] = close(item)
        if result.get("type") == "object" or "properties" in result:
            properties = result.get("properties", {})
            if not isinstance(properties, dict):
                raise LLMConfigurationError("Invalid response tool schema")
            result.update(
                properties=properties, required=list(properties), additionalProperties=False
            )
        return result

    if not isinstance(schema, dict) or schema.get("type") != "object":
        raise LLMConfigurationError("Responses tool schema must be an object")
    closed = close(schema)
    if not isinstance(closed, dict):
        raise LLMConfigurationError("Invalid response tool schema")
    return closed


def _named_tools(prompt: dict[str, JsonValue]) -> list[dict[str, Any]] | None:
    """Allow only the declared wealth functions, with closed strict wire schemas."""
    if "tools" not in prompt:
        return None
    offered = prompt["tools"]
    if (
        "response_schema" in prompt
        or not isinstance(offered, list)
        or not 1 <= len(offered) <= len(_WEALTH_TOOL_NAMES)
    ):
        raise LLMConfigurationError("Named tools require one unambiguous tool catalogue")
    tools = []
    names = set()
    for tool in offered:
        if (
            not isinstance(tool, dict)
            or set(tool) != {"type", "name", "description", "parameters", "strict"}
            or tool.get("type") != "function"
            or tool.get("strict") is not True
            or not isinstance(tool.get("name"), str)
            or tool["name"] not in _WEALTH_TOOL_NAMES
            or tool["name"] in names
            or not isinstance(tool.get("description"), str)
        ):
            raise LLMConfigurationError("Invalid named wealth tool definition")
        names.add(tool["name"])
        tools.append({**tool, "parameters": _strict_schema(tool["parameters"])})
    return tools


def _response_envelope(raw: bytes) -> Any:
    """Discard root sampling/timestamp metadata before the exact JSON decoder."""
    if len(raw) > 1_048_576:
        raise ValueError("Provider response exceeds the transport bound")
    source = raw.decode("utf-8")
    parts: list[str] = []
    stack: list[str] = []
    previous, root_key = "", ""
    offset = 0
    while offset < len(source):
        if source[offset] in " \t\r\n":
            parts.append(source[offset])
            offset += 1
            continue
        match = _WIRE_TOKEN.match(source, offset)
        if match is None:
            raise ValueError("Malformed provider JSON envelope")
        token = match.group()
        root = stack == ["{"]
        if root and previous in {"{", ","} and token.startswith('"'):
            root_key = loads_exact(token)
        if (
            root
            and previous == ":"
            and root_key in _IGNORED_ENVELOPE_NUMBERS
            and token[0] in "-0123456789"
        ):
            parts.append("null")
        else:
            parts.append(token)
        if token in {"{", "["}:
            stack.append(token)
        elif token in {"}", "]"}:
            if not stack or stack[-1] != ("{" if token == "}" else "["):
                raise ValueError("Malformed provider JSON envelope")
            stack.pop()
        previous = token
        offset = match.end()
    # Duplicate properties, malformed number tails, and all other floats still reject.
    return loads_exact("".join(parts))


def _safe_exception_diagnostics(error: Exception) -> dict[str, Any]:
    def label(item: BaseException) -> str:
        name = type(item).__name__
        return name if name in _ERROR_TYPES else "OtherError"

    result: dict[str, Any] = {"error_type": label(error)}
    causes = []
    cause = error.__cause__ or error.__context__
    for _ in range(4):
        if cause is None or cause is error:
            break
        causes.append(label(cause))
        cause = cause.__cause__ or cause.__context__
    if causes:
        result["error_cause_types"] = causes
    return result


def _envelope_diagnostics(raw: bytes, error: Exception) -> dict[str, Any]:
    """Describe decoder failures without exposing body values or unknown property names."""
    message = str(error)
    if isinstance(error, UnicodeDecodeError):
        reason = "utf8"
    elif message.startswith("JSON floating-point numbers are forbidden:"):
        reason = "float"
    elif message.startswith("Duplicate JSON property:"):
        reason = "duplicate-key"
    elif message == "Provider response exceeds the transport bound":
        reason = "response-too-large"
    elif isinstance(error, ValueError):
        reason = "json-syntax"
    else:
        reason = "other"
    result: dict[str, Any] = {"envelope_error_reason": reason}
    if reason != "float" or len(raw) > 1_048_576:
        return result
    paths: list[str] = []
    try:
        source = raw.decode("utf-8")
        stack: list[dict[str, str]] = []
        offset = 0
        while offset < len(source) and len(paths) < 12:
            if source[offset] in " \t\r\n":
                offset += 1
                continue
            match = _WIRE_TOKEN.match(source, offset)
            if match is None:
                break
            token = match.group()
            offset = match.end()
            frame = stack[-1] if stack else None
            if frame is not None and frame["kind"] == "object" and frame["phase"] == "key":
                if token.startswith('"'):
                    name = loads_exact(token)
                    frame["key"] = (
                        name
                        if name in _SAFE_ENVELOPE_FIELDS
                        else f"field_{sha256(name.encode('utf-8')).hexdigest()[:12]}"
                    )
                    frame["phase"] = "colon"
                    continue
            if token == ":" and frame is not None:
                frame["phase"] = "value"
                continue
            if token == "," and frame is not None:
                frame["phase"] = "key" if frame["kind"] == "object" else "value"
                continue
            if token in {"}", "]"}:
                if stack:
                    stack.pop()
                continue
            path = "$"
            if frame is not None:
                path = frame["path"] + (f".{frame['key']}" if frame["kind"] == "object" else "[*]")
                frame["phase"] = "after"
            if token in {"{", "["}:
                if len(stack) >= 32:
                    break
                stack.append({
                    "kind": "object" if token == "{" else "array",
                    "path": path,
                    "key": "",
                    "phase": "key" if token == "{" else "value",
                })
            elif (
                token[0] in "-0123456789"
                and any(character in token for character in ".eE")
                and path not in {f"$.{name}" for name in _IGNORED_ENVELOPE_NUMBERS}
                and path not in paths
            ):
                paths.append(path)
    except (ValueError, TypeError):
        pass
    if paths:
        result["envelope_float_paths"] = paths
    return result


def _safe_provider_diagnostics(raw: bytes) -> dict[str, str]:
    try:
        envelope = _response_envelope(raw)
        error = envelope.get("error") if isinstance(envelope, dict) else None
        if not isinstance(error, dict):
            return {}
        return {
            f"provider_error_{key}": error[key]
            for key, allowed in _PROVIDER_ERROR_FIELDS.items()
            if isinstance(error.get(key), str) and error[key] in allowed
        }
    except (ValueError, TypeError):
        return {}


def _omit_null_defaults(value: object, schema: dict[str, Any]) -> object:
    """Restore omitted optional fields after strict tools made every field required."""

    def resolve(node: dict[str, Any]) -> dict[str, Any]:
        reference = node.get("$ref")
        if isinstance(reference, str) and reference.startswith("#/$defs/"):
            target = schema.get("$defs", {}).get(reference[8:])
            if isinstance(target, dict):
                return {**target, **{key: item for key, item in node.items() if key != "$ref"}}
        return node

    def prune(item: object, node: dict[str, Any], depth: int = 0) -> object:
        if depth > 128:
            raise LLMOutputError("Model output nesting exceeds the response bound")
        node = resolve(node)
        for branch in node.get("anyOf", []):
            if not isinstance(branch, dict):
                continue
            branch = resolve(branch)
            kind = branch.get("type")
            if (kind == "object" and isinstance(item, dict)) or (
                kind == "array" and isinstance(item, list)
            ):
                return prune(item, branch, depth + 1)
        if isinstance(item, dict):
            properties = node.get("properties", {})
            result = {}
            for key, child in item.items():
                child_schema = properties.get(key, node.get("additionalProperties", {}))
                if not isinstance(child_schema, dict):
                    child_schema = {}
                if child is None and "default" in child_schema and child_schema["default"] is None:
                    continue
                result[key] = prune(child, child_schema, depth + 1)
            return result
        if isinstance(item, list):
            child_schema = node.get("items", {})
            if not isinstance(child_schema, dict):
                child_schema = {}
            return [prune(child, child_schema, depth + 1) for child in item]
        return item

    return prune(value, schema)


class LLMClient:
    def __init__(
        self,
        mode: str = "scripted",
        replay_dir: Path = Path("data/replay/bank"),
        model: str = "scripted-bank-v1",
        config: str = "cca",
        user_policy: str = "careful",
        context_guard: Callable[[object], None] | None = None,
        *,
        api_key: str | None = None,
        max_calls: int | None = None,
        max_usd: Fraction | str | None = None,
        max_output_tokens: int = 512,
        env_file: Path | None = Path(".env"),
        api: str | None = None,
        reasoning_effort: str | None = None,
        model_tier: str = "main",
        assumed_price_in: Fraction | str | None = None,
        assumed_price_out: Fraction | str | None = None,
        environment: Mapping[str, str] | None = None,
        api_base: str | None = None,
        request_guard: Callable[[Fraction], Callable[[Fraction], None]] | None = None,
    ) -> None:
        if mode not in _MODES:
            raise LLMConfigurationError("Unknown planner mode")
        self.mode, self.replay_dir = mode, Path(replay_dir)
        self.model, self.config, self.user_policy = model, config, user_policy
        self.context_guard = context_guard or default_context_guard
        self.calls: list[dict[str, Any]] = []
        self.observers: list[Callable[[str, object], None]] = []
        self.spent_usd = Fraction(0)
        self.api_calls = 0
        self._api_key = ""
        self._budget_exhausted = False
        self.request_guard = request_guard
        self._request_settle: Callable[[Fraction], None] | None = None
        self.max_calls = 0
        self.max_usd = Fraction(0)
        self.max_output_tokens = max_output_tokens
        if model_tier not in {"main", "cheap", "weak"}:
            raise LLMConfigurationError("Unknown model tier")
        env = (
            (dict(environment) if environment is not None else _environment(env_file))
            if mode in {"live", "record"}
            else {}
        )
        self.api_base = _api_base(api_base or env.get("LLM_API_BASE", "https://api.openai.com/v1"))
        if mode in {"live", "record"}:
            self._api_key = api_key if api_key is not None else env.get("LLM_API_KEY", "")
            if not self._api_key:
                raise LLMConfigurationError("Live/record requires an API key credential")
            if model == "scripted-bank-v1":
                model_key = (
                    "LLM_MODEL" if model_tier == "main" else f"LLM_MODEL_{model_tier.upper()}"
                )
                self.model = env.get(model_key, model)
            raw_model = self.model.removeprefix("openai/")
            if (
                not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", raw_model)
                or self.model.endswith("-latest")
                or self.model == "scripted-bank-v1"
            ):
                raise LLMConfigurationError("Live/record requires a fixed OpenAI model")
            try:
                call_caps = ([max_calls] if max_calls is not None else []) + (
                    [int(env["LLM_MAX_CALLS"])] if "LLM_MAX_CALLS" in env else []
                )
                usd_caps = ([max_usd] if max_usd is not None else []) + (
                    [env["LLM_MAX_USD"]] if "LLM_MAX_USD" in env else []
                )
                if not call_caps or not usd_caps:
                    raise ValueError
                if any(type(cap) is not int or cap < 1 for cap in call_caps):
                    raise ValueError
                if any(isinstance(cap, (float, bool)) for cap in usd_caps):
                    raise ValueError
                fractions = [Fraction(cap) for cap in usd_caps]
                if any(cap <= 0 for cap in fractions):
                    raise ValueError
                self.max_calls, self.max_usd = min(call_caps), min(fractions)
            except (ValueError, TypeError, ZeroDivisionError):
                raise LLMConfigurationError(
                    "Live/record requires positive call and USD budgets"
                ) from None
        is_gpt6 = self.model.removeprefix("openai/").startswith("gpt-6")
        self.api = api or env.get("LLM_API") or ("responses" if is_gpt6 else "chat")
        if self.api == "chat.completions":
            self.api = "chat"
        if self.api not in {"chat", "responses"}:
            raise LLMConfigurationError("Unknown OpenAI API")
        self.reasoning_effort = (
            reasoning_effort
            or env.get("LLM_REASONING_EFFORT")
            or ("low" if self.api == "responses" else None)
        )
        if self.reasoning_effort not in {None, "none", "minimal", "low", "medium", "high", "xhigh"}:
            raise LLMConfigurationError("Unknown reasoning effort")
        if mode in {"live", "record"} and is_gpt6 and self.api != "responses":
            raise LLMConfigurationError("GPT-6 function tools require the Responses API")
        if type(max_output_tokens) is not int or (
            not 128 <= max_output_tokens <= 8192
            if self.api == "responses"
            else max_output_tokens != 512
        ):
            raise LLMConfigurationError("Invalid bounded generation profile")
        try:
            self._assumed_pricing_configured = (
                assumed_price_in is not None
                or assumed_price_out is not None
                or "LLM_ASSUMED_PRICE_IN" in env
                or "LLM_ASSUMED_PRICE_OUT" in env
            )
            prices = (
                assumed_price_in
                if assumed_price_in is not None
                else env.get("LLM_ASSUMED_PRICE_IN", "10"),
                assumed_price_out
                if assumed_price_out is not None
                else env.get("LLM_ASSUMED_PRICE_OUT", "40"),
            )
            if any(isinstance(price, (float, bool)) for price in prices):
                raise ValueError
            self.assumed_price_in, self.assumed_price_out = (Fraction(price) for price in prices)
            if min(self.assumed_price_in, self.assumed_price_out) <= 0:
                raise ValueError
        except (ValueError, TypeError, ZeroDivisionError):
            raise LLMConfigurationError(
                "Assumed token prices must be positive exact values"
            ) from None

    def complete(
        self,
        *,
        task_id: str,
        step: str,
        prompt: dict[str, JsonValue],
        tool_state: dict[str, JsonValue],
        sample_idx: int = 0,
        scripted: Callable[[], dict[str, JsonValue]],
    ) -> LLMResult:
        if not task_id or not step or type(sample_idx) is not int or sample_idx < 0:
            raise ValueError("Invalid replay request identity")
        prompt, tool_state = _object(prompt), _object(tool_state)
        named_tools = _named_tools(prompt)
        if named_tools is not None and self.api != "responses":
            raise LLMConfigurationError("Named wealth tools require the Responses API")
        request: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "model": self.model,
            "api": self.api,
            "reasoning_effort": self.reasoning_effort,
            "max_output_tokens": self.max_output_tokens,
            "prompt_hash": _hash(prompt),
            "tool_state_hash": _hash(tool_state),
            "task_id": task_id,
            "step": step,
            "sample_idx": sample_idx,
            "config": self.config,
            "user_policy": self.user_policy,
        }
        key = H(request)
        trace = {**request, "request_hash": key, "replay_key": key, "source": "context-rejected"}
        try:
            for value in (
                prompt,
                tool_state,
                {
                    "task_id": task_id,
                    "step": step,
                    "model": self.model,
                    "config": self.config,
                    "user_policy": self.user_policy,
                },
            ):
                if self._api_key and self._api_key in jcs_bytes(value).decode("utf-8"):
                    raise ValueError("PII-CTX")
                self.context_guard(value)
        except Exception:
            for name in ("task_id", "step", "model", "config", "user_policy"):
                trace[name] = f"redacted:{_hash(request[name])}"
            self.calls.append(trace)
            raise ValueError("PII-CTX") from None
        self.calls.append(trace)
        self._observe("request", {"prompt": prompt, "tool_state": tool_state})
        path = self.replay_dir / key[:16] / f"{request['prompt_hash'][:16]}.json"
        if self.mode == "record" and path.exists():
            trace["source"] = "record-exists"
            raise ReplayCorrupt("Refusing to replace an existing live replay")
        if self.mode in {"strict", "fallback"}:
            if path.exists():
                try:
                    record = loads_exact(path.read_bytes())
                    if (
                        record["source"] != "live-recorded"
                        or record["request"] != request
                        or record["replay_key"] != key
                        or record["output_hash"] != _hash(record["output"])
                    ):
                        raise ValueError
                    if "usage" in record or "usage_hash" in record:
                        usage = _usage_metadata(record["usage"])
                        if (
                            record["usage_hash"] != _hash(usage)
                            or usage["output_tokens"] > self.max_output_tokens
                        ):
                            raise ValueError
                        trace["recorded_usage"] = usage
                    output = self._output(record["output"], named_tools)
                except (ValueError, KeyError, TypeError, OSError):
                    trace["source"] = "replay-corrupt"
                    raise ReplayCorrupt("Invalid real-response replay record") from None
                trace["source"] = "replay"
                return LLMResult(output, "replay", key)
            if self.mode == "strict":
                trace["source"] = "replay-miss"
                raise ReplayMiss(self._miss(request, prompt))
        if self.mode in {"scripted", "fallback"}:
            source = "scripted" if self.mode == "scripted" else "scripted-fallback"
            output = self._output(scripted(), named_tools)
        else:
            trace["source"] = "live-attempt"
            try:
                with _SDK_LOCK:
                    try:
                        output = self._live(prompt, tool_state, trace)
                    finally:
                        if self._request_settle is not None:
                            settle, self._request_settle = self._request_settle, None
                            settle(Fraction(trace["cost_usd"]))
            except TimeoutError:
                if self.mode == "live":
                    trace["source"] = "live-error"
                    raise LLMOutputError(
                        "Model request timed out; live mode remains selected"
                    ) from None
                output, source = self._output(scripted(), named_tools), "scripted-timeout"
            else:
                source = "live-recorded" if self.mode == "record" else "live"
                if self.mode == "record":
                    usage = _usage_metadata({field: trace[field] for field in _USAGE_FIELDS})
                    record = {
                        "source": source,
                        "request": request,
                        "replay_key": key,
                        "prompt_fingerprints": _fingerprints(prompt),
                        "output": output,
                        "output_hash": _hash(output),
                        "cost_usd": trace["cost_usd"],
                        "usage": usage,
                        "usage_hash": _hash(usage),
                    }
                    path.parent.mkdir(parents=True, exist_ok=True)
                    data = jcs_bytes(record)
                    if path.exists():
                        raise ReplayCorrupt("Refusing to replace an existing live replay")
                    with path.open("xb") as stream:
                        if stream.write(data) != len(data):
                            raise OSError("Replay write failed")
                        stream.flush()
        trace["source"] = source
        return LLMResult(deepcopy(output), source, key)

    def _observe(self, stage: str, value: object) -> None:
        """Offer in-memory inspection without persisting data or allowing mutation."""
        for observer in self.observers:
            observer(stage, deepcopy(value))

    def _output(
        self, output: object, named_tools: list[dict[str, Any]] | None = None
    ) -> dict[str, JsonValue]:
        try:
            result = _object(output)
            if named_tools is not None and (
                set(result) != {"tool", "arguments"}
                or not isinstance(result.get("tool"), str)
                or result["tool"] not in {tool["name"] for tool in named_tools}
                or not isinstance(result.get("arguments"), dict)
            ):
                raise LLMOutputError("Invalid named tool selection or arguments")
            if self._api_key and self._api_key in jcs_bytes(result).decode("utf-8"):
                raise ValueError
            self._observe("output", result)
            self.context_guard(result)
            return result
        except (ValueError, TypeError):
            raise LLMOutputError("Invalid or unsafe model output (PII-OUT)") from None

    def _miss(self, request: dict[str, Any], prompt: dict[str, JsonValue]) -> str:
        current = _fingerprints(prompt)
        previous: dict[str, str] = {}
        for path in sorted(self.replay_dir.glob("*/*.json")):
            try:
                record = loads_exact(path.read_bytes())
                if all(record["request"][key] == request[key] for key in ("task_id", "step")):
                    candidate = record.get("prompt_fingerprints", {})
                    path_pattern = r"\$(?:\.[A-Za-z_][A-Za-z_0-9]{0,63}|\.[0-9a-f]{12}|\[[0-9]+\])*"
                    if isinstance(candidate, dict) and all(
                        isinstance(name, str)
                        and re.fullmatch(path_pattern, name)
                        and isinstance(digest, str)
                        and re.fullmatch(r"[0-9a-f]{64}", digest)
                        for name, digest in candidate.items()
                    ):
                        previous = candidate
                    break
            except (ValueError, KeyError, TypeError, OSError):
                continue
        changes = [
            f"{path}: {previous.get(path, 'missing')[:12]} -> {current.get(path, 'missing')[:12]}"
            for path in sorted(previous.keys() | current.keys())
            if previous.get(path) != current.get(path)
        ]
        difference = ", ".join(changes[:20]) or "unchanged prompt; request metadata differs"
        return (
            f"Replay miss task_id={request['task_id']} step={request['step']}; "
            f"prompt diff (hashes only): {difference}"
        )

    def _live(
        self, prompt: dict[str, JsonValue], state: dict[str, JsonValue], trace: dict[str, Any]
    ) -> dict[str, JsonValue]:
        if self.api == "responses":
            return self._responses(prompt, state, trace)
        with _SDK_LOCK:
            if self._budget_exhausted or self.api_calls >= self.max_calls:
                trace["source"] = "budget-rejected"
                raise BudgetExceeded("LLM call budget exhausted")
            # Importing LiteLLM otherwise refreshes its remote pricing map.
            os.environ["LITELLM_LOCAL_MODEL_COST_MAP"] = "True"
            os.environ["EXPERIMENTAL_OPENAI_BASE_LLM_HTTP_HANDLER"] = "false"
            import litellm

            raw_model = self.model.removeprefix("openai/")
            info = litellm.model_cost.get(self.model, litellm.model_cost.get(raw_model, {}))
            try:
                input_limit = info["max_input_tokens"]
                output_limit = info["max_output_tokens"]
                if info.get("mode") != "chat":
                    raise ValueError
                if (
                    type(input_limit) is not int
                    or input_limit < 1
                    or self.max_output_tokens > output_limit
                ):
                    raise ValueError
                input_rate = max(
                    Fraction(str(value))
                    for key, value in info.items()
                    if key.startswith("input_cost_per_token") and value is not None
                )
                output_rate = max(
                    Fraction(str(value))
                    for key, value in info.items()
                    if key.startswith("output_cost_per_token") and value is not None
                )
                if input_rate < 0 or output_rate < 0:
                    raise ValueError
            except (ValueError, KeyError, TypeError, ZeroDivisionError):
                trace["source"] = "pricing-rejected"
                raise LLMConfigurationError("Missing bounded local model pricing") from None
            if self._assumed_pricing_configured:
                input_rate = max(input_rate, self.assumed_price_in / 1_000_000)
                output_rate = max(output_rate, self.assumed_price_out / 1_000_000)
            trace["pricing_source"] = (
                "assumed_or_local_max" if self._assumed_pricing_configured else "local-model-map"
            )
            messages = [
                {
                    "role": "system",
                    "content": "Return exactly one JSON object. Use only supplied typed handles.",
                },
                {
                    "role": "user",
                    "content": jcs_bytes({"prompt": prompt, "tool_state": state}).decode("utf-8"),
                },
            ]
            # A byte bound avoids tokenizer downloads or approximate sampling.
            frozen_messages = jcs_bytes(messages)
            input_bound = len(frozen_messages) + 128
            if input_bound > input_limit:
                raise LLMConfigurationError("Request exceeds conservative model input bound")
            reserve = input_bound * input_rate + self.max_output_tokens * output_rate
            if self.spent_usd + reserve > self.max_usd:
                trace["source"] = "budget-rejected"
                raise BudgetExceeded("LLM USD budget cannot cover the bounded request cost")
            import httpx
            from openai import OpenAI

            class SingleRequestTransport(httpx.BaseTransport):
                def __init__(self) -> None:
                    self.inner = httpx.HTTPTransport(retries=0, trust_env=False)
                    self.sent = False
                    self.responded = False
                    self.raw: object = None

                def handle_request(self, request: httpx.Request) -> httpx.Response:
                    if self.sent:
                        raise BudgetExceeded("Provider retry blocked before a second HTTP request")
                    body = loads_exact(request.content)
                    if (
                        request.method != "POST"
                        or str(request.url) != endpoint
                        or not isinstance(body, dict)
                        or body.get("model") != raw_model
                        or jcs_bytes(body.get("messages")) != frozen_messages
                        or body.get("max_completion_tokens", body.get("max_tokens")) != 512
                        or ("max_completion_tokens" in body and "max_tokens" in body)
                        or body.get("n", 1) != 1
                        or body.get("stream", False) is not False
                        or body.get("response_format") != {"type": "json_object"}
                        or set(body)
                        - {
                            "model",
                            "messages",
                            "max_completion_tokens",
                            "max_tokens",
                            "n",
                            "stream",
                            "response_format",
                        }
                    ):
                        raise LLMConfigurationError("Provider request changed fixed model or scope")
                    self.sent = True
                    response = self.inner.handle_request(request)
                    self.responded = 200 <= response.status_code < 300
                    if self.responded:
                        self.raw = _response_envelope(response.read())
                    return response

                def close(self) -> None:
                    self.inner.close()

            endpoint = self.api_base + "/chat/completions"
            if self.request_guard is not None:
                self._request_settle = self.request_guard(reserve)
            self.api_calls += 1
            self.spent_usd += reserve
            trace["cost_usd"] = reserve
            previous = {
                name: getattr(litellm, name, None)
                for name in (
                    "num_retries",
                    "model_fallbacks",
                    "drop_params",
                    "route_all_chat_openai_to_responses",
                    "model_alias_map",
                )
            }
            litellm.num_retries, litellm.model_fallbacks, litellm.drop_params = 0, None, False
            litellm.route_all_chat_openai_to_responses = False
            litellm.model_alias_map = {}
            try:
                transport = SingleRequestTransport()
                with (
                    _quiet_provider_logging(),
                    httpx.Client(
                        transport=transport, follow_redirects=False, trust_env=False, timeout=20
                    ) as http_client,
                ):
                    client = OpenAI(
                        api_key=self._api_key,
                        max_retries=0,
                        http_client=http_client,
                        base_url=self.api_base,
                        timeout=20,
                    )
                    litellm.completion(
                        model=f"openai/{raw_model}",
                        messages=deepcopy(messages),
                        client=client,
                        api_key=self._api_key,
                        max_completion_tokens=self.max_output_tokens,
                        n=1,
                        stream=False,
                        response_format={"type": "json_object"},
                        timeout=20,
                        num_retries=0,
                        max_retries=0,
                        retry_policy=None,
                        context_window_fallback_dict={},
                        _skip_responses_api_bridge=True,
                        caching=False,
                        api_base=self.api_base,
                    )
                    if not transport.responded:
                        raise LLMOutputError(
                            "No actual provider request; refusing cached SDK output"
                        )
            except Exception as exc:
                trace["source"] = "live-error"
                if isinstance(exc, (TimeoutError, getattr(litellm, "Timeout", TimeoutError))):
                    raise TimeoutError("Model request timed out") from None
                raise LLMOutputError("Model request failed; no replay recorded") from None
            finally:
                for name, value in previous.items():
                    setattr(litellm, name, value)
            try:
                response = transport.raw
                if not isinstance(response, dict):
                    raise ValueError
                usage = response.get("usage")
                if not isinstance(usage, dict):
                    raise ValueError
                used_in, used_out = usage.get("prompt_tokens"), usage.get("completion_tokens")
                details = usage.get("completion_tokens_details") or {}
                if not isinstance(details, dict):
                    raise ValueError
                reasoning = details.get("reasoning_tokens", 0)
                if (
                    type(used_in) is not int
                    or type(used_out) is not int
                    or type(reasoning) is not int
                ):
                    raise ValueError
                total = usage.get("total_tokens", used_in + used_out)
                if (
                    used_in < 1
                    or used_out < 1
                    or type(total) is not int
                    or total != used_in + used_out
                    or not 0 <= reasoning <= used_out
                ):
                    raise ValueError
                actual = used_in * input_rate + used_out * output_rate
                trace.update(
                    input_tokens=used_in,
                    output_tokens=used_out,
                    reasoning_tokens=reasoning,
                    total_tokens=total,
                )
                if actual > reserve:
                    self.spent_usd += actual - reserve
                    trace["cost_usd"] = actual
                if (
                    used_in > input_bound
                    or used_out > self.max_output_tokens
                    or self.spent_usd > self.max_usd
                ):
                    self._budget_exhausted = True
                    trace["source"] = "budget-rejected"
                    raise BudgetExceeded("Provider usage exceeded the reserved request budget")
                choices = response["choices"]
                if len(choices) != 1:
                    raise ValueError
                choice = choices[0]
                message = choice["message"] if isinstance(choice, dict) else choice.message
                content = message["content"] if isinstance(message, dict) else message.content
                if not isinstance(content, str):
                    raise ValueError
                output = self._output(loads_exact(content))
                self.spent_usd -= max(Fraction(0), reserve - actual)
                trace["cost_usd"] = actual
                return output
            except LLMOutputError:
                trace["source"] = "output-rejected"
                raise
            except (ValueError, TypeError, KeyError, AttributeError):
                trace["source"] = "output-rejected"
                raise LLMOutputError("Invalid model response; no replay recorded") from None

    def _responses(
        self, prompt: dict[str, JsonValue], state: dict[str, JsonValue], trace: dict[str, Any]
    ) -> dict[str, JsonValue]:
        """One actual Responses request, with a reservation before any SDK call."""
        with _SDK_LOCK:
            if self._budget_exhausted or self.api_calls >= self.max_calls:
                trace["source"] = "budget-rejected"
                raise BudgetExceeded("LLM call or USD budget exhausted")
            raw_model = self.model.removeprefix("openai/")
            schema = prompt.get("response_schema")
            named_tools = _named_tools(prompt)
            if schema is not None and not isinstance(schema, dict):
                raise LLMConfigurationError("Responses tool schema must be an object")
            body: dict[str, Any] = {
                "model": raw_model,
                "input": [
                    {
                        "role": "system",
                        "content": (
                            "Choose exactly one supplied function. Use only supplied typed handles."
                            if named_tools is not None
                            else "Return exactly one JSON object. Use only supplied typed handles."
                        ),
                    },
                    {
                        "role": "user",
                        "content": jcs_bytes({"prompt": prompt, "tool_state": state}).decode(
                            "utf-8"
                        ),
                    },
                ],
                "max_output_tokens": self.max_output_tokens,
                "store": False,
                "stream": False,
            }
            if self.reasoning_effort is not None:
                body["reasoning"] = {"effort": self.reasoning_effort}
            if named_tools is not None:
                body.update(tools=named_tools, tool_choice="required", parallel_tool_calls=False)
            elif schema is not None:
                body.update(
                    tools=[
                        {
                            "type": "function",
                            "name": "emit_result",
                            "description": (
                                "Return the requested typed result using only supplied handles."
                            ),
                            "parameters": _strict_schema(schema),
                            "strict": True,
                        }
                    ],
                    tool_choice={"type": "function", "name": "emit_result"},
                    parallel_tool_calls=False,
                )
            else:
                body["text"] = {"format": {"type": "json_object"}}
            # UTF-8 bytes bound text tokens; padding covers tool/message framing.
            frozen_body = jcs_bytes(body)
            input_bound = len(frozen_body) + _RESPONSE_INPUT_PADDING
            input_rate = self.assumed_price_in / 1_000_000
            output_rate = self.assumed_price_out / 1_000_000
            reserve = input_bound * input_rate + self.max_output_tokens * output_rate
            if self.spent_usd + reserve > self.max_usd:
                trace["source"] = "budget-rejected"
                raise BudgetExceeded("LLM USD budget cannot cover the bounded request cost")
            import httpx
            from openai import OpenAI

            class SingleResponseTransport(httpx.BaseTransport):
                def __init__(self) -> None:
                    self.inner = httpx.HTTPTransport(retries=0, trust_env=False)
                    self.sent = False
                    self.responded = False
                    self.raw: object = None

                def handle_request(self, request: httpx.Request) -> httpx.Response:
                    if self.sent:
                        raise BudgetExceeded("Provider retry blocked before a second HTTP request")
                    if (
                        request.method != "POST"
                        or str(request.url) != endpoint
                        or jcs_bytes(loads_exact(request.content)) != frozen_body
                    ):
                        raise LLMConfigurationError("Provider request changed fixed model or scope")
                    self.sent = True
                    response = self.inner.handle_request(request)
                    self.responded = 200 <= response.status_code < 300
                    if type(response.status_code) is int and 100 <= response.status_code <= 599:
                        trace["http_status"] = response.status_code
                    if self.responded:
                        # Preserve wire types: the SDK may coerce boolean/string usage to ints.
                        payload = response.read()
                        try:
                            self.raw = _response_envelope(payload)
                        except (ValueError, TypeError) as exc:
                            trace["error_stage"] = "response-envelope"
                            trace.update(_envelope_diagnostics(payload, exc))
                            raise
                    else:
                        trace.update(_safe_provider_diagnostics(response.read()))
                    return response

                def close(self) -> None:
                    self.inner.close()

            endpoint = self.api_base + "/responses"
            if self.request_guard is not None:
                self._request_settle = self.request_guard(reserve)
            self.api_calls += 1
            self.spent_usd += reserve
            trace.update(cost_usd=reserve, pricing_source="assumed")
            try:
                transport = SingleResponseTransport()
                with (
                    _quiet_provider_logging(),
                    httpx.Client(
                        transport=transport, follow_redirects=False, trust_env=False, timeout=20
                    ) as http_client,
                ):
                    client = OpenAI(
                        api_key=self._api_key,
                        max_retries=0,
                        http_client=http_client,
                        base_url=self.api_base,
                        timeout=20,
                    )
                    client.responses.create(**deepcopy(body))
                    if not transport.responded:
                        raise LLMOutputError(
                            "No actual provider request; refusing cached SDK output"
                        )
            except Exception as exc:
                trace["source"] = "live-error"
                trace.update(_safe_exception_diagnostics(exc))
                # Responses live mode never turns a failed paid request into scripted success.
                raise LLMOutputError("Model request failed; no replay recorded") from None
            try:
                response = transport.raw
                if not isinstance(response, dict):
                    raise ValueError
                usage = response.get("usage")
                if not isinstance(usage, dict):
                    raise ValueError
                used_in, used_out = usage.get("input_tokens"), usage.get("output_tokens")
                total = usage.get("total_tokens")
                details = usage.get("output_tokens_details") or {}
                if not isinstance(details, dict):
                    raise ValueError
                reasoning = details.get("reasoning_tokens", 0)
                if (
                    type(used_in) is not int
                    or type(used_out) is not int
                    or type(total) is not int
                    or type(reasoning) is not int
                ):
                    raise ValueError
                if (
                    used_in < 1
                    or used_out < 1
                    or total != used_in + used_out
                    or not 0 <= reasoning <= used_out
                ):
                    raise ValueError
                actual = used_in * input_rate + used_out * output_rate
                trace.update(
                    input_tokens=used_in,
                    output_tokens=used_out,
                    reasoning_tokens=reasoning,
                    total_tokens=total,
                )
                if actual > reserve:
                    self.spent_usd += actual - reserve
                    trace["cost_usd"] = actual
                if (
                    used_in > input_bound
                    or used_out > self.max_output_tokens
                    or self.spent_usd > self.max_usd
                ):
                    self._budget_exhausted = True
                    trace["source"] = "budget-rejected"
                    raise BudgetExceeded("Provider usage exceeded the reserved request budget")
                if response.get("status") != "completed" or response.get("error") is not None:
                    raise ValueError
                entries = response.get("output")
                if not isinstance(entries, list) or not all(
                    isinstance(entry, dict) for entry in entries
                ):
                    raise ValueError
                substantive = [entry for entry in entries if entry.get("type") != "reasoning"]
                if len(substantive) != 1:
                    raise ValueError
                entry = substantive[0]
                if named_tools is not None:
                    if (
                        entry.get("type") != "function_call"
                        or entry.get("status", "completed") != "completed"
                        or not isinstance(entry.get("arguments"), str)
                    ):
                        raise ValueError
                    output = self._output(
                        {"tool": entry.get("name"), "arguments": loads_exact(entry["arguments"])},
                        named_tools,
                    )
                elif schema is not None:
                    if (
                        entry.get("type") != "function_call"
                        or entry.get("name") != "emit_result"
                        or entry.get("status", "completed") != "completed"
                        or not isinstance(entry.get("arguments"), str)
                    ):
                        raise ValueError
                    decoded = loads_exact(entry["arguments"])
                    output = self._output(_omit_null_defaults(decoded, schema))
                else:
                    content = entry.get("content")
                    if (
                        entry.get("type") != "message"
                        or entry.get("role", "assistant") != "assistant"
                        or not isinstance(content, list)
                        or len(content) != 1
                        or not isinstance(content[0], dict)
                        or content[0].get("type") != "output_text"
                        or not isinstance(content[0].get("text"), str)
                    ):
                        raise ValueError
                    output = self._output(loads_exact(content[0]["text"]))
                self.spent_usd -= max(Fraction(0), reserve - actual)
                trace["cost_usd"] = actual
                return output
            except LLMOutputError:
                trace["source"] = "output-rejected"
                raise
            except (ValueError, TypeError, KeyError, AttributeError):
                trace["source"] = "output-rejected"
                raise LLMOutputError("Invalid model response; no replay recorded") from None
