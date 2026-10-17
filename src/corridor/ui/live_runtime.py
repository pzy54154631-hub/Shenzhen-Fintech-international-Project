"""Session-only credentials and operational budgets, separate from synthetic bank time."""

import hmac
import os
import sqlite3
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from fractions import Fraction
from pathlib import Path
from threading import RLock
from time import gmtime, monotonic, strftime

from corridor.agent.llm import BudgetExceeded, LLMClient, LLMConfigurationError
from corridor.schemas.money import fraction_string


class LiveRateLimited(BudgetExceeded):
    """A transient request limit; it does not consume the session call allowance."""


def _operational_day() -> str:
    # Hosting spend uses the real UTC day; synthetic business clocks remain unchanged.
    return strftime("%Y-%m-%d", gmtime())


@dataclass(frozen=True)
class LiveConfig:
    api_key: str = field(default="", repr=False)
    access_code: str = field(default="", repr=False)
    model: str = "gpt-6.1-sol"
    api: str = "responses"
    api_base: str = "https://api.openai.com/v1"
    daily_usd: Fraction = Fraction(5)
    session_calls: int = 40

    @classmethod
    def from_sources(
        cls,
        secrets: Mapping[str, object] | None = None,
        *,
        environ: Mapping[str, str] | None = None,
    ) -> "LiveConfig":
        values: dict[str, object] = dict(os.environ if environ is None else environ)
        values.update(dict(secrets or {}))
        try:
            daily = values.get("LIVE_DAILY_USD", "5")
            calls = values.get("LIVE_SESSION_CALLS", "40")
            if (
                not isinstance(daily, (int, str, Fraction))
                or isinstance(daily, bool)
                or not isinstance(calls, (int, str))
                or isinstance(calls, bool)
            ):
                raise ValueError
            daily_usd, session_calls = Fraction(daily), int(calls)
            if daily_usd < 0 or session_calls < 0:
                raise ValueError
            names = ("LLM_API_KEY", "LIVE_ACCESS_CODE", "LLM_MODEL", "LLM_API", "LLM_API_BASE")
            if any(name in values and not isinstance(values[name], str) for name in names):
                raise ValueError
        except (ValueError, TypeError, ZeroDivisionError, OverflowError):
            raise LLMConfigurationError("Invalid live hosting configuration") from None
        return cls(
            api_key=str(values.get("LLM_API_KEY", "")).strip(),
            access_code=str(values.get("LIVE_ACCESS_CODE", "")),
            model=str(values.get("LLM_MODEL", "gpt-6.1-sol")),
            api=str(values.get("LLM_API", "responses")),
            api_base=str(values.get("LLM_API_BASE", "https://api.openai.com/v1")),
            daily_usd=daily_usd,
            session_calls=session_calls,
        )


class DailyBudget:
    """SQLite serializes reservations across threads and local hosting processes.

    A crash keeps the whole reservation. Only validated provider usage releases
    unused funds; the journal contains operational dates and exact costs only.
    """

    def __init__(
        self, directory: Path, cap: Fraction, *, day: Callable[[], str] = _operational_day
    ):
        self.path = Path(directory) / "live-budget.sqlite3"
        self.cap, self.day = cap, day

    def _connection(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS reservations "
                "(id INTEGER PRIMARY KEY, day TEXT NOT NULL, "
                "usd TEXT NOT NULL, settled INTEGER NOT NULL)"
            )
            return connection
        except sqlite3.Error:
            connection.close()
            raise

    @staticmethod
    def _spent(connection: sqlite3.Connection, day: str) -> Fraction:
        return sum(
            (
                Fraction(row[0])
                for row in connection.execute("SELECT usd FROM reservations WHERE day = ?", (day,))
            ),
            Fraction(0),
        )

    def remaining(self) -> Fraction:
        try:
            connection = self._connection()
            try:
                return max(Fraction(0), self.cap - self._spent(connection, self.day()))
            finally:
                connection.rollback()
                connection.close()
        except (OSError, sqlite3.Error, ValueError, ZeroDivisionError):
            raise BudgetExceeded("Live budget journal is unavailable") from None

    def reserve(self, amount: Fraction) -> Callable[[Fraction], None]:
        if amount <= 0:
            raise BudgetExceeded("Invalid live request reservation")
        try:
            connection = self._connection()
            try:
                day = self.day()
                if self._spent(connection, day) + amount > self.cap:
                    raise BudgetExceeded("Site daily USD budget cannot cover this request")
                cursor = connection.execute(
                    "INSERT INTO reservations(day, usd, settled) VALUES (?, ?, 0)",
                    (day, fraction_string(amount)),
                )
                reservation = cursor.lastrowid
                connection.commit()
            finally:
                connection.close()
        except (OSError, sqlite3.Error, ValueError, ZeroDivisionError):
            raise BudgetExceeded("Live budget journal is unavailable") from None

        def settle(actual: Fraction) -> None:
            try:
                connection = self._connection()
                try:
                    if actual < 0:
                        raise ValueError
                    connection.execute(
                        "UPDATE reservations SET usd = ?, settled = 1 WHERE id = ? AND settled = 0",
                        (fraction_string(actual), reservation),
                    )
                    connection.commit()
                finally:
                    connection.close()
            except (OSError, sqlite3.Error, ValueError, ZeroDivisionError):
                # Failure retains the earlier conservative reservation.
                raise BudgetExceeded("Live budget settlement is unavailable") from None

        return settle


class LiveSession:
    def __init__(
        self,
        config: LiveConfig,
        *,
        journal_dir: Path | None = None,
        monotonic: Callable[[], float] = monotonic,
        day: Callable[[], str] = _operational_day,
    ):
        self.config = config
        self._journal_dir = Path(
            journal_dir
            or os.environ.get("LIVE_JOURNAL_DIR")
            or Path(tempfile.gettempdir()) / "corridor-live-v1"
        )
        self._clock, self._day = monotonic, day
        self._budget = DailyBudget(self._journal_dir, config.daily_usd, day=day)
        self._lock = RLock()
        self._authorized = False
        self._byok = ""
        self._access_failures = 0
        self._next_access = 0
        self._last_request: float | None = None
        self._server_calls = 0
        self._server_spent = Fraction(0)
        self._budget_blocked_day: str | None = None
        self._server_client: LLMClient | None = None
        self._byok_client: LLMClient | None = None

    def refresh_config(self, config: LiveConfig) -> None:
        with self._lock:
            if self.config == config:
                return
            if (self.config.api_key, self.config.access_code) != (
                config.api_key,
                config.access_code,
            ):
                self._authorized = False
            self.config = config
            self._budget = DailyBudget(self._journal_dir, config.daily_usd, day=self._day)
            self._server_client = None

    update_config = refresh_config

    def authorize(self, code: str) -> str:
        with self._lock:
            if not self.config.api_key or not self.config.access_code:
                return "unavailable"
            now = self._clock()
            if now < self._next_access:
                return "throttled"
            matched = hmac.compare_digest(
                code.encode("utf-8"), self.config.access_code.encode("utf-8")
            )
            if matched:
                self._authorized = True
                self._access_failures = 0
                return "accepted"
            self._access_failures += 1
            self._next_access = now + min(60, 2 ** min(self._access_failures, 6))
            return "invalid"

    def set_byok(self, key: str) -> None:
        if not isinstance(key, str) or len(key) > 8192:
            raise LLMConfigurationError("Invalid session credential")
        with self._lock:
            key = key.strip()
            if key != self._byok:
                self._byok = key
                self._byok_client = None

    @property
    def available(self) -> bool:
        return bool(self.snapshot()["available"])

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            byok = bool(self._byok)
            remaining = Fraction(0)
            if not byok and self.config.api_key:
                try:
                    remaining = self._budget.remaining()
                except BudgetExceeded:
                    self._budget_blocked_day = self._day()
            exhausted = not byok and (
                self._server_calls >= self.config.session_calls
                or remaining <= 0
                or self._budget_blocked_day == self._day()
            )
            authorized = byok or bool(
                self.config.api_key and self.config.access_code and self._authorized
            )
            reason = (
                "ready"
                if authorized and not exhausted
                else "missing_credentials"
                if not byok and not self.config.api_key
                else "access_required"
                if not authorized
                else "budget_exhausted"
            )
            client = self._byok_client if byok else self._server_client
            return {
                "available": authorized and not exhausted,
                "reason": reason,
                "source": "byok" if byok else "server",
                "model": "gpt-6.1-sol" if byok else self.config.model,
                "calls_used": client.api_calls
                if byok and client
                else (0 if byok else self._server_calls),
                "calls_remaining": None
                if byok
                else max(0, self.config.session_calls - self._server_calls),
                "spent_usd": fraction_string(
                    client.spent_usd
                    if byok and client
                    else (Fraction(0) if byok else self._server_spent)
                ),
                "daily_remaining_usd": None if byok else fraction_string(remaining),
                "exhausted": exhausted,
            }

    def _reserve_server(self, amount: Fraction, client: LLMClient) -> Callable[[Fraction], None]:
        with self._lock:
            if (
                client is not self._server_client
                or self._byok
                or not self._authorized
                or not self.config.api_key
                or not self.config.access_code
                or not self.available
            ):
                raise BudgetExceeded("Server live access or budget is unavailable")
            now = self._clock()
            if self._last_request is not None and now - self._last_request < 2:
                raise LiveRateLimited("Wait two seconds before another live request")
            try:
                settle = self._budget.reserve(amount)
            except BudgetExceeded:
                self._budget_blocked_day = self._day()
                raise
            self._last_request = now
            self._server_calls += 1
            self._server_spent += amount

        def finish(actual: Fraction) -> None:
            settle(actual)
            with self._lock:
                self._server_spent += actual - amount

        return finish

    def _reserve_byok(self, client: LLMClient) -> Callable[[Fraction], None]:
        with self._lock:
            if not self._byok or client is not self._byok_client:
                raise BudgetExceeded("Session live credential is no longer available")
        return lambda actual: None

    def client(self, *, context_guard: Callable[[object], None] | None = None) -> LLMClient:
        with self._lock:
            if not self.available:
                raise BudgetExceeded("Live mode requires current access and available budget")
            byok = bool(self._byok)
            client = self._byok_client if byok else self._server_client
            if client is None:
                client = LLMClient(
                    mode="live",
                    model="gpt-6.1-sol" if byok else self.config.model,
                    api="responses" if byok else self.config.api,
                    api_key=self._byok if byok else self.config.api_key,
                    api_base="https://api.openai.com/v1" if byok else self.config.api_base,
                    environment={},
                    env_file=None,
                    max_calls=2**31 - 1 if byok else max(1, self.config.session_calls),
                    max_usd="1000000000",
                    max_output_tokens=2048 if (byok or self.config.api == "responses") else 512,
                    context_guard=context_guard,
                )
                client.request_guard = (
                    (lambda amount: self._reserve_byok(client))
                    if byok
                    else lambda amount: self._reserve_server(amount, client)
                )
                if byok:
                    self._byok_client = client
                else:
                    self._server_client = client
            elif context_guard is not None:
                client.context_guard = context_guard
            return client

    make_client = client
