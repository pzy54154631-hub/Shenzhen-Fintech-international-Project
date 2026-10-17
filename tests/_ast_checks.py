"""Small, conservative AST checks for the repository's safety contracts.

These checks resolve ordinary import aliases, relative imports, literal dynamic
imports, and simple aliases of functions. They are a review guard, not a Python
sandbox; arbitrary computed code requires review and is rejected in the TCB.
"""

import ast
from dataclasses import dataclass
from pathlib import PurePosixPath

CORE = ("corridor.kernel", "corridor.stores", "corridor.schemas", "corridor.crypto")
FORBIDDEN_CORE = tuple(
    f"corridor.{name}" for name in ("agent", "ui", "bench", "eval", "sim", "gateway")
) + (
    "litellm",
    "openai",
    "anthropic",
    "requests",
    "httpx",
    "fastapi",
    "streamlit",
    "socket",
    "urllib",
    "http",
    "asyncio",
    "subprocess",
)
DYNAMIC_LOADERS = {"importlib.import_module", "__import__", "builtins.__import__"}
WALLCLOCK = {
    "datetime.datetime.now",
    "datetime.datetime.utcnow",
    "datetime.datetime.today",
    "datetime.date.today",
    "datetime.now",
    "datetime.utcnow",
    "time.time",
    "time.time_ns",
    "uuid.uuid4",
}


def _within(module: str, prefix: str) -> bool:
    return module == prefix or module.startswith(prefix + ".")


def _relative(name: str, package: str) -> str:
    level = len(name) - len(name.lstrip("."))
    if not level:
        return name
    parts = package.split(".")
    base = parts[: len(parts) - level + 1]
    suffix = name[level:]
    return ".".join(base + ([suffix] if suffix else []))


@dataclass(frozen=True)
class ImportReference:
    name: str | None
    lineno: int


class Analysis:
    def __init__(self, source: str, module: str = "") -> None:
        self.tree = ast.parse(source, filename=module)
        self.module = module
        self.package = module.rpartition(".")[0]
        self.bindings: dict[str, str] = {}
        self.strings: dict[str, str] = {}
        self.imports: list[ImportReference] = []
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                for item in node.names:
                    self.imports.append(ImportReference(item.name, node.lineno))
                    self.bindings[item.asname or item.name.split(".")[0]] = (
                        item.name if item.asname else item.name.split(".")[0]
                    )
            elif isinstance(node, ast.ImportFrom):
                base = _relative("." * node.level + (node.module or ""), self.package)
                self.imports.append(ImportReference(base, node.lineno))
                for item in node.names:
                    name = f"{base}.{item.name}"
                    self.imports.append(ImportReference(name, node.lineno))
                    if item.name == "*":
                        for special in ("import_module", "float", "uuid4", "time"):
                            self.bindings.setdefault(special, f"{base}.{special}")
                    else:
                        self.bindings[item.asname or item.name] = name

        # Iterate simple alias assignments so aliases of aliases are recognized.
        assignments = [node for node in ast.walk(self.tree) if isinstance(node, ast.Assign)]
        for _ in range(len(assignments) + 1):
            changed = False
            for node in assignments:
                for target in node.targets:
                    if not isinstance(target, ast.Name):
                        continue
                    string = self.string(node.value)
                    if string is not None and self.strings.get(target.id) != string:
                        self.strings[target.id] = string
                        changed = True
                    name = self.name(node.value)
                    if name and name != target.id and self.bindings.get(target.id) != name:
                        self.bindings[target.id] = name
                        changed = True
            if not changed:
                break

        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call) and self.name(node.func) in DYNAMIC_LOADERS:
                target = self.string(node.args[0]) if node.args else None
                if target and target.startswith("."):
                    package = self.string(node.args[1]) if len(node.args) > 1 else None
                    for keyword in node.keywords:
                        if keyword.arg == "package":
                            package = self.string(keyword.value)
                    target = _relative(target, package) if package else None
                self.imports.append(ImportReference(target, node.lineno))

    def string(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Name):
            return self.strings.get(node.id)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left, right = self.string(node.left), self.string(node.right)
            if left is not None and right is not None:
                return left + right
        return None

    def name(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return self.bindings.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            base = self.name(node.value)
            return f"{base}.{node.attr}" if base else None
        if isinstance(node, ast.Call):
            function = self.name(node.func)
            if function in {"getattr", "builtins.getattr"} and len(node.args) >= 2:
                base, attr = self.name(node.args[0]), self.string(node.args[1])
                return f"{base}.{attr}" if base and attr else None
            if function in DYNAMIC_LOADERS and node.args:
                return self.string(node.args[0])
        return None


def import_violations(source: str, module: str) -> list[str]:
    analysis = Analysis(source, module)
    core = any(_within(module, prefix) for prefix in CORE)
    independent = any(
        _within(module, f"corridor.eval.{name}") for name in ("mockbank", "reforacle")
    )
    execution_caller = _within(module, "corridor.gateway") or (
        module == "corridor.bench.baseline_exec"
    )
    errors = []
    for reference in analysis.imports:
        name = reference.name
        if name is None:
            forbidden = core or independent
        else:
            forbidden = (
                (core and any(_within(name, prefix) for prefix in FORBIDDEN_CORE))
                or (
                    independent
                    and any(
                        _within(name, prefix)
                        for prefix in (
                            "corridor.kernel",
                            "corridor.stores",
                            "corridor.gateway",
                            "corridor.agent",
                        )
                    )
                )
                or (not execution_caller and _within(name, "corridor.eval.mockbank.exec"))
                or (
                    not _within(module, "corridor.bench")
                    and _within(name, "corridor.bench.baseline_exec")
                )
            )
        if forbidden:
            errors.append(f"{module}:{reference.lineno}: prohibited import {name or '<computed>'}")
    return errors


def float_violations(source: str, filename: str) -> list[str]:
    analysis = Analysis(source)
    errors = []
    for node in ast.walk(analysis.tree):
        literal = isinstance(node, ast.Constant) and isinstance(node.value, float)
        call = isinstance(node, ast.Call) and analysis.name(node.func) in {
            "float",
            "builtins.float",
        }
        if literal or call:
            errors.append(f"{filename}:{node.lineno}: floating-point literal or conversion")
    return errors


def wallclock_violations(source: str, filename: str) -> list[str]:
    analysis = Analysis(source)
    logging_module = PurePosixPath(filename.replace("\\", "/")).name in {"logging.py", "log.py"}
    errors = []
    for node in ast.walk(analysis.tree):
        if not isinstance(node, ast.Call):
            continue
        name = analysis.name(node.func)
        if name in WALLCLOCK and (not logging_module or name == "uuid.uuid4"):
            errors.append(f"{filename}:{node.lineno}: nondeterministic call {name}")
    return errors
