"""Policy visitor checks for attribute, subscript and dynamic-attribute references."""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from qbit_plugin_dl.audit.policy import (
    _DANGEROUS_ATTR_NAMES,
    _DYN_ATTR_FUNCS,
    SEVERITY_FAIL,
    SEVERITY_WARN,
)
from qbit_plugin_dl.audit.report import _attr_chain, _finding, _fold_str
from qbit_plugin_dl.audit.structure import _sink_for_chain

if TYPE_CHECKING:
    pass

class RefChecksMixin:
    """Checks on attribute chains, subscripts and getattr-style access."""

    def visit_Call(self, node: ast.Call) -> None:
        # The call target is judged by _check_call; don't re-flag it as a
        # bare reference when generic_visit walks into it.
        current: ast.AST = node.func
        while True:
            self._judged.add(id(current))
            if not isinstance(current, ast.Attribute):
                break
            current = current.value
        self._check_call(node)
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        self._check_dangerous_subscript(node)
        if isinstance(node.ctx, ast.Load) and self._resolved_chain(node.value) == [
            "sys",
            "modules",
        ]:
            self._fail_sys_modules(node.lineno)
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> None:
        # ``"x" in sys.modules`` is a harmless membership test.
        for op, comparator in zip(node.ops, node.comparators):
            if isinstance(op, (ast.In, ast.NotIn)):
                self._judged.add(id(comparator))
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        self._judged.add(id(node.value))
        if isinstance(node.ctx, ast.Load) and id(node) not in self._judged:
            chain = self._resolved_chain(node)
            sink = _sink_for_chain(chain) if chain else None
            if sink is not None:
                code, label = sink
                self._fail_reference(code, label, node.lineno)
                return
        self.generic_visit(node)

    def _resolved_chain(self, node: ast.AST) -> list[str] | None:
        """Attribute chain with the root import alias expanded (``o.system`` → os)."""
        chain = _attr_chain(node)
        if not chain:
            return None
        origin = self._aliases.get(chain[0])
        if origin is None:
            return chain
        return origin.split(".") + chain[1:]

    def _fail_reference(self, code: str, label: str, lineno: int) -> None:
        if code == "DYN_EXEC":
            self.saw_dyn_exec = True
        self.findings.append(
            _finding(
                code,
                SEVERITY_FAIL,
                f"Reference to {label} at line {lineno} "
                "(aliasing a dangerous callable)",
            )
        )

    def _fail_sys_modules(self, lineno: int) -> None:
        self.findings.append(
            _finding(
                "SYS_MODULES",
                SEVERITY_FAIL,
                f"Module lookup via sys.modules at line {lineno}",
            )
        )

    def _constant_str(self, node: ast.AST | None) -> str | None:
        return _fold_str(node)

    def _check_dangerous_attr_name(self, name: str, lineno: int, *, via: str) -> None:
        if name not in _DANGEROUS_ATTR_NAMES:
            return
        self.findings.append(
            _finding(
                "DYN_ATTR",
                SEVERITY_FAIL,
                f"Dynamic access to dangerous attribute {name!r} via {via} "
                f"at line {lineno}",
            )
        )

    def _check_dangerous_subscript(self, node: ast.Subscript) -> None:
        chain = _attr_chain(node.value)
        if not chain:
            return
        if chain[-1] not in {"__dict__", "__builtins__", "__globals__", "__class__"}:
            return
        slice_node = node.slice
        name = self._constant_str(slice_node)
        if name is None:
            return
        self._check_dangerous_attr_name(
            name,
            node.lineno,
            via=".".join(chain),
        )

    def _check_dyn_attr_call(self, node: ast.Call) -> bool:
        """Block getattr/setattr/… and operator.attrgetter of dangerous names."""
        func = node.func
        lineno = node.lineno

        if isinstance(func, ast.Name) and func.id in _DYN_ATTR_FUNCS:
            # getattr(obj, "system") — name is 2nd arg; vars(obj) alone is warn-free.
            if func.id in {"getattr", "setattr", "delattr"} and len(node.args) >= 2:
                self._check_dyn_attr_name_arg(
                    node.args[1], lineno, via=func.id, receiver=node.args[0]
                )
                return True
            return False

        chain = self._resolved_chain(func)
        if not chain:
            return False
        if chain[0] == "operator" and chain[-1] in {"attrgetter", "methodcaller"}:
            if node.args:
                self._check_dyn_attr_name_arg(
                    node.args[0], lineno, via=".".join(chain), receiver=None
                )
                return True
        if chain[-1] in _DYN_ATTR_FUNCS and len(node.args) >= 2:
            self._check_dyn_attr_name_arg(
                node.args[1], lineno, via=".".join(chain), receiver=node.args[0]
            )
            return True
        return False

    def _check_dyn_attr_name_arg(
        self,
        name_node: ast.AST,
        lineno: int,
        *,
        via: str,
        receiver: ast.AST | None,
    ) -> None:
        name = self._constant_str(name_node)
        if name is not None:
            self._check_dangerous_attr_name(name, lineno, via=via)
            if name not in _DANGEROUS_ATTR_NAMES and receiver is not None:
                # Fully known attribute: the receiver isn't an opaque module ref.
                self._judged.add(id(receiver))
            return
        # Name not statically known. Receivers that are sensitive modules are
        # still caught as MODULE_REF when visited; elsewhere this is unusual.
        self.findings.append(
            _finding(
                "DYN_ATTR_DYNAMIC",
                SEVERITY_WARN,
                f"Attribute name computed at runtime via {via} at line {lineno}",
            )
        )
