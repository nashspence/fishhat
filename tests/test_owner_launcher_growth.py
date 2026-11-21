"""Source-level linear-walk proof; no compiler or native program is executed."""

import ast
import re

import pytest
from pycparser import c_ast, c_parser

from scripts.owner_launcher import SOURCE

CHECK_PURPOSE = {
    "purpose": "validation-tooling",
    "authority": ["fishhat/host-ops/launcher/launch.c"],
    "scope": "parsed complete launch control flow: monotone argv/environment/auxiliary-vector walks with constant work per entry and negative proof-checker cases",
    "relationship": "no-product-claim",
    "reason": "The source proof bounds the emitted algorithm; original compiled-output identity and actual complete argv/credential behavior still require enrolled-guest witnesses.",
    "claims": [],
}


def nodes(root, kind):
    result = []

    class Visitor(c_ast.NodeVisitor):
        def generic_visit(self, node):
            if isinstance(node, kind):
                result.append(node)
            super().generic_visit(node)

    Visitor().visit(root)
    return result


def parsed(source):
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.S)
    source = re.sub(r"^\s*#.*$", "", source, flags=re.M)
    entry = re.search(r"__asm__\((.*?)\);", source, re.S)
    assert entry is not None
    instructions = "".join(
        ast.literal_eval(x) for x in re.findall(r'"(?:\\.|[^"\\])*"', entry[1])
    ).splitlines()
    assert instructions == [
        ".global _start",
        ".text",
        "_start:",
        "mov %rsp, %rdi",
        "andq $-16, %rsp",
        "call protected_launch",
        "ud2",
    ]
    source = source[: entry.start()] + source[entry.end() :]
    syscall = re.search(r"__asm__ volatile\((.*?)\);", source, re.S)
    assert syscall is not None and re.findall(r'"(?:\\.|[^"\\])*"', syscall[1])[0] == '"syscall"'
    assert re.match(r'\s*"syscall"\s*:', syscall[1])
    source = source[: syscall.start()] + ";" + source[syscall.end() :]
    source = re.sub(r'__asm__\("r(?:10|8|9)"\)', "", source)
    source = source.replace("__attribute__((noreturn))", "")
    source = re.sub(r"\bOWNER_INTERPRETER\b", '"fixed-interpreter"', source)
    source = re.sub(r"\bOWNER_PROGRAM\b", '"fixed-program"', source)
    return c_parser.CParser().parse(source)


def prove(source):
    tree = parsed(source)
    functions = {node.decl.name: node for node in tree.ext if isinstance(node, c_ast.FuncDef)}
    assert set(functions) == {"kernel", "refuse", "protected_launch"}
    for name in ("kernel", "refuse"):
        assert not nodes(functions[name], (c_ast.For, c_ast.While, c_ast.DoWhile))
    assert not nodes(functions["kernel"], c_ast.FuncCall)
    assert all(
        isinstance(call.name, c_ast.ID) and call.name.name in {"kernel", "__builtin_unreachable"}
        for call in nodes(functions["refuse"], c_ast.FuncCall)
    )
    body = functions["protected_launch"]
    assert not nodes(body, (c_ast.Goto, c_ast.Label))
    assert all(
        isinstance(call.name, c_ast.ID) and call.name.name in {"kernel", "refuse"}
        for call in nodes(body, c_ast.FuncCall)
    )
    loops = nodes(body, (c_ast.For, c_ast.While, c_ast.DoWhile))
    assert len(loops) == 3 and sum(isinstance(loop, c_ast.For) for loop in loops) == 1
    for loop in loops:
        assert not nodes(
            loop.stmt,
            (c_ast.For, c_ast.While, c_ast.DoWhile, c_ast.Goto, c_ast.Break, c_ast.Continue),
        )
        assert all(
            isinstance(call.name, c_ast.ID) and call.name.name == "refuse"
            for call in nodes(loop.stmt, c_ast.FuncCall)
        )
        if isinstance(loop, c_ast.For):
            (declaration,) = loop.init.decls
            cursor = declaration.name
            assert isinstance(declaration.init, c_ast.Constant) and declaration.init.value == "1"
            assert (
                isinstance(loop.cond, c_ast.BinaryOp)
                and loop.cond.op == "<"
                and isinstance(loop.cond.left, c_ast.ID)
                and loop.cond.left.name == cursor
                and isinstance(loop.cond.right, c_ast.ID)
            )
            assert (
                isinstance(loop.next, c_ast.UnaryOp)
                and loop.next.op in {"p++", "++"}
                and loop.next.expr.name == cursor
            )
            assignment = loop.stmt
            assert isinstance(assignment, c_ast.Assignment) and assignment.op == "="
            assert isinstance(assignment.lvalue, c_ast.ArrayRef) and isinstance(
                assignment.rvalue, c_ast.ArrayRef
            )
            assert (
                isinstance(assignment.rvalue.subscript, c_ast.ID)
                and assignment.rvalue.subscript.name == cursor
            )
            assert (
                isinstance(assignment.lvalue.subscript, c_ast.BinaryOp)
                and assignment.lvalue.subscript.op == "+"
                and assignment.lvalue.subscript.left.name == cursor
                and isinstance(assignment.lvalue.subscript.right, c_ast.Constant)
            )
        else:
            condition = loop.cond
            if isinstance(condition, c_ast.UnaryOp):
                assert condition.op == "*" and isinstance(condition.expr, c_ast.ID)
                cursor = condition.expr.name
            else:
                assert (
                    isinstance(condition, c_ast.ArrayRef)
                    and isinstance(condition.subscript, c_ast.Constant)
                    and condition.subscript.value == "0"
                )
                cursor = condition.name.name
            updates = nodes(loop.stmt, (c_ast.Assignment, c_ast.UnaryOp))
            updates = [
                node
                for node in updates
                if (
                    isinstance(node, c_ast.Assignment)
                    and isinstance(node.lvalue, c_ast.ID)
                    and node.lvalue.name == cursor
                )
                or (
                    isinstance(node, c_ast.UnaryOp)
                    and node.op in {"p++", "++", "p--", "--"}
                    and isinstance(node.expr, c_ast.ID)
                    and node.expr.name == cursor
                )
            ]
            (update,) = updates
            if isinstance(update, c_ast.Assignment):
                assert (
                    update.op == "+="
                    and isinstance(update.rvalue, c_ast.Constant)
                    and int(update.rvalue.value) > 0
                )
            else:
                assert update.op in {"p++", "++"}


def test_complete_source_has_only_monotone_linear_walks_and_constant_helpers():
    prove(SOURCE.read_text())


@pytest.mark.parametrize("case", ["nested-rescan", "hidden-call", "reset-cursor"])
def test_source_proof_refuses_repeated_work_and_nonmonotone_walks(case):
    source = SOURCE.read_text()
    if case == "nested-rescan":
        source = source.replace(
            "forwarded[index + 4] = argv[index];",
            "{ for (unsigned long scan=0;scan<argc;scan++) forwarded[index + 4] = argv[index]; }",
        )
    elif case == "hidden-call":
        source = source.replace(
            "forwarded[index + 4] = argv[index];", "forwarded[index + 4] = helper(argv[index]);"
        )
    else:
        source = source.replace(
            "while (*auxiliary)\n        auxiliary++;",
            "while (*auxiliary) { auxiliary = initial; auxiliary++; }",
        )
    with pytest.raises((AssertionError, ValueError)):
        prove(source)
