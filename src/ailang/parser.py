"""Spanned S-Expression parser (`u64[lo..hi]`, `i64[lo..hi]`, signed literals) + `ModuleProto` bridge."""

from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ailang import ail_agent_pb2 as pb
from ailang.diagnostics import AILCompilerError, Span


@dataclass
class Token:
    text: str
    span: Span


@dataclass
class SNode:
    val: int | str | list[SNode]
    span: Span

    def raw(self) -> Any:
        if isinstance(self.val, list):
            return [x.raw() for x in self.val]
        return self.val


def pretty(node: SNode | Any) -> str:
    raw = node.raw() if isinstance(node, SNode) else node
    if isinstance(raw, list):
        if len(raw) == 3 and raw[0] == "u64_range":
            return f"u64[{pretty(raw[1])}..{pretty(raw[2])}]"
        if len(raw) == 3 and raw[0] == "i64_range":
            return f"i64[{pretty(raw[1])}..{pretty(raw[2])}]"
        return "(" + " ".join(pretty(x) for x in raw) + ")"
    return str(raw)


def _is_int_token(s: str) -> bool:
    if s.isdigit():
        return True
    return len(s) > 1 and s[0] == "-" and s[1:].isdigit()


def tokenize_spanned(src: str) -> list[Token]:
    tokens: list[Token] = []
    for line_idx, raw_line in enumerate(src.splitlines(), start=1):
        line = raw_line.split(";", 1)[0]
        i = 0
        n = len(line)
        while i < n:
            ch = line[i]
            if ch.isspace():
                i += 1
                continue
            if ch in "()[]":
                tokens.append(Token(ch, Span(line_idx, i + 1)))
                i += 1
                continue
            if line[i : i + 2] == "..":
                tokens.append(Token("..", Span(line_idx, i + 1)))
                i += 2
                continue
            start = i
            while i < n and (not line[i].isspace()) and (line[i] not in "()[]") and line[i : i + 2] != "..":
                i += 1
            tokens.append(Token(line[start:i], Span(line_idx, start + 1)))
    return tokens


def _parse_one(tokens: list[Token], pos: int) -> tuple[SNode, int]:
    if pos >= len(tokens):
        sp = tokens[-1].span if tokens else Span(1, 1)
        raise AILCompilerError(pb.E_SYNTAX, pb.STAGE_PARSE, "<module>", "Unexpected end of input", sp)

    tok = tokens[pos]
    if tok.text == "(":
        items: list[SNode] = []
        pos += 1
        while pos < len(tokens) and tokens[pos].text != ")":
            child, pos = _parse_one(tokens, pos)
            items.append(child)
        if pos >= len(tokens):
            raise AILCompilerError(pb.E_SYNTAX, pb.STAGE_PARSE, "<module>", "Unclosed '('", tok.span)
        return SNode(items, tok.span), pos + 1

    if tok.text in (")", "]", ".."):
        raise AILCompilerError(pb.E_SYNTAX, pb.STAGE_PARSE, "<module>", f"Unexpected token '{tok.text}'", tok.span)

    # Refinement type sugar: u64[lo..hi] and i64[lo..hi]
    if tok.text in ("u64", "i64") and pos + 1 < len(tokens) and tokens[pos + 1].text == "[":
        tag = "u64_range" if tok.text == "u64" else "i64_range"
        pos += 2
        lo_node, pos = _parse_one(tokens, pos)
        if pos >= len(tokens) or tokens[pos].text != "..":
            sp = tokens[pos].span if pos < len(tokens) else tok.span
            raise AILCompilerError(pb.E_SYNTAX, pb.STAGE_PARSE, "<module>", f"Expected '..' inside {tok.text}[lo..hi]", sp)
        pos += 1
        hi_node, pos = _parse_one(tokens, pos)
        if pos >= len(tokens) or tokens[pos].text != "]":
            sp = tokens[pos].span if pos < len(tokens) else tok.span
            raise AILCompilerError(pb.E_SYNTAX, pb.STAGE_PARSE, "<module>", f"Expected ']' closing {tok.text}[lo..hi]", sp)
        return SNode([SNode(tag, tok.span), lo_node, hi_node], tok.span), pos + 1

    if _is_int_token(tok.text):
        return SNode(int(tok.text), tok.span), pos + 1

    return SNode(tok.text, tok.span), pos + 1


def parse_source(src: str) -> list[SNode]:
    tokens = tokenize_spanned(src)
    forms: list[SNode] = []
    pos = 0
    while pos < len(tokens):
        node, pos = _parse_one(tokens, pos)
        if not isinstance(node.val, list) or not node.val:
            raise AILCompilerError(pb.E_SYNTAX, pb.STAGE_PARSE, "<module>", "Top-level item must be a declaration list", node.span)
        forms.append(node)
    return forms


def snode_to_proto(node: SNode) -> pb.SExprProto:
    p = pb.SExprProto(span=pb.SourceSpan(line=node.span.line, column=node.span.col))
    if isinstance(node.val, int):
        if node.val >= 0:
            p.u64_lit = node.val
        else:
            p.i64_lit = node.val
    elif isinstance(node.val, str):
        p.symbol = node.val
    else:
        p.list.items.extend(snode_to_proto(ch) for ch in node.val)
    return p


def proto_to_snode(p: pb.SExprProto) -> SNode:
    sp = Span(p.span.line or 1, p.span.column or 1)
    which = p.WhichOneof("node")
    if which == "u64_lit":
        return SNode(int(p.u64_lit), sp)
    if which == "i64_lit":
        return SNode(int(p.i64_lit), sp)
    if which == "symbol":
        return SNode(str(p.symbol), sp)
    return SNode([proto_to_snode(ch) for ch in p.list.items], sp)


def module_to_proto(forms: list[SNode], module_name: str = "main") -> pb.ModuleProto:
    return pb.ModuleProto(
        module_name=module_name,
        declarations=[snode_to_proto(f) for f in forms],
    )


def proto_to_module(mp: pb.ModuleProto) -> list[SNode]:
    return [proto_to_snode(d) for d in mp.declarations]


def load_ail_path(path: Path) -> list[SNode]:
    if path.suffix == ".pb" or path.name.endswith(".ail.pb"):
        mp = pb.ModuleProto()
        mp.ParseFromString(path.read_bytes())
        return proto_to_module(mp)
    return parse_source(path.read_text())
