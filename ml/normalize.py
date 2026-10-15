"""Turns real Python source into the statement format the locator was trained on (DetectVul style).

DetectVul stores each function as: a header ("def f(a):..." or "@first_decorator..."), then one entry per
statement, unindented, comments dropped; compound statements contribute only their header ("if x:").
Feeding raw source lines instead is a train/inference mismatch, so the scorer converts first.
Parses only (ast), never executes anything.
"""
import ast
import textwrap


def _header(node):
    u = ast.unparse
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        if node.decorator_list:
            return '@' + u(node.decorator_list[0]) + '...'
        prefix = 'async def ' if isinstance(node, ast.AsyncFunctionDef) else 'def '
        return f'{prefix}{node.name}({u(node.args)}):...'
    if isinstance(node, ast.ClassDef):
        return f'class {node.name}:...'
    if isinstance(node, ast.If):
        return f'if {u(node.test)}:'
    if isinstance(node, (ast.For, ast.AsyncFor)):
        return f"{'async ' if isinstance(node, ast.AsyncFor) else ''}for {u(node.target)} in {u(node.iter)}:"
    if isinstance(node, ast.While):
        return f'while {u(node.test)}:'
    if isinstance(node, (ast.With, ast.AsyncWith)):
        return f"{'async ' if isinstance(node, ast.AsyncWith) else ''}with {', '.join(u(i) for i in node.items)}:"
    if isinstance(node, ast.Try) or type(node).__name__ == 'TryStar':
        return 'try:'
    if isinstance(node, ast.ExceptHandler):
        t = f' {u(node.type)}' if node.type else ''
        return f"except{t}{' as ' + node.name if node.name else ''}:"
    if type(node).__name__ == 'Match':
        return f'match {u(node.subject)}:'
    return None


def _walk(stmts, out):
    for s in stmts:
        h = _header(s)
        if h is None:
            out.append((ast.unparse(s) + '\n', s.lineno))
            continue
        out.append((h + '\n', s.lineno))
        if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            _walk(s.body, out)
            continue
        for field in ('body', 'orelse', 'finalbody'):
            _walk(getattr(s, field, []) or [], out)
        for handler in getattr(s, 'handlers', []) or []:
            out.append((_header(handler) + '\n', handler.lineno))
            _walk(handler.body, out)
        for case in getattr(s, 'cases', []) or []:
            _walk(case.body, out)


def statements(source, start_line=1, max_statements=60):
    """Returns [(text, source_line_number)] for one function's source, or None if it does not parse."""
    try:
        tree = ast.parse(textwrap.dedent(source))
    except SyntaxError:
        return None
    fn = next((n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))), None)
    if fn is None:
        return None
    out = [(_header(fn) + '\n', fn.lineno)]
    _walk(fn.body, out)
    return [(text, start_line + line - 1) for text, line in out[:max_statements]]
