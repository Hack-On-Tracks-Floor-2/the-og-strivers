"""Python text features and conservative template grouping; submitted code is never run."""

import ast
import hashlib
import re

NEGATIVE = "BENCHMARK_NEGATIVE"


class _StripBenchmarkMetadata(ast.NodeTransformer):
    def _body(self, node):
        self.generic_visit(node)
        node.body = [
            value for value in node.body
            if not (isinstance(value, ast.Expr) and isinstance(value.value, ast.Constant)
                    and isinstance(value.value.value, str))
        ] or [ast.Pass()]
        return node

    def visit_Module(self, node):
        return self._body(node)

    def visit_FunctionDef(self, node):
        self._body(node)
        if re.match(r"BenchmarkTest\d+", node.name):
            node.name = "benchmark_handler"
            node.decorator_list = []
        return node

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        return self._body(node)

    def visit_Name(self, node):
        node.id = re.sub(r"BenchmarkTest\d+\w*", "benchmark_sample", node.id)
        return node

    def visit_Constant(self, node):
        if isinstance(node.value, str):
            value = re.sub(r"BenchmarkTest\d+\w*", "benchmark_sample", node.value)
            value = re.sub(r"/benchmark/[^\s]*", "/benchmark-route", value)
            value = re.sub(r"\bCWE[-_ ]?\d+\b", "CWE", value, flags=re.I)
            value = re.sub(r"This_should_(?:always|never)_happen", "constant_value", value)
            node.value = value
        return node


def clean_python(code):
    """Remove benchmark scaffolding/comments using parsing, without executing source."""
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError, RecursionError):
        return ""
    post = next((node for node in ast.walk(tree)
                 if isinstance(node, ast.FunctionDef)
                 and re.fullmatch(r"BenchmarkTest\d+_post", node.name)), None)
    if post is not None:
        # GET bootstrap, route decorators and HTML template paths reveal category IDs.
        imports = [node for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom))]
        tree = ast.Module(body=imports + [post], type_ignores=[])
    try:
        cleaned = _StripBenchmarkMetadata().visit(tree)
        ast.fix_missing_locations(cleaned)
        return ast.unparse(cleaned).strip()
    except (ValueError, RecursionError):
        return ""


def _condition_shape(node):
    """Abstract every name, literal and called API; retain only expression operations."""
    if isinstance(node, (ast.Name, ast.Constant, ast.Attribute, ast.Subscript, ast.Call)):
        return "VALUE"
    if isinstance(node, ast.Compare):
        return ["COMPARE", *[type(op).__name__ for op in node.ops]]
    if isinstance(node, ast.BoolOp):
        return [type(node.op).__name__, *[_condition_shape(value) for value in node.values]]
    if isinstance(node, ast.UnaryOp):
        return [type(node.op).__name__, _condition_shape(node.operand)]
    if isinstance(node, ast.BinOp):
        return [type(node.op).__name__, _condition_shape(node.left), _condition_shape(node.right)]
    return type(node).__name__


def _control_family(nodes):
    """Ignore sinks and straight-line statements so broad template relatives stay together."""
    family = []
    for node in nodes:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            family.extend(_control_family(node.body))
        elif isinstance(node, ast.If):
            family.append(["IF", _condition_shape(node.test), _control_family(node.body),
                           _control_family(node.orelse)])
        elif isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
            condition = _condition_shape(node.test) if isinstance(node, ast.While) else "ITERABLE"
            family.append([type(node).__name__, condition, _control_family(node.body),
                           _control_family(node.orelse)])
        elif isinstance(node, (ast.Try, ast.TryStar)):
            # Exception names/API calls are deliberately absent from group identity.
            family.append(["TRY", _control_family(node.body),
                           [_control_family(handler.body) for handler in node.handlers],
                           _control_family(node.orelse), _control_family(node.finalbody)])
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            family.append(["WITH", _control_family(node.body)])
        elif isinstance(node, ast.Match):
            family.append(["MATCH", [_control_family(case.body) for case in node.cases]])
        else:
            # Include expression-level control flow, but no data-flow/sink identities.
            for child in ast.walk(node):
                if isinstance(child, ast.IfExp):
                    family.append(["IFEXPR", _condition_shape(child.test)])
                elif isinstance(child, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                    family.append(["COMPREHENSION", len(child.generators),
                                   [len(generator.ifs) for generator in child.generators]])
    return family


def template_group(code):
    """Control-flow family grouping is deliberately coarser than a normalized AST hash."""
    tree = ast.parse(code)
    # copy is not required by this traversal, but no input tree is ever mutated.
    family = repr(_control_family(tree.body))
    return hashlib.sha256(family.encode("utf-8")).hexdigest()


def predict_python(code, model, vectorizer, metadata):
    """Return an experimental category. Availability/activation is enforced by the router."""
    import numpy as np

    result = {
        "status": "unknown", "predicted_category": None, "cwe": None,
        "probability": None, "language": "python",
        "supported_cwes": metadata["supported_cwes"],
        "scope": "OWASP Benchmark Python v0.1 only; experimental category, never a confirmed vulnerability",
    }
    cleaned = clean_python(code)
    if len(cleaned) < 25 or not re.search(r"\b(?:def|class|import|from|if|return|try)\b", cleaned):
        return {**result, "reason": "Insufficient recognizable Python source context."}
    features = vectorizer.transform([cleaned])
    if features.nnz < 3:
        return {**result, "reason": "Insufficient vocabulary overlap with the training benchmark."}
    probabilities = model.predict_proba(features)[0]
    index = int(np.argmax(probabilities))
    probability = float(probabilities[index])
    if probability < metadata["rejection_threshold"]:
        return {**result, "probability": probability,
                "reason": "Low uncalibrated model probability; unknown category."}
    category = str(model.classes_[index])
    return {**result, "status": "predicted", "predicted_category": category,
            "cwe": None if category == NEGATIVE else category, "probability": probability,
            "note": "Probability is uncalibrated. BENCHMARK_NEGATIVE is not a general safety guarantee."}
