"""Shared feature preprocessing. No repository code is executed."""
import hashlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if (ROOT / '.deps').exists():
    sys.path.insert(0, str(ROOT / '.deps'))

LEX = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|/\*.*?\*/|//[^\n]*', re.S)
TOKENS = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[A-Za-z_$][\w$]*|\d+(?:\.\d+)?|[^\s]', re.S)
KEYWORDS = set('if else switch case default for while do try catch finally return throw throws new null true false instanceof synchronized break continue class public private protected static final void int long boolean byte char float double short extends implements this super'.split())
NEGATIVE = 'BENCHMARK_NEGATIVE'

def clean_code(code):
    """Strip comments and identity/route hints, retaining actual code and sink APIs."""
    code = LEX.sub(lambda m: ' ' if m.group().startswith(('/*', '//')) else m.group(), code)
    start = re.search(r'public\s+void\s+doPost\s*\([^)]*\)[^{]*\{', code)
    if start:
        depth = 1
        for token in TOKENS.finditer(code, start.end()):
            if token.group() == '{': depth += 1
            elif token.group() == '}':
                depth -= 1
                if depth == 0:
                    code = code[start.start():token.end()]
                    break
    code = re.sub(r'BenchmarkTest\d+\w*', 'BenchmarkSample', code)
    code = re.sub(r'/(?:sqli|xss|pathtraver|cmdi|hash|crypto|trustbound|weakrand|ldapi|xpathi|securecookie)-\d+[^"\s]*', '/benchmark-route', code, flags=re.I)
    code = re.sub(r'\bCWE[-_ ]?\d+\b', 'CWE', code, flags=re.I)
    return code.strip()

def template_group(code):
    # Abstract ALL identifiers, literals, and numbers. Keep control flow/punctuation:
    # same-shaped servlet templates stay together even across CWE categories.
    abstract = []
    for match in TOKENS.finditer(code):
        token = match.group()
        if token in ('true', 'false'): token = 'BOOLEAN'
        elif token.startswith(('"', "'")): token = 'LITERAL'
        elif re.fullmatch(r'\d+(?:\.\d+)?', token): token = 'NUMBER'
        elif re.fullmatch(r'[A-Za-z_$][\w$]*', token) and token not in KEYWORDS: token = 'IDENT'
        abstract.append(token)
    return hashlib.sha256(' '.join(abstract).encode()).hexdigest()

def predict(code, model, vectorizer, metadata, language='java', expected_cwe=None):
    import numpy as np
    result = {'status':'unknown', 'predicted_category':None, 'cwe':None, 'probability':None,
              'language':language.lower(), 'supported_cwes':metadata['supported_cwes'],
              'scope':'OWASP Benchmark Java only; not a production vulnerability detector'}
    if language.lower() != 'java':
        return {**result, 'reason':'Unsupported language; only Java was evaluated.'}
    if expected_cwe and expected_cwe not in metadata['supported_cwes']:
        return {**result, 'reason':'Requested CWE category was not trained.'}
    cleaned = clean_code(code)
    if len(cleaned) < 25 or not re.search(r'\b(?:class|public|private|protected|String|java|javax|void|new)\b', cleaned):
        return {**result, 'reason':'Insufficient recognizable Java source context.'}
    features = vectorizer.transform([cleaned])
    if features.nnz < 3:
        return {**result, 'reason':'Insufficient vocabulary overlap with training data.'}
    probabilities = model.predict_proba(features)[0]
    index = int(np.argmax(probabilities)); probability = float(probabilities[index])
    if probability < metadata['rejection_threshold']:
        return {**result, 'probability':probability, 'reason':'Low model probability; category unsupported or uncertain.'}
    category = str(model.classes_[index])
    return {**result, 'status':'predicted', 'predicted_category':category,
            'cwe':None if category == NEGATIVE else category, 'probability':probability,
            'note':'Probability is not calibrated. BENCHMARK_NEGATIVE is not a general safety guarantee.'}
