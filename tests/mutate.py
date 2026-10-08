#!/usr/bin/env python3
"""Mutation testing: the positive control for the test-suite.

For each mutant of the verifier sources the whole test-suite runs in an
isolated copy of the repository; a mutant is KILLED when at least one test
fails, SURVIVED otherwise.  A surviving mutant is either an equivalent
mutation (same behaviour) or a hole in the tests, and each one is classified
by hand in tests/MUTATION.md.

Operators (AST level, Python >= 3.9 for ast.unparse):
  drop-fail     a ``rep.fail(...)`` / ``problems.append(...)`` statement -> ``pass``
  cmp           == <-> !=, < <-> <=, > <-> >=, in <-> not in, is <-> is not
  bool          and <-> or
  not           ``not x`` -> ``x``
  anyall        any(...) <-> all(...)
  const         small integer constants +1; True <-> False

Usage: python3 tests/mutate.py [--module verifier,strict_json,...] [--jobs N] [--out report.json]
"""

from __future__ import annotations

import argparse
import ast
import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PKG = os.path.join(ROOT, "aee_verifier")

CMP_SWAP = {ast.Eq: ast.NotEq, ast.NotEq: ast.Eq, ast.Lt: ast.LtE, ast.LtE: ast.Lt,
            ast.Gt: ast.GtE, ast.GtE: ast.Gt, ast.In: ast.NotIn, ast.NotIn: ast.In,
            ast.Is: ast.IsNot, ast.IsNot: ast.Is}


class Site:
    def __init__(self, op: str, node_path: list, describe: str):
        self.op = op
        self.path = node_path
        self.describe = describe


def _walk_with_paths(node, path=()):
    yield node, path
    for field, value in ast.iter_fields(node):
        if isinstance(value, list):
            for i, item in enumerate(value):
                if isinstance(item, ast.AST):
                    yield from _walk_with_paths(item, path + ((field, i),))
        elif isinstance(value, ast.AST):
            yield from _walk_with_paths(value, path + ((field, None),))


def _get(node, path):
    for field, idx in path:
        node = getattr(node, field)
        if idx is not None:
            node = node[idx]
    return node


def _set(root, path, new):
    parent = _get(root, path[:-1])
    field, idx = path[-1]
    if idx is None:
        setattr(parent, field, new)
    else:
        getattr(parent, field)[idx] = new


def find_sites(tree) -> list:
    sites = []
    for node, path in _walk_with_paths(tree):
        line = getattr(node, "lineno", "?")
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            f = node.value.func
            name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")
            if name in ("fail", "append") and isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id in ("rep", "problems"):
                sites.append(Site("drop-fail", path, "L%s drop %s.%s(...)" % (line, f.value.id, name)))
        elif isinstance(node, ast.Compare) and len(node.ops) == 1 and type(node.ops[0]) in CMP_SWAP:
            sites.append(Site("cmp", path, "L%s %s -> %s" % (line, type(node.ops[0]).__name__, CMP_SWAP[type(node.ops[0])].__name__)))
        elif isinstance(node, ast.BoolOp):
            sites.append(Site("bool", path, "L%s %s" % (line, "and->or" if isinstance(node.op, ast.And) else "or->and")))
        elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            sites.append(Site("not", path, "L%s drop not" % line))
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in ("any", "all"):
            sites.append(Site("anyall", path, "L%s %s" % (line, "any->all" if node.func.id == "any" else "all->any")))
        elif isinstance(node, ast.Constant) and isinstance(node.value, bool):
            sites.append(Site("const", path, "L%s %r -> %r" % (line, node.value, not node.value)))
        elif isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool) and 0 <= node.value <= 130:
            sites.append(Site("const", path, "L%s %d -> %d" % (line, node.value, node.value + 1)))
    return sites


def apply(tree, site: Site):
    tree = copy.deepcopy(tree)
    node = _get(tree, site.path)
    if site.op == "drop-fail":
        _set(tree, site.path, ast.Pass())
    elif site.op == "cmp":
        node.ops = [CMP_SWAP[type(node.ops[0])]()]
    elif site.op == "bool":
        node.op = ast.Or() if isinstance(node.op, ast.And) else ast.And()
    elif site.op == "not":
        _set(tree, site.path, node.operand)
    elif site.op == "anyall":
        node.func.id = "all" if node.func.id == "any" else "any"
    elif site.op == "const":
        node.value = (not node.value) if isinstance(node.value, bool) else node.value + 1
    ast.fix_missing_locations(tree)
    return tree


def run_mutant(idx: int, module: str, source: str, workdir: str, python: str, timeout: int) -> dict:
    mdir = os.path.join(workdir, "m%04d" % idx)
    shutil.copytree(ROOT, mdir, ignore=shutil.ignore_patterns(".git", "__pycache__", ".mutants", "spec"))
    with open(os.path.join(mdir, "aee_verifier", module + ".py"), "w") as fh:
        fh.write(source)
    t0 = time.time()
    try:
        proc = subprocess.run([python, "-m", "unittest", "discover", "-s", os.path.join(mdir, "tests"), "-p", "test_*.py"], cwd=mdir,
                              stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=timeout)
        rc = proc.returncode
        tail = proc.stderr.decode(errors="replace").strip().splitlines()[-1:] or [""]
    except subprocess.TimeoutExpired:
        rc, tail = -1, ["TIMEOUT"]
    shutil.rmtree(mdir, ignore_errors=True)
    return {"rc": rc, "status": "survived" if rc == 0 else "killed", "seconds": round(time.time() - t0, 1), "tail": tail[0][:120]}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--module", default="verifier")
    ap.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) // 2))
    ap.add_argument("--timeout", type=int, default=120)
    ap.add_argument("--out", default=None)
    ap.add_argument("--python", default=sys.executable)
    ap.add_argument("--only", default=None, help="comma-separated operators")
    args = ap.parse_args()

    # positive control of the harness itself: the unmutated suite must pass
    proc = subprocess.run([args.python, "-m", "unittest", "discover", "-s", os.path.join(ROOT, "tests"), "-p", "test_*.py"], cwd=ROOT,
                          stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    if proc.returncode != 0:
        print("baseline test-suite FAILS; refusing to measure mutants", file=sys.stderr)
        return 2

    results = {}
    workdir = tempfile.mkdtemp(prefix="aee-mutants-")
    try:
        for module in args.module.split(","):
            with open(os.path.join(PKG, module + ".py")) as fh:
                src = fh.read()
            tree = ast.parse(src)
            sites = find_sites(tree)
            if args.only:
                sites = [s for s in sites if s.op in args.only.split(",")]
            print("%s: %d mutation sites, %d jobs" % (module, len(sites), args.jobs), flush=True)
            mutants = []
            for i, site in enumerate(sites):
                try:
                    msrc = ast.unparse(apply(tree, site))
                except Exception as exc:  # unparse failure -> skip
                    results["%s#%d" % (module, i)] = {"status": "skipped", "describe": site.describe, "error": str(exc)}
                    continue
                if msrc == ast.unparse(tree):
                    results["%s#%d" % (module, i)] = {"status": "noop", "describe": site.describe}
                    continue
                mutants.append((i, site, msrc))
            with ThreadPoolExecutor(max_workers=args.jobs) as ex:
                futs = {ex.submit(run_mutant, i, module, msrc, workdir, args.python, args.timeout): (i, site) for i, site, msrc in mutants}
                done = 0
                for fut in futs:
                    i, site = futs[fut]
                    r = fut.result()
                    r["describe"] = site.describe
                    r["op"] = site.op
                    results["%s#%d" % (module, i)] = r
                    done += 1
                    if r["status"] != "killed":
                        print("  SURVIVED %s#%d %s" % (module, i, site.describe), flush=True)
                    if done % 25 == 0:
                        print("  ... %d/%d" % (done, len(mutants)), flush=True)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    killed = sum(1 for r in results.values() if r["status"] == "killed")
    survived = sum(1 for r in results.values() if r["status"] == "survived")
    other = len(results) - killed - survived
    print("killed %d / survived %d / other %d (noop or skipped)" % (killed, survived, other))
    if args.out:
        with open(args.out, "w") as fh:
            json.dump(results, fh, indent=1, sort_keys=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
