"""Analyze a pyan3 dot graph for unreachable production code.

pyan3 cannot trace abstract dispatch, property access, or match-statement
dispatch. This script reports raw unreachable nodes grouped by module so
a human can spot genuine dead code among the structural false positives.
"""

import sys
from collections import defaultdict


def analyze(dot_path: str) -> None:
    nodes: set[str] = set()
    targets: set[str] = set()

    with open(dot_path) as f:
        for line in f:
            line = line.strip()
            if "->" in line:
                dst = line.split("->")[1].split("[")[0].strip().strip('"').rstrip(";")
                targets.add(dst)
            elif "label=" in line and "->" not in line and "graph" not in line:
                node = line.split("[")[0].strip().strip('"').rstrip(";")
                if node:
                    nodes.add(node)

    dead = sorted(nodes - targets)

    by_module: dict[str, list[str]] = defaultdict(list)
    modules = 0
    magic = 0

    for n in dead:
        clean = n.replace("__", ".").replace("dude.", "").lstrip(".")
        parts = clean.rsplit(".", 1)
        method = parts[1] if len(parts) == 2 else ""

        if "." not in clean:
            modules += 1
            continue
        if method.startswith(".") and method.endswith("."):
            magic += 1
            continue

        mod = clean.rsplit(".", 1)[0]
        by_module[mod].append(method or clean)

    total_reported = sum(len(v) for v in by_module.values())
    print(f"{len(nodes)} nodes, {len(targets)} reached, {len(dead)} unreachable raw")
    print(f"  {modules} module entries, {magic} magic methods, {total_reported} reported")
    print()

    for mod in sorted(by_module):
        methods = by_module[mod]
        print(f"  {mod}: {', '.join(methods)}")


if __name__ == "__main__":
    analyze(sys.argv[1] if len(sys.argv) > 1 else "reachability.dot")
