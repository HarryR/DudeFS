"""Analyze a pyan3 dot graph to find production functions with no callers."""

import sys


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

    # False positives: protocols (called via duck typing), magic methods,
    # encode/decode (called via base-class dispatch), entry points, dispatch handlers
    skip = (
        "__",
        "_encode",
        "_decode",
        "cli",
        "main",
        "Substrate.",
        "Reader.",
        "View.",
        "Listener.",
        "Protocol",
        "Authoriser.",
        "_on_",
    )
    real = [n for n in dead if not any(s in n for s in skip)]

    def clean(name: str) -> str:
        return name.replace("__", ".").replace("dude.", "").lstrip(".")

    print(f"{len(nodes)} nodes, {len(targets)} reached, {len(dead)} unreachable raw, {len(real)} after filtering")
    print()
    for n in real:
        print(f"  {clean(n)}")


if __name__ == "__main__":
    analyze(sys.argv[1] if len(sys.argv) > 1 else "reachability.dot")
