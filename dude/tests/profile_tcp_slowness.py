"""Profile the SQLite read slowness with TCP cluster active.

Generates a cProfile output file that can be viewed with:
    python -m snakeviz /tmp/tcp_slowness.prof
    # or
    python -c "import pstats; p = pstats.Stats('/tmp/tcp_slowness.prof'); p.sort_stats('cumulative'); p.print_stats(30)"

Run:
    python -m dude.tests.profile_tcp_slowness
"""

import cProfile
import os
import pstats
import time

from .cluster import Cluster, TCPFabric


def bench_reads(store, iterations: int = 3):
    for _ in range(iterations):
        mr = store.mgmt_reader
        mr.nodes()
        mr.roster()
        mr.authorized_identities()


def main() -> None:
    print("Starting TCP cluster...", flush=True)
    c = Cluster(nodes=3, mgmt=0, fabric=TCPFabric())
    time.sleep(1)

    store = c.nodes[0].store
    prof_path = "/tmp/tcp_slowness.prof"

    print("Profiling store reads with TCP active...", flush=True)
    profiler = cProfile.Profile()
    profiler.enable()
    t0 = time.monotonic()
    bench_reads(store)
    elapsed = (time.monotonic() - t0) * 1000
    profiler.disable()

    profiler.dump_stats(prof_path)
    print(f"\nWall clock: {elapsed:.0f}ms for 3 iterations ({elapsed/3:.0f}ms each)")
    print(f"Profile saved to {prof_path}")
    print()

    stats = pstats.Stats(profiler)
    stats.sort_stats("cumulative")
    stats.print_stats(30)

    os._exit(0)


if __name__ == "__main__":
    main()
