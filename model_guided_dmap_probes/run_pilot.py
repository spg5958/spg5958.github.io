#!/usr/bin/env python3
"""Run offline pilot and record process resource use (standard library only)."""
import json
from pathlib import Path
import platform
import resource
import sys
from time import perf_counter
from search import main

if __name__ == "__main__":
    started=perf_counter()
    main()
    used=resource.getrusage(resource.RUSAGE_SELF)
    out=Path(__file__).with_name("results")
    if "--output" in sys.argv:
        out=Path(sys.argv[sys.argv.index("--output")+1])
    peak=used.ru_maxrss/(1024*1024 if sys.platform=="darwin" else 1024)
    report={"wall_seconds":round(perf_counter()-started,4),
        "user_cpu_seconds":used.ru_utime,"system_cpu_seconds":used.ru_stime,
        "peak_rss_mib":round(peak,3),"python":platform.python_version(),
        "platform":platform.platform(),"packets_transmitted":0,
        "measurement":"Python process peak RSS; excludes external applications; host is not the user's M2"}
    (out/"resource_usage.json").write_text(json.dumps(report,indent=2))
    print(json.dumps(report))
