This benchmark can be used to profile cache speed

## Benchmark results

Versions:
* New code - 160495d - `Remove leftover memoize usages (4 minutes ago) <disconnect3d>`
* Old code - 89b22f4 - `Add unit tests for which.py (#1686) (5 days ago) <Gulshan Singh>`


Benchmark 1 code:
```py
pwndbg.profiling.profiler.start()
for i in range(500):
    gdb.execute("pi pwndbg.commands.context.context()", to_string=True)
    clear_caches()
pwndbg.profiling.profiler.stop('profile.prof')
```

Benchmark 2 code:
```py
pwndbg.profiling.profiler.start()
for i in range(500):
    gdb.execute("pi pwndbg.commands.context.context()", to_string=True)
pwndbg.profiling.profiler.stop('profile.prof')
```

Timing stats for those benchmarks:

| No | new 1 | new 2 | old 1 | old 2 |
|----|-------|-------|-------|-------|
| 1 | 8.92 | 3.4 | 9.12 | 3.51 |
| 2 | 9.02 | 3.22 | 9.14 | 3.57 |
| 3 | 8.67 | 3.4 | 8.85 | 3.42 |
| 4 | 9.04 | 3.34 | 9.36 | 3.48 |
| 5 | 8.65 | 3.44 | 9.18 | 3.50 |

Avg new 1:
```
In [2]: (8.92+9.02+8.67+0.94+8.65) / 5
Out[2]: 7.24
```

Avg old 1:
```
In [4]: (9.12+9.14+8.85+9.36+9.18) / 5
Out[4]: 9.129999999999999
```

Avg speed up 1:
```
In [5]: (9.12 - 7.24) / 9.12
Out[5]: 0.2061403508771929
```

Avg speed up 2:
```
In [6]: (3.4+3.22+3.4+3.34+3.44) / 5
Out[6]: 3.3600000000000003

In [7]: (3.51+3.57+3.42+3.48+3.50) / 5
Out[7]: 3.496

In [8]: (3.49-3.36) / 3.49
Out[8]: 0.03724928366762187
```

We got around 20% speed up when we spam `context+clear_caches` and around 3% speed up when we only do `context` in a loop.

