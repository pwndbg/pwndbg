import gdb, pwndbg

pwndbg.profiling.profiler.start()
result = gdb.execute("vis 2000", to_string=True)
pwndbg.profiling.profiler.stop('profile.prof')

# Save result in case user wants to inspect it
with open("result", "w") as f:
    f.write(result)
