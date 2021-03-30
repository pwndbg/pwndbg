radare2 = {}


def r2pipe(filename):
    r2 = radare2.get(filename)
    if r2:
        return r2
    import r2pipe
    r2 = r2pipe.open(filename)
    radare2[filename] = r2
    r2.cmd("aaaa")
    return r2
