# musl libraries used by tests

```bash
❯ sha256sum tests/gdb-tests/tests/binaries/musls/1.2.4/lib/*
a99a3b9349cccda16c787626594ca6fc1a1484eb8c5c49889f5345b6ee61840b  tests/gdb-tests/tests/binaries/musls/1.2.4/lib/ld-musl-124-x86_64.so.1
a620bdc6789a0e984340b348095aac566f5351fbdbc5a767ef5a9d2db3bab2d2  tests/gdb-tests/tests/binaries/musls/1.2.4/lib/ld-musl-124-x86_64.so.1.debug
a99a3b9349cccda16c787626594ca6fc1a1484eb8c5c49889f5345b6ee61840b  tests/gdb-tests/tests/binaries/musls/1.2.4/lib/ld-musl-x86_64.so.1
a620bdc6789a0e984340b348095aac566f5351fbdbc5a767ef5a9d2db3bab2d2  tests/gdb-tests/tests/binaries/musls/1.2.4/lib/ld-musl-x86_64.so.1.debug
❯ sha256sum tests/gdb-tests/tests/binaries/musls/1.2.4/usr/lib/*
ffb51a69191a69fc34acaec1003fabe245d8841da7036d124d3445718415f9ea  tests/gdb-tests/tests/binaries/musls/1.2.4/usr/lib/crt1.o
926a46168dbca60732de4b44734512d44dc40bd5886840fafe8ad5ccf80e6507  tests/gdb-tests/tests/binaries/musls/1.2.4/usr/lib/crti.o
cc39e6fde3d1ed27fecec5ebe8ff0349b08cd493e08b8023d5da479c64e9a5a9  tests/gdb-tests/tests/binaries/musls/1.2.4/usr/lib/crtn.o
46f1e3a2447a158922694da4b4bf473449dcd9187bb8eaaf58163f7c6d2179ee  tests/gdb-tests/tests/binaries/musls/1.2.4/usr/lib/rcrt1.o
4c9e7de444013cf04513ef50d2c30c1a682f6c62fe9a5710f2af7d2c75396e94  tests/gdb-tests/tests/binaries/musls/1.2.4/usr/lib/Scrt1.o
```

## Obtaining binaries

You can see which operating systems have what musl versions using [this query](https://pkgs.org/search/?q=musl).

We use the alpine v.3.18 .apk as the base point for getting musl-1.2.4, so it can be manually extracted for verification
if preferred.

```bash
wget https://dl-cdn.alpinelinux.org/alpine/v3.18/main/x86_64/musl-1.2.4-r2.apk
wget https://dl-cdn.alpinelinux.org/alpine/v3.18/main/x86_64/musl-dev-1.2.4-r2.apk
wget https://dl-cdn.alpinelinux.org/alpine/v3.18/main/x86_64/musl-dbg-1.2.4-r2.apk
sha256sum *.apk
21c732ba7b1a7088a85d79a781076e3d5ec41b0bd52933ecb47bcc5804d6f501  musl-1.2.4-r2.apk
7ef08becf7225f2515d045d25082aa9fe00282e1224bc3f816b5062741c958ec  musl-dev-1.2.4-r2.apk
32b9837354e254e06b2f5429f0a9753580614bd0272ad8db0f5798544e20e9a7  musl-dbg-1.2.4-r2.apk
tar -xvzf musl-1.2.4-r2.apk
tar -xvzf musl-dev-1.2.4-r2.apk
tar -xzvf musl-dbg-1.2.4-r2.apk
```

We are interested in the resulting files:

* `lib/*`
* `usr/lib/*`

These are placed into `tests/gdb-tests/tests/binaries/musls/<version>` folders, and adjusted with symlinks of the form
`ld-musl-124-x86_64.so.1` where 124 corresponds to version 1.2.4, so it's easier to find the exact versions.
