# Cross-architecture testing

Sometimes you want to test or play around with architectures that are not your native CPU architecture. Oftentimes we [just want a userspace binary](#just-a-binary) running on the target architecture, though sometimes we want to see how GDB itself behaves on a different host architecture and need [full system emulation](#full-system).

## Just a binary

If you just want to test a userspace binary on a different architecture, but are fine with GDB running on your host architecture, your best bet is qemu-user.

Say for instance, you would like to debug the `tests/library/dbg/tests/test_command_telescope.py` test on aarch64. First we need to compile `tests/binaries/host/telescope_binary.native.c` for aarch64. The easiest way to do this is with zig:
```{.bash .copy}
zig cc tests/binaries/host/telescope_binary.native.c --target=aarch64-linux-musl -o ./tele-aarch64 -static
```
We compile it with `-static` because I don't want to install `/lib/ld-linux-aarch64.so.1` which is required to run `aarch64` binaries on my x86_64 system. We use `-musl` instead of `-gnu` because glibc does not support static linking.

Now, if you have `qemu-user-binfmt` installed, you may be able to run the binary just like that: `./tele-aarch64`, but that includes the whole of QEMU, so we will want to use `qemu-user` explicitly to facilitate sane debugging. In particular run:
```{.bash .copy}
qemu-aarch64 -g 1234 ./tele-aarch64
```
This will wait for GDB to attach on port 1234. Now we can start Pwndbg:
```{.bash .copy}
pwndbg ./tele-aarch64
```
and attach on that port:
```{.bash .copy}
pwndbg> tar rem :1234
# Short for `target remote localhost:1234`
```

And we're debugging an aarch64 binary! Yay!

If you specifically need glibc and/or dynamic linking, you will need to install the appropriate toolchain. On Arch Linux, the relevant packages would for example be `aarch64-linux-gnu-linux-api-headers`, `aarch64-linux-gnu-binutils`, `aarch64-linux-gnu-glibc`, `aarch64-linux-gnu-gcc`, `aarch64-linux-gnu-gdb`, but it may differ for your distro. For installing `qemu-user`, and `zig` you'll also need to consult your package manager, but the package names usually are literarly just `qemu-user` and `zig`.

## Full system

