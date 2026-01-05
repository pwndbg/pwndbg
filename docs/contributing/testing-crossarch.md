# Cross-architecture testing

Sometimes you want to test or play around with architectures that are not your native CPU architecture. Oftentimes we [just want a userspace binary](#just-a-binary) running on the target architecture, though sometimes we want to see how GDB itself behaves on a different host architecture and need [full system emulation](#full-system).

## Just a binary

If you just want to test a userspace binary on a different architecture, but are fine with GDB running on your host architecture, your best bet is qemu-user.

Say for instance, you would like to debug the `tests/library/dbg/tests/test_command_telescope.py` test on aarch64. First we need to compile `tests/binaries/host/telescope_binary.native.c` for aarch64. The easiest way to do this is with zig:
```{.bash .copy}
zig cc tests/binaries/host/telescope_binary.native.c \
    --target=aarch64-linux-musl -static \
    -o ./tele-aarch64 
```
We compile it with `-static` because I don't want to install `/lib/ld-linux-aarch64.so.1` which is required to run aarch64 binaries on my x86_64 system. We use `-musl` instead of `-gnu` because glibc does not officially support static linking (and thus zig doesn't allow it).

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

Btw if you need to strip the binary, `strip` won't work, but `llvm-strip` is architecture-agnostic :P

## Full system

We cannot just run a development Dockerfile under `qemu-user` (by leveraging the docker `--platform` flag) because qemu-user does not implement ptrace, and so debugging will not work. We can however, build that docker image using qemu-user, and then run it using qemu-system. The easiest way to do this is with https://github.com/patryk4815/kernel (you will need to install the nix package manager).

Here is an aarch64 example. First we need qemu binfmt rules, you can get this by installing your distro's flavour of `qemu-user-static-binfmt` or by running this:
```{.bash .copy}
docker run --privileged --rm tonistiigi/binfmt --install arm64
```
then we build a aarch64 image from the Pwndbg ubuntu development Dockerfile:
```
docker buildx build \
  --platform linux/arm64 \
  -t pwndbg:aarch64 \
  --load \
  .
```
Now we run the image using qemu-system:
```{.bash .copy}
sudo nix run github:patryk4815/kernel#vm-aarch64-linux \
    --accept-flake-config --extra-experimental-features flakes \
    --extra-experimental-features nix-command \
    -- -i pwndbg:aarch64
```
If you want to use more CPUs, you can pass `--cpus N`. If you have enough RAM you should also consider passing `--runtime tmpfs`. After it has started:
```{.bash .copy}
bash
cd /pwndbg
source /venv/bin/activate
export PWNDBG_NO_AUTOUPDATE=1
pwndbg
```
And you are running pwndbg inside of another architecture!

If you make some changes to Pwndbg on your host machine that you want to be reflected in the guest, you need to exit qemu-system, rebuild the docker image (by rerunning the previously shown command), and rerun the nix command **with the `--refresh` flag**. If you need to communicate with the host from the guest, don't forget that QEMU exposes the host at IP address 10.0.2.2 .
