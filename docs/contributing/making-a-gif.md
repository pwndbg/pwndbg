# Making a pwndbg gif

## The rundown

If you wish to make a gif of your terminal while using pwndbg (usually to add an example of some command/workflow to the website) you should use [charmbracelet/vhs](https://github.com/charmbracelet/vhs). This ensures a consistent look to the gifs throughout the documentation, makes them easily updateable when UI changes are made, and just makes them more easily reproducable and modifiable in general.

The workflow to creating a gif is simple. Start a recording:
```{.bash .copy}
vhs record > my_thingy.tape
```
Whatever you now do in the terminal will be "recorded" to the `my_thingy.tape` file. Exit the shell to save the recording. The tape probably isn't ready to use as-is. You will want to add some metadata and fixup some lines.
??? example

    This is the tape used to generate the gif at https://pwndbg.re/ :
    ```bash
    Output my_thingy.gif

    Set FontSize 20
    Set Width 1920
    Set Height 1080
    Set TypingSpeed 100ms

    Sleep 1s
    Type "gdb /bin/sh --quiet"
    Enter
    Sleep 2s
    Type "start"
    Enter
    Sleep 3s
    Type "ni"
    Sleep 2s
    Enter 1
    Sleep 1s
    Enter 1
    Sleep 1s
    Enter 1
    Sleep 1s
    Type "nextcall"
    Sleep 3s
    Enter 1
    Sleep 10s
    Type "b *$rdi"
    Sleep 1s
    Enter 1
    Sleep 2s
    Type "continue"
    Sleep 1s
    Enter 1
    Sleep 4s
    Type "nextcall"
    Sleep 1s
    Enter 1
    Sleep 1s
    Enter 1
    Sleep 1s
    Enter 1
    Sleep 1s
    Enter 1
    Sleep 1s
    Enter 1
    Sleep 1s
    Enter 1
    Sleep 1s
    Type "stepsyscall"
    Sleep 1s
    Enter 1
    Sleep 10s
    Type "checksec"
    Sleep 1s
    Enter 1
    Sleep 5s
    Type "vmmap"
    Sleep 1s
    Enter 1
    Sleep 5s
    Type "exit"
    Sleep 1s
    Enter
    Sleep 2s
    ```

You may now run
```{.bash .copy}
vhs my_thingy.tape
```
and it will generate a gif with the filename you specified in the tape (the `Output` line in the example).

Make sure to commit the `.tape` file along with the gif.

## Recording in Docker

If the setup for the gif is not highly involved, you may want to use a Dockerfile to generate the gif to ensure reproducability (or if wish to make sure your environment variables aren't visible during the debugging session). Here is a sample Dockerfile you can modify to your liking:
```{.Dockerfile .copy}
# https://github.com/charmbracelet/vhs
FROM ghcr.io/charmbracelet/vhs

# Install pwndbg
RUN apt update && apt install -y git \
    && git clone https://github.com/pwndbg/pwndbg.git /pwndbg \
    && cd /pwndbg \
    && ./setup.sh

# Make sure uv.lock.hash is created so we don't get
# a message about updating during the gif.
RUN gdb /bin/sh --batch

# The ENTRYPOINT and CMD are defined in the vhs docker image.
```
you can use a script like this to run it easily.
```{.bash .copy}
#!/bin/sh

set -e

IMAGE_NAME="vhs-pwndbg"

rm -f .gdb_history
docker build -t "$IMAGE_NAME" .
docker run --rm -v "$(pwd)":/vhs "$IMAGE_NAME" my_thingy.tape
```
