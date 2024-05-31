---
title: Pwndbg coding sprints report
date: 2022-08-21
authors: [disconnect3d]
slug: pwndbg-coding-sprints-report
description: >
  Report of the two coding sprints with Pwndbg
---

This blog post is a report of the two coding sprints for the [Pwndbg project](https://github.com/pwndbg/pwndbg) that I organized first on the EuroPython 2022 conference and then, taking inspiration from the previous one, in the Hackerspace Kraków, located in Cracow, Poland.

PS: If you are only looking for a list of things done, scroll down!

<!-- more -->

## Where I got the idea for sprints?

I have recently attended the [EuroPython 2022](https://ep2022.europython.eu) conference and I enjoyed the “sprints” there. In short, a [sprint](https://ep2022.europython.eu/sprints#what-is-a-sprint-) is a semi-organized event, where anyone can announce a project they will be working on and others can join them. This helps both the projects and the event participants to learn about the project and to make first-time contributions. At the EuroPython conference, [there were 16 officially announced projects](https://ep2022.europython.eu/sprints#2022-sprints-listings), but I know that even more projects were being worked on in practice. Of course, other communities or conferences also do this (e.g. [NixCon](https://2022.nixcon.org/#hackday)).

At the EuroPython conference, I announced my own sprint to work on the Pwndbg project that I maintain. Having no expectations, I felt excited when four people showed up to learn something new and hack together on the project. Later, taking inspiration from it, I organized another sprint, this time in Cracow in the local Hackerspace with even a bigger response. Below, you can read a small report on the two sprints that have happened.

## My general idea for a Pwndbg sprint
Pwndbg is written in Python, so on one hand is easy to hack on, but on the other hand it is a plugin for GDB, a console debugger for native programs (e.g. ones written in C, C++, Go or Rust). The general idea of Pwndbg is to alleviate the pain points of working with and improve the UX of GDB when debugging assembly code, reverse engineering a binary or during exploit development.

Since not everyone is familiar with debuggers or the underlyings of programs execution (e.g. assembly code, CPU registers or stack or heap memory) I knew that I had to make some introduction to those concepts and if possible, prepare a list of simple tasks, so that people can get familiar with the codebase and the tool and contribute something.


## EuroPython 2022 sprint

On the first sprint, four people showed up, mostly having no prior experience with the topic. We started with an introduction to what GDB and Pwndbg are and why and when they are useful.

For this, I took a small C program that had a buffer overflow bug:
```c
#include <stdio.h>
#include <string.h>

int main(int argc, char* argv[]) {
    char name[16] = {0};

    // NOTE: We copy the `argv[1]` string which may be of arbitrary length
    // into the `name` buffer which is only of 16-bytes long. Thus, we can
    // overwrite the stack memory of the program past the `name` buffer.
    strcpy(name, argv[1]);

    printf("Hello %s!\n", name);
}
```

Then, after compiling it (`gcc main.c`), we ran the program twice to see that it will crash if we provide a too long string as its argument:

```bash
$ ./a.out Disconnect3d
Hello Disconnect3d!

$ ./a.out Disconnect3d_at_EuroPython
Hello Disconnect3d_at_EuroPython!
*** stack smashing detected ***: <unknown> terminated
Aborted (core dumped)
```

Then, I explained that the "stack smashing detected" we see is the "stack canaries" (also called "stack cookies") exploit mitigation added by compilers. This compiler feature adds a special 8-bytes canary value after the function's local variables located on the stack, so that then a stack frame may look like this:

```
------------------------------   lower addresses
char name[16];                         |
uint8_t canary[8];                     |
void* function_return_address;         V
------------------------------   higher addresses
```

This local stack canary value is then filled in just after the function’s prologue and is verified against a global value before the function returns to see if the stack was not corrupted (starting from the canary). Of course this may not detect all possible stack memory corruptions but it often makes it impossible to exploit a program (e.g. by changing the return address, also located on the stack), knowing just this vulnerability.

The stack canary mitigation can also be disabled. And if it were done (by passing in a `-fno-stack-protector` flag during compilation), we would get a different result when running the resulting program:

```bash
$ gcc -fno-stack-protector buf.c

$ ./a.out Disconnect3d_on_EuroPython
Hello Disconnect3d_on_EuroPython!
Segmentation fault (core dumped)
```

Now, the "stack smashing detected" is gone, but the program still crashed, because we still corrupted a part of its memory that we shouldn't have touched in a way that made the program do illegal things (e.g. accessing unmapped memory).

During the sprint, we also ran a GDB+Pwndbg session to see the exact instructions that placed the canary value on the stack memory, to see that our input string was located just before it and how the canary was checked just before the function was returned.

I am not going to describe all of this here, but you can see some of it in the below asciinema recording.

[![asciicast](https://asciinema.org/a/zuuwfJIZrpu6IjuwWhiNgAdim.svg)](https://asciinema.org/a/zuuwfJIZrpu6IjuwWhiNgAdim)


## Hackerspace Kraków sprint

Since the second sprint was an ad-hoc event, I had to organize it myself. As a member of Hackerspace Kraków, I was able to reserve the hackerspace's softroom, which is a perfect place for people to hack on things using their computers. Then, I advertised the event on the [Hackerspace's mailing list](https://groups.google.com/g/hackerspace-krk/c/MP6mX4I5vXY) and on a few other mediums.

I did not expect many people to come, especially that I advertised the sprint ~2 days before the event.

But... 8 people (!) showed up (excluding me). I prepared a document with some basic information and tasks, which can be found [here](https://hackmd.io/vjfZ4GIYS8eu_j-7q-fkBg) (though, it is in Polish and it was modified during and after the sprint).

I won't lie: most people that came were friends of mine, some of which I play [CTFs](https://en.wikipedia.org/wiki/Capture_the_flag_(cybersecurity)) with. However, not all of them had really used or developed Pwndbg before.

## Accomplishments from the two sprints

On the EP sprint, since we were just a group of four, we focused on small improvements to the codebase. In total, we did the following:
* [reviewed and merged the fs/gs_base fetching improvement PR](https://github.com/pwndbg/pwndbg/pull/1030),
* [pinned the project's dependencies](https://github.com/pwndbg/pwndbg/pull/1033),
* [updated the unicorn dependency version](https://github.com/pwndbg/pwndbg/pull/1034),
* [added a "tip of the day" feature](https://github.com/pwndbg/pwndbg/pull/1036),
* [improved the UX of using Pwndbg within a Python virtual environment](https://github.com/pwndbg/pwndbg/pull/1037),
* and also [worked on enhancing the display of arguments when stopping on a call to the printf functions family](https://github.com/pwndbg/pwndbg/pull/1038).

The last item from the list was the hardest to jump on and it still requires enhancements until it is merged. Nonetheless, all of this was a nice outcome from the whole sprint :).

On the second sprint, while we were a bigger group, we had much more limited time (since instead of having ~8 hours, we had just a few). Anyway, we were able to do the following:

* [Cleanup some code leftover after dropping Python 2 support](https://github.com/pwndbg/pwndbg/pull/1052),
* [Added documentation on how to debug Pwndbg using PyCharm remote debugging](https://github.com/pwndbg/pwndbg/pull/1058),
* Reviewed and merged the PRs that [sets `$base_heap` variable](https://github.com/pwndbg/pwndbg/pull/1051) and [a tip for it](https://github.com/pwndbg/pwndbg/pull/1053), which may be useful for heap exploitation,
* [Fix the X30 register display on AARCH64 targets](https://github.com/pwndbg/pwndbg/pull/1054),
* [Fix `context args` display when PC/IP register pointed to unmapped memory](https://github.com/pwndbg/pwndbg/pull/1055),
* [Fixed the `xor` and `memfrob` commands and added tests for them (! :D)](https://github.com/pwndbg/pwndbg/pull/1057),
* [Worked on adding a way to dump memory that can be copied right away as C or Python code](https://github.com/pwndbg/pwndbg/pull/1056) (this needs to be changed to a command flag),
* Investigated a [potential parsing issue](https://github.com/pwndbg/pwndbg/issues/1050), even looking at GDB's command parsing source code, [implemented potential patch](https://github.com/pwndbg/pwndbg/pull/1062), which only later turned out to be redundant and the issue to be invalid.

## Summary and what's next?

Organizing those sprints helped me to get back to develop the Pwndbg project more and and attract more people to contribute to it. I also think that more conferences should have this kind of attractions (similarly as more conferences should have lightning talk sessions, heh).

Regarding the Pwndbg sprints, I am organizing another one this week in Cracow on Tuesday, so if you live nearby and are interested in learning about Pwndbg or contributing to the project, feel invited! :)

PS: Thanks a lot to [@arturcygan](https://twitter.com/arturcygan) for reviewing this blog post.
