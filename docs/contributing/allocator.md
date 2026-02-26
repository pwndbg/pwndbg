# Implementing an Allocator

Implementing support for an allocator is one of the most complex and most useful things you can do in the Pwndbg codebase. Pwndbg currently has support for 4 different allocators: glibc malloc, jemalloc, musl's mallocng and kernel's SLUB allocator. These subsystems take significantly different approaches w.r.t. their implementation, so this document is written to help future implementations take on better designs.

Naturally, contributions that refactor the existing allocators to follow these guidelines are also very welcome. Some of the comparisons to the current implementations may became dated with time, but they should stay for educational purposes (you should add a comment to the relevant section if the comparison is dated).

We sometimes refer to a Pwndbg allocator subsystem as an "allocator inspector" for the given upstream allocator.

## Important considerations

Here are some things you need to keep in mind while designing support for a new allocator, that may not be so obvious initially:

+ It should support both statically and dynamically compiled binaries
+ It should support the allocator implementation having full debug info, having only symbols, and being stripped
+ It should work cross-architecture
+ It should be flexible to changes in new versions of the upstream allocator

## Tight integration with the libc

Often, an allocator implementation is only found in its libc. For instance glibc malloc is found only in glibc, musl's mallocng only in musl. But this is not always the case, for instance jemalloc and scudo are predominantly used with Android's bionic libc, but they also exist as standalone project. Microsoft's mimalloc does not have an associated libc.

So, the glibc malloc code may assume it is running inside glibc, but knowing we are in glibc is not enough to conclude that glibc malloc is being used (as e.g. jemalloc could have been LD_PRELOAD-ed).

If there doesn't exist a LibcProvider for the libc most commonly associated with your allocator, you should implement it. In any case, you should read [implementing libc support](./libc-provider.md) as it covers many important concepts. Add instructions for compiling your allocator/libc to the [Compiling the allocator](#compiling-the-allocator) section of this file / [compiling-the-libc](./libc-provider.md#compiling-the-libc) section of the libc file.

## The commands

### Fundamentally, we are visualizing

The implementation will need to understand all aspects of the allocator's state, but ultimately its purpose is to help the user **visualize**. Thus, great care should be taken to make sure the visualization is nice, useful, and easy to parse.

Use colors, make them meaningful, and have an explicit legend (in the command description or at the start of the command output). Good examples of this are the glibc `vis` command we know and love, mallocng's `ng-vis`:

![](../assets/caps/mallocng-vis.png)

mallocng's `ng-dump`:

![](../assets/caps/mallocng-dump.png)

and SLUB's `slab info`:

![](../assets/caps/slab-info.png)

![](../assets/caps/slab-info-v.png)

### Seeing it for the first time

When writing the commands, you should assume that the user does not know anything about this allocator's internals, but vaguely understands how some allocators work. This is one of the most important things to keep in mind. Don't spare out on proper annotations in the command's outputs.

### Important commands to include

#### explain

Further to the previous point, you should include an "explain" command that gives a rundown of how this allocator works (i.e. it just prints text to the screen). This is not only important for users but also for future contributors who want to touch this allocator's code.

The most important thing is the ASCII diagram (here is `ng-explain`):

![](../assets/caps/mallocng-explain.png)

But absolutely do include further text explanations, and especially clarify the terminology you will be using in the other commands.

#### dump

The most important command by far is a "dump everything" command, analagous to SLUB's `slab info <name-of-cache>` and mallocng's `ng-dump`. For consistency with other allocator implementations, let's always call this command "dump". You may or may not want to show each heap object with this command by default, but there should be a way to do it (like with `slab info -v`). Whatever the default is, print a hint at the bottom to let the user know about the command flag since it is very important.

Yes such a command may print *a lot* of output, but the user can do `| ng-dump | less` or use the terminal's scrollback controls to navigate it. Each object should be at most one line in the printed output. You can also provide an optional argument to facilitate further filtering; `slab info` essentially already does this as you have to provide the name of the slab, `ng-dump` could do this by allowing you to provide the address or index of a metaarea for instance.

#### find

Next, it is crucial to have a command which takes an address and tells the user everything it can figure out about that address. For glibc this is `hi` (heap inspect), for mallocng this is `ng-find`, for SLUB this is `slab contains`. For future consistency, call this command "find". The command must work even if the address if in the middle of the heap object. Here is what `ng-find` looks like:

![](../assets/caps/mallocng-find.png)

It should be used as reference. You don't want too much output, but just enough that it could save another command invocation by the user (which is why it also invokes and prints the output of `ng-slots`). Importantly it must link all the structures associated with this address (so here group address, meta address, and slot start).

#### vis

The bread and butter of heap visualization is `vis`. It allows reasoning easily about what the actual data on the heap looks like, what metadata is where, and how to target it. Let's call this command "vis" (in glibc it's `vis-heap-chunks`, in mallocng it's `mallocng-visualize-slots`, it doesn't really matter what the expansion is as long as the alias is unambiguously `vis`).

The leftmost column shows addresses for easy referencing and copy-pasting, the rightmost column shows ASCII-fied data so it is easier to locate important data, and the middle two columns show the ground truth on what bytes are there. Objects should have clear colored boundaries, and metadata should be highlighted. See the `ng-vis` example above, here is what it looks like for glibc: 

![](../assets/caps/alloc-vis-example.png)

Note that the `<-- tcachebins[0x70][0/1]` is unfathomably useful, include stuff like this in an extra column! Further, we make the realization that often for exploitation, the content in the middle of the heap object is not as important as the start and beginning, so the `set max-visualize-chunk-size 0x50` allows us to cut it out (those are the `...` dots in the image). Similarly, repeated lines are not that important and may be skipped as they are done for `telescope`, but care should be taken that this plays nicely with everything else (for possible pitfalls see #3506).

Every single flag in the `vis-heap-chunks` command has its place and should be carefully studied.

One important thing to realize about `vis-heap-chunks` is that it does not consult the allocator's ground truth for the object coloring. In other words, you may run the command in the middle of some actual heap object, where you crafted fake allocator metadata, and it will color according to this fake, local, allocator metadata. This is immensly useful for exploitation. Whether or not this makes sense depends on a lot on the allocator's design (for instance, our mallocng code does not support this, as the location of the previous and next slot is not determined by the current slots size; they are determined by indexing into the slab).

#### object visualization

The previous three things are truly the most important, but they are also the most complex to implement. To take things further, you should provide the user with a way to visualize the allocator-internal structures. In some cases, this can be fundamentally invaluable, like is the case for our glibc malloc `bins` command. Similarly, there doesn't actually exist a `slot` struct in the mallocng code, so the `ng-slotu` command fills the gap.

![](../assets/caps/mallocng-slotu-good.png)

These comments on the right might seem redundant, but they can be really useful for people to refresh their knowledge on the allocator. Don't be afraid to introduce new terminology, as long as it is explained properly in the "explain" command. The mallocng printing code leverages `pwndbg/lib/pretty_print.py:from_properties()` for object visualization which you are encouraged to use (but if you want to do something else, don't be afraid to).

An important thing to keep in mind here is that the "local view" of the metadata around the given address may not be the same as what the allocator actually sees. But, both can be valuable. You should thus make sure to print both if they differ, and make it clear to the user what is what. Carefully study `pwndbg/commands/mallocng.py:smart_dump_slot()` to understand what I mean. Here are two important examples:

![](../assets/caps/mallocng-slotu-bad.png)

![](../assets/caps/mallocng-slotu-split.png)

You are able to run this command on a stack address, completely out of the heap, and it will give you something sensible. The view "that the allocator actually sees" is essentially given by crawling the allocator state i.e. doing the same thing as the "find" command does, as this can be somewhat slow and unexpected to the user, we provide the "ng-search-on-fail" configuration option which is `True` by default.

An annoyance with the glibc `hi` and `vis` commands is that it is not obvious what exact range they consider to belong to a heap object, and whether the start of the range is the "user start" (the pointer returned by `malloc`) or the "internal start" (the start of that heap objects metadata, which is before the "user start"). To mitigate this in mallocng, we provide `ng-slotu` which expects the "user start", and `ng-slots` which expects the "internal start". Whether this makes sense or not depends on the allocator, but it is something you should definitely consider.

### Use subcommands

Pwndbg supports a bunch of commands. The most straight-forward way for users to discover commands is by browsing the output of the `pwndbg` command. If this output is too cluttered, it will be hard for the user to pick out the commands that are interesting to them. Thus, you shouldn't make the same mistake that `jemalloc` and `mallocng` do and name your commands `ng-slots`, `ns-slotu`, `ng-find`, etc. but rather you should have one base command called `mallocng` and have subcommands: `slots`, `slotu`, `find`, etc. (fixed in #3750). The `slab` command does this properly.

However, you must keep in mind one important thing (that you should be keeping in mind when adding any command really). If you determine that e.g. `jemalloc extent-info` is long to type out, and decide to add a `jemalloc -> je` alias, make sure that you are not overriding a shortened usage of any other important command. Test this by just running `pwndbg> je<enter>` and see if GDB runs some command, or complains about some ambiguity. Two to three letter aliases should be used sparingly.

## Implementation

Now that we understand how the commands should feel, lets go over some tips on implementing them. Your code should go into `pwndbg/aglib/heap/`, see the other allocator implementations there as well.

### Use pwndbg.aglib.structures

You should use the `pwndbg.aglib.structures` API when implementing your allocator. It allows you to load an arbitrary C structure into the debugger, which in turn allows you to read out a C structure from memory and intract with it from your python code. See the `pwndbg/aglib/kernel` subsystem on how to properly do this. The glibc malloc code does not do this and uses the travesty that is `pwndbg/aglib/heap/structs.py`. The mallocng code does not do this but rather does direct memory reads - this is terrible both because it causes unnecessarily bloated code and because it makes it hard to modify if the structs change in a new version of the upstream allocator.

### Comment with links to the source

The allocator subsystems are probably by far the hardest to "jump in" to as they rely on a lot of domain-specific knowledge (i.e. knowledge of the allocator's internals). So, use a *bunch* of comments in your code. Explain what code does, and why you decided to do it in a certain way. Have many links to the original allocator's source (see `pwndbg/aglib/heap/mallocng.py` for an example; there should be more links than that). Use elixir if your project is hosted there, then github, then whatever else (in that order of preference). Make sure your link is pinned to a version/commit. Make sure it points to a specific line of code. Be aware that unofficial mirrors often die and your links can die with them.

### There *will* be version-specific code

so you should embrace it. The upstream allocator will update, maybe the structures in a field look different, maybe the algorithm is slightly different, but it will break our code.

It is thus absolutely necessary to have a function which robustly retrieves the version of the allocator. For the kernel SLUB allocator, this is `pwndbg.aglib.kernel.kversion()` and `.krelease()`, for the other ones this is `pwndbg.libc.version()`.

Then, you can handle changing structs using C macros and `#if`s. See `pwndbg.aglib.kernel.slab.py:kmem_cache_structs()` for an example. You will likely also have some if-statements in the code controlling the logic. If some part of the code is highly dependant on the allocator's version, you may use an abstract class / protocol to handle the dispatch in a cleaner way (unfortunately no allocator does this currently).

Make it clear what versions are supported. Sometimes you get support for newer versions for free, sometimes you don't. The users (and contributors) should be informed on what the oldest and latest version you tested is. We will do two things to facilitate this.

Firstly, in the description of the top-level command of your allocator inspector (in all of the commands if you have multiple of them (use a const variable in this case)), write `"Tested for [2.31, 2.42]."` using whichever version range you actually tested. Then we can bump it when a new version comes out and we test it.

Secondly, when a new version of the allocator breaks something and we fix it, add a note to the [Allocator Changelog](#allocator-changelog) below. It should just be one short bullet point. It will be useful for contributors, but can also give curious users a nice overview of how the allocators evolved. Do add entries for previous versions as well!

### Use debug info if it is present

See [Implementing Libc support#Debug Info](./libc-provider.md#debug-info) for rationale.

The mallocng implementation unfortunately does not do this, the jemalloc implementation unfortunately only does this (i.e. does not support jemalloc without debug info), the glibc implementation handles this pretty cleanly by having one class which uses debug info and one class which uses heuristics.

The kernel code handles this the best, see `pwndbg/aglib/kernel/__init__.py:typeinfo_recovery()`. If debug info is present, we do nothing, otherwise we add the debug info ourselves using the `pwndbg.aglib.structures` API. From then on we can simply safely assume that we "have" debug info. This also allows the user to use the types that we infer (e.g. it allows them to do `print *(struct kmem_cache_node*) <some_addr>` even if they don't have debug info).

### Fail gracefully

Similarly to what the glibc and SLUB code do, if you fail to recover a symbol or type, you will want to raise a `SymbolNotRecoveredError` / `TypeNotRecoveredError` exception and catch it somewhere. Currently, `TypeNotRecoveredError` is caught in the top-level try-except in `pwndbg/commands/__init__.py:CommandObj:__call__()`, and `SymbolNotRecoveredError` is expected to be caught by the heap command (see `pwndbg/commands/__init__.py:_try2run_heap_command()`). We should likely decide on one approach or the other.

The kernel code currently has very aggressive assert's that are caught in bare `except:`s. Don't do this. Only assert for stuff that is strictly the programmer's fault. Don't use bare `except:`s.

### Handling statically compiled binaries

In statically compiled binaries, code that isn't used isn't compiled in. Luckily if malloc is used, all allocator-relevant code must be there, and must be (theoretically) recoverable. But critical stuff like version information usually isn't available in the binary and libc detection is likely to fail.

So, what you will want to do is:

+ Let the user run your command only if `pwndbg.libc.which()` is the appropriate libc or `LibcType.UNKNOWN`.
+ Try `pwndbg.libc.version()` and if it returns `None` ask the user to input the version (e.g. `set glibc 2.42`).
+ Don't rely on any other libc-provider-specific function because you might be talking to the "unknown" implementation which will always say you don't have debug info / you don't have symbols etc. So don't rely on `has_internal_symbols()`, `has_debug_info()`, ...
+ *Do* rely on the non-libc-provider-specific functions like e.g. `filepath()`, `addr()`, `section_by_name()` etc. They will work properly.
+ Maybe you will want to implement your own allocator-specific `has_debug_info()` / `has_internal_symbols()`, or simply peform a type/symbol lookup on everything you try to recover (no code in the codebase currently does this). 

There is an issue open about this: #3745 .

## Allocator Changelog

Inspired by [bata24/gef](https://github.com/bata24/gef)'s `heap -h`. If some compilation options are/aren't supported, write it down.

### glibc malloc

Tested for [???, 2.42\].

+ 2.42: start of changelog (#3272, #3464, #3487)

### kernel SLUB

Tested for [???, 6.18\].

+ 6.18: start of changelog (#3689)

`CONFIG_SLAB_VIRTUAL` support: until the mitigation feature gets accepted into mainline, only the latest patch (currently `mitigation-v4-6.12`) is fully supported. The `slab` commands are not guaranteed to work on older patches because the feature is experimental and may undergo significant changes.

### musl mallocng

Tested for [1.2.1, 1.2.5\].

+ 1.2.1: mallocng imported into the musl codebase. No important changes since.

### jemalloc

Tested for 5.3.0 .

+ 5.3.0: start of changelog

## Compiling the allocator

### Outlinks

For glibc malloc see [compiling glibc](./libc-provider.md#glibc).
For mallocng see [compiling musl](./libc-provider.md#musl).
For SLUB compile the kernel.

### jemalloc

TODO
