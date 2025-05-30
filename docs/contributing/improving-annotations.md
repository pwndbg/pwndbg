# Improving Annotations

Alongside the disassembled instructions in the dashboard, Pwndbg also has the ability to display annotations - text that contains relevent information regarding the execution of the instruction. For example, on the x86 `MOV` instruction, we can display the concrete value that gets placed into the destination register. Likewise, we can indicate the results of mathematical operations and memory accesses. The annotation in question is always dependent on the exact instruction being annotated - we handle it in a case-by-case basis.

The main hurdle in providing annotations is determining what each instruction does, getting the relevent CPU registers and memory that are accessed, and then resolving concrete values of the operands. We call the process of determining this information "enhancement", as we enhance the information provided natively by GDB.

The Capstone Engine disassembly framework is used to statically determine information about instructions and their operands. Take the x86 instruction `sub rax, rdx`. Given the raw bytes of the machine instructions, Capstone creates an object that provides an API that, among many things, exposes the names of the operands and the fact that they are both 8-byte wide registers. It provides all the information necessary to describe each operand. It also tells the general 'group' that a instruction belongs to, like if its a JUMP-like instruction, a RET, or a CALL. These groups are architecture agnostic.

However, the Capstone Engine doesn't fill in concrete values that those registers take on. It has no way of knowing the value in `rdx`, nor can it actually read from memory.

To determine the actual values that the operands take on, and to determine the results of executing an instruction, we use the Unicorn Engine, a CPU emulator framework. The emulator has its own internal CPU register set and memory pages that mirror that of the host process, and it can execute instructions to mutate its internal state. Note that the Unicorn Engine cannot execute syscalls - it doesn't have knowledge of a kernel.

We have the ability to single-step the emulator - tell it to execute the instruction at the program counter inside the emulator. After doing so, we can inspect the state of the emulator - read from its registers and memory. The Unicorn Engine itself doesn't expose information regarding what each instruction is doing - what is the instruction (is it an `add`, `mov`, `push`?) and what registers/memory locations is it reading to and writing from? - which is why we use the Capstone engine to statically determine this information.

Using what we know about the instruction based on the Capstone engine - such as that it was a `sub` instruction and `rax` was written to - we query the emulator after stepping in to determine the results of the instruction.

We also read the program counter from the emulator to determine jumps and so we can display the instructions that will actually be executed, as opposed to displaying the instructions that follow consecutively in memory.

## Enhancing

Everytime the inferior process stops (and when the `disasm` context section is displayed), we display the next handful of assembly instructions in the dashboard so the user can understand where the process is headed. The exact amount is determined by the `context-disasm-lines` setting.

We will be enhancing the instruction at the current program counter, as well as all the future instructions that are displayed. The end result of enhancement is that we get a list of `PwndbgInstruction` objects, each encapsulating relevent information regarding the instructions execution.

When the process stops, we instantiate the emulator from scratch. We copy all the registers from the host process into the emulator. For performance purposes, we register a handler to the Unicorn Engine to lazily map memory pages from the host to the emulator when they are accessed (a page fault from within the emulator), instead of immediately copying all the memory from the host to the emulator.

The enhancement is broken into a couple stops:

1. First, we resolve the values of all the operands of the instruction before stepping the emulator. This means we read values from registers and dereference memory depending on the operand type. This gives us the values of operands before the instruction executes.
2. Then, we step the emulator, executing a single instruction.
3. We resolve the values of all operands again, giving us the `after_value` of each operand.
4. Then, we enhance the "condition" field of PwndbgInstructions, where we determine if the instruction is conditional (conditional branch or conditional mov are common) and if the action is taken.
5. We then determine the `next` and `target` fields of PwndbgInstructions. `next` is the address that the program counter will take on after using the GDB command `nexti`, and `target` indicates the target address of branch/jump/PC-changing instructions.
6. With all this information determined, we now effectively have a big switch statement, matching on the instruction type, where we set the `annotation` string value, which is the text that will be printed alongside the instruction in question.

We go through the enhancement process for the instruction at the program counter and then ensuing handful of instructions that are shown in the dashboard.

## When to use emulation / reasoning about process state

When possible, we code aims to use emulation as little as possible. If there is information that can be determined statically or without the emulator, then we try to avoid emulation. This is so we can display annotations even when the Unicorn Engine is disabled. For example, say we come to a stop, and are faced with enhancing the following three instructions in the dashboard:

```asm
1.     lea    rax, [rip + 0xd55]
2. >   mov    rsi, rax      # The host process program counter is here
3.     mov    rax, rsi
```

Instruction 1, the `lea` instruction, is already in the past - we pull our enhanced PwndbgInstruction for it from a cache.

Instruction 2, the first `mov` instruction, is where the host process program counter is at. If we did `stepi` in GDB, this instruction would be executed. In this case, there is two ways we can determine the value that gets written to `rsi`.

1. After stepping the emulator, read from the emulators `rsi` register.
2. Given the context of the instruction, we know the value in `rsi` will come from `rax`. We can just read the `rax` register from the host. This avoids emulation.

The decision on which option to take is implemented in the annotation handler for the specific instruction. When possible, we have a preference for the second option, because it makes the annotations work even when emulation is off.

The reason we could do the second option, in this case, is because we could reason about the process state at the time this instruction would execute. This instruction is about to be executed (`Program PC == instruction.address`). We can safely read from `rax` from the host, knowing that the value we get is the true value it takes on when the instruction will execute. It must - there are no instructions in-between that could have mutated `rax`.

However, this will not be the case while enhancing instruction 3 while we are paused at instruction 2. This instruction is in the future, and without emulation, we cannot safely reason about the operands in question. It is reading from `rsi`, which might be mutated from the current value that `rsi` has in the stopped process (and in this case, we happen to know that it will be mutated). We must use emulation to determine the `before_value` of `rsi` in this case, and can't just read from the host processes register set. This principle applies in general - future instructions must be emulated to be fully annotated. When emulation is disable, the annotations are not as detailed since we can't fully reason about process state for future instructions.

## What if the emulator fails?

It is possible for the emulator to fail to execute an instruction - either due to a restrictions in the engine itself, or the instruction inside segfaults and cannot continue. If the Unicorn Engine fails, there is no real way we can recover. When this happens, we simply stop emulating for the current step, and we try again the next time the process stops when we instantiate the emulator from scratch again.

## Caching annotations

When we are stepping through the emulator, we want to remember the annotations of the past couple instructions. We don't want to `nexti`, and suddenly have the annotation of the previously executed instruction deleted. At the same time, we also never want stale annotations that might result from coming back to point in the program to which we have stepped before, such as the middle of a loop via a breakpoint.

New annotations are only created when the process stops, and we create annotations for next handful of instructions to be executed. If we `continue` in GDB and stop at a breakpoint, we don't want annotations to appear behind the PC that are from a previous time we were near the location in question. To avoid stale annotations while still remembering them when stepping, we have a simple caching method:

While we are doing our enhancement, we create a list containing the addresses of the future instructions that are displayed.

For example, say we have the following instructions with the first number being the memory address:

```gdb
   0x555555556259 <main+553>    lea    rax, [rsp + 0x90]
   0x555555556261 <main+561>    mov    edi, 1                          EDI => 1
   0x555555556266 <main+566>    mov    rsi, rax
   0x555555556269 <main+569>    mov    qword ptr [rsp + 0x78], rax
   0x55555555626e <main+574>    call   qword ptr [rip + 0x6d6c]    <fstat64>

 ► 0x555555556274 <main+580>    mov    edx, 5                  EDX => 5
   0x555555556279 <main+585>    lea    rsi, [rip + 0x3f30]     RSI => 0x55555555a1b0 ◂— 'standard output'
   0x555555556280 <main+592>    test   eax, eax
   0x555555556282 <main+594>    js     main+3784                   <main+3784>

   0x555555556288 <main+600>    mov    rsi, qword ptr [rsp + 0xc8]
   0x555555556290 <main+608>    mov    edi, dword ptr [rsp + 0xa8]
```

In this case, our `next_addresses_cache` would be `[0x555555556279, 0x555555556280, 0x555555556282, 0x555555556288, 0x555555556290]`.

Then, the next time our program comes to a stop (after using `si`, `n`, or any GDB command that continues the process), we immediately check if the current program counter is in this list. If it is, then we can infer that the annotations are still valid, as the program has only executed a couple instructions. In all other cases, we delete our cache of annotated instructions.

We might think "why not just check if it's the next address - 0x555555556279 in this case? Why a list of the next couple addresses?". This is because when source code is available, `step` and `next` often skip a couple instructions. It would be jarring to remove the annotations in this case. Likewise, this method has the added benefit that if we stop somewhere, and there happens to be a breakpoint only a couple instructions in front of us that we `continue` to, then previous couple annotations won't be wiped.

## Other random annotation details

- We don't emulate through CALL instructions. This is because the function might be very long.
- We resolve symbols during the enhancement stage for operand values.
- The folder [`pwndbg/aglib/disasm`](https://github.com/pwndbg/pwndbg/tree/dev/pwndbg/aglib/disasm) contains the code for enhancement. It follows an object-oriented model, with `arch.py` implementing the parent class with shared functionality, and the per-architecture implementations are implemented as subclasses in their own files.
- `pwndbg/aglib/nearpc.py` is responsible for getting the list of enhanced PwndbgInstruction objects and converting them to the output seen in the 'disasm' view of the dashboard.

## Adding or fixing annotations

We annotate on an instruction-by-instruction basis. Effectively, imagine a giant `switch` statement that selects the correct handler to create an annotation based on the specific instruction. Many instruction types can be grouped and annotated using the same logic, such as `load`, `store`, and `arithmetic` instructions.

See [`pwndbg/aglib/disasm/aarch64.py`](https://github.com/pwndbg/pwndbg/tree/dev/pwndbg/aglib/disasm/aarch64.py) as an example. We define sets that group instructions using the unique Capstone ID for each instruction, and inside the constructor of `DisassemblyAssistant` we have a mapping of instructions to a specific handler. The `_set_annotation_string` function will match the instruction to the correct handler, which set the `instruction.annotation` field.

If there is a bug in an annotation, the first order of business is finding its annotation handler. To track down where we are handling the instruction, you can search for its Capstone constant. For example, the RISC-V store byte instruction, `sb`, is represented as the Capstone constant `RISCV_INS_SB`. Or, if you are looking for the handler for the AArch64 instruction SUB, you can search the disasm code for `_INS_SUB` to find where we reference the appropriate Capstone constant for the instruction and following the code to the function that ultimately sets the annotation.

If an annotation is causing a crash, is it most likely due to a handler making an incorrect assumption on the number of operands, leading to a `list index out of range` error. One possible source of this is that a given instruction has multiple different disassembly representations. Take the RISC-V `JALR` instruction. It can be represented in 3 ways:

```asm
jalr rs1        # return register is implied as ra, and imm is implied as 0
jalr rs1, imm   # return register is implied as ra
jalr rd, rs1, imm
```

Capstone will expose the most "simplified" one possible, and the underlying list of register operands will change. If the handler doesn't take these different options into account, and rather assumes that `jalr` always has 3 operands, then an index error can occur if the handler accesses `instruction.operands[2]`.

## Bug root cause

When encountering an instruction that is behaving strangely (incorrect annotation, or there is a jump target when one shouldn't exist, or the target is incorrect), there are a couple routine things to check.

1\. Use the `dev-dump-instruction` command to print all the enhancement information. With no arguments, it will dump the info from the instruction at the current address. If given an address, it will pull from the instruction cache at the corresponding location.

If the issue is not related to branches, check the operands and the resolved values for registers and memory accesses. Verify that the values are correct - are the resolved memory locations correct? Step past the instruction and use instructions like `telescope` and `regs` to read memory and verify if the claim that the annotation is making is correct. For things like memory operands, you can try to look around the resolved memory location in memory to see the actual value that the instruction dereferenced, and see if the resolved memory location is simply off by a couple bytes.

Example output of dumping a `mov` instruction:

```
mov qword ptr [rsp], rsi at 0x55555555706c (size=4) (arch: x86)
        ID: 460, mov
        Raw asm: mov    qword ptr [rsp], rsi
        New asm: mov    qword ptr [rsp], rsi
        Next: 0x555555557070
        Target: 0x555555557070, Target string=, const=None
        Condition: UNDETERMINED
        Groups: []
        Annotation: [0x7fffffffe000] => 0x7fffffffe248 —▸ 0x7fffffffe618 ◂— '/usr/bin/ls'
        Operands: [['[0x7fffffffe000]': Symbol: None, Before: 0x7fffffffe000, After: 0x7fffffffe000, type=CS_OP_MEM, size=8, access=CS_AC_WRITE]] ['RSI': Symbol: None, Before: 0x7fffffffe248, After: 0x7fffffffe248, type=CS_OP_REG, size=8, access=CS_AC_READ]]]
        Conditional jump: False. Taken: False
        Unconditional jump: False
        Declare unconditional: None
        Can change PC: False
        Syscall:  N/A
        Causes Delay slot: False
        Split: NO_SPLIT
        Call-like: False
```

2\. Use the Capstone disassembler to verify the number of operands the instruction groups.

Taken the raw instruction bytes and pass them to `cstool` to see the information that we are working with:

```sh
cstool -d mips 0x0400000c
```

The number of operands may not match the visual appearance. You might also check the instruction groups, and verify that an instruction that we might consider a `call` has the Capstone `call` group. Capstone is not 100% correct in every single case in all architectures, so it's good to verify. Report a bug to Capstone if there appears to be an error, and in the meanwhile we can create a fix in Pwndbg to work around the current behavior.

3\. Check the state of the emulator.

Go to [pwndbg/emu/emulator.py](https://github.com/pwndbg/pwndbg/tree/dev/pwndbg/emu/emulator.py) and uncomment the `DEBUG = -1` line. This will enable verbose debug printing. The emulator will print it's current `pc` at every step, and indicate important events, like memory mappings. Likewise, in [pwndbg/aglib/disasm/arch.py](https://github.com/pwndbg/pwndbg/tree/dev/pwndbg/aglib/disasm/arch.py) you can set `DEBUG_ENHANCEMENT = True` to print register accesses to verify they are sane values.

Potential bugs:

- A register is 0 (may also be the source of a Unicorn segfault if used as a memory operand) - often means we are not copying the host processes register into the emulator. By default, we map register by name - if in Pwndbg, it's called `rax`, then we find the UC constant named `U.x86_const.UC_X86_REG_RAX`. Sometimes, this default mapping doesn't work, sometimes do to differences in underscores (`FSBASE` vs `FS_BASE`). In these cases, we have to manually add the mapping.
- Unexpected crash - the instruction at hand might require a 'coprocessor', or some information that is unavailable to Unicorn (it's QEMU under the hood).
- Instructions are just no executing - we've seen this in the case of Arm Thumb instructions. There might be some specific API/way to invoke the emulator that is required for a certain processor state.

## Creating small cross-architecture programs

If you are encountering a strange behavior with a certain instruction or scenario in a non-native-architecture program, you can use some great functions from `pwntools` to handle the compilation and debugging. This is a great way to create a small reproducible example to isolate an issue.

The following Python program, when run from inside a `tmux` session, will take some AArch64 assembly, compile it, and run it with GDB attached in a new `tmux` pane. It will search your system for the appropriate cross compiler for the architecture at hand, and run the compiled binary with QEMU.

```python
from pwn import *

context.arch = "aarch64"

AARCH64_GRACEFUL_EXIT = """
mov x0, 0
mov x8, 93
svc 0
"""

out = make_elf_from_assembly(STORE)
# Debug info
print(out)
gdb.debug(out)

pause()
```
