from __future__ import annotations

from dataclasses import dataclass


@dataclass
class SigInfoKill:
    si_pid: int
    si_uid: int


@dataclass
class SigInfoTimer:
    si_tid: int
    si_overrun: int
    si_sigval: SigInfoSigVal


@dataclass
class SigInfoSigVal:
    sival_int: int
    sival_ptr: int


@dataclass
class SigInfoRt:
    si_pid: int
    si_uid: int
    si_sigval: SigInfoSigVal


@dataclass
class SigInfoSigChld:
    si_pid: int
    si_uid: int
    si_status: int
    si_utime: int
    si_stime: int


@dataclass
class SigInfoSigFault:
    si_addr: int


@dataclass
class SigInfoSigPoll:
    si_band: int
    si_fd: int


@dataclass
class SigInfoSigSys:
    call_addr: int
    syscall: int
    arch: int


@dataclass
class SigInfo:
    si_signo: int
    si_errno: int
    si_code: int

    kill: SigInfoKill
    timer: SigInfoTimer
    rt: SigInfoRt
    sigchld: SigInfoSigChld
    sigfault: SigInfoSigFault
    sigpoll: SigInfoSigPoll
    sigsys: SigInfoSigSys
