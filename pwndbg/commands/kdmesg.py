import argparse
from typing import Dict
from typing import Filter
from typing import Generator
from typing import List
from typing import Optional

import pwndbg
from pwndbg.commands import CommandCategory
from pwndbg.gdblib.kernel import log

parser = argparse.ArgumentParser(description="Outputs the kernel log buffer")
parser.add_argument("-l", "--level", type=str, help="Filter by log levels")
parser.add_argument("-f", "--facility", type=str, help="Filter by facilities")

LEVEL_MAP = {
    0: "EMERGENCY",
    1: "ALERT",
    2: "CRITICAL",
    3: "ERROR",
    4: "WARNING",
    5: "NOTICE",
    6: "INFORMATIONAL",
    7: "DEBUG",
}

FACILITY_MAP = {
    0: "KERNEL",
    1: "USER",
    2: "MAIL",
    3: "DAEMONS",
    4: "AUTH",
    5: "SYSLOG",
    6: "LPR",
    7: "NETWORK NEWS",
}


@pwndbg.commands.ArgparsedCommand(
    parser, aliases=["dmesg", "klog"], category=CommandCategory.KERNEL
)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWithKernelDebugSyms
def kdmesg(level: Optional[str], facility: Optional[str]) -> None:

    facilities = _facilities(facility)
    log_levels = _log_lvls(level)

    logs = log.KernelLog().get_logs()
    filtered_logs = filter_logs(logs, facilities, log_levels)
    for _log in filtered_logs:
        ts = float(_log["timestamp"]) / 1e9
        text = _log["text"]
        print(f"[{ts:12.6f}] {text}")


def filter_logs(
    logs: Generator[Dict, None, None],
    _facilities: Optional[List[int]] = None,
    _log_levels: Optional[List[int]] = None,
) -> Filter[Dict]:
    return filter(
        lambda log: (not _facilities or log["facility"] in _facilities)
        and (not _log_levels or log["log_level"] in _log_levels),
        logs,
    )


def _get_values(usr_input: Optional[str], map_dict: Dict[int, str], error_msg: str) -> List[int]:
    """Convert the user-provided values to numerical based on a given map_dict"""
    _values: List[int] = []

    if usr_input is None:
        return _values

    for value in usr_input.split(","):
        if value.isdigit() and int(value) in map_dict.keys():
            _values.append(int(value))
            continue

        _value = value.upper()
        for key, name in map_dict.items():
            if _value in name:
                _values.append(key)
                break
        else:
            raise ValueError(error_msg.format(value=value))

    return _values


def _log_lvls(levels: Optional[str]) -> List[int]:
    return _get_values(levels, LEVEL_MAP, "Unrecognized log level: '{value}'")


def _facilities(facilities: Optional[str]) -> List[int]:
    return _get_values(facilities, FACILITY_MAP, "Unrecognized facility: '{value}'")
