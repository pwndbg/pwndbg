from __future__ import annotations

import logging

import pwndbg.color


class ColorFormatter(logging.Formatter):
    log_funcs = {
        logging.DEBUG: pwndbg.color.message.debug,
        logging.INFO: pwndbg.color.message.info,
        logging.WARNING: pwndbg.color.message.warn,
        logging.ERROR: pwndbg.color.message.error,
        logging.CRITICAL: pwndbg.color.message.error,
    }

    def format(self, record):
        log_func = self.log_funcs.get(record.levelno)
        formatter = logging.Formatter(log_func("%(message)s"))
        return formatter.format(record)
