#!/usr/bin/env python
# -*- coding: utf-8 -*-

import pwndbg.color.theme as theme
import pwndbg.config as config
from pwndbg.color import generateColorFunction

config_symbol        = theme.ColoredParameter('nearpc-symbol-color', 'normal', 'color for nearpc command (symbol)')
config_address       = theme.ColoredParameter('nearpc-address-color', 'normal', 'color for nearpc command (address)')
config_prefix        = theme.ColoredParameter('nearpc-prefix-color', 'none', 'color for nearpc command (prefix marker)')
config_syscall_name  = theme.ColoredParameter('nearpc-syscall-name-color', 'red', 'color for nearpc command (resolved syscall name)')
config_argument      = theme.ColoredParameter('nearpc-argument-color', 'bold', 'color for nearpc command (target argument)')
config_ida_anterior  = theme.ColoredParameter('nearpc-ida-anterior-color', 'bold', 'color for nearpc command (IDA anterior)')
config_branch_marker = theme.ColoredParameter('nearpc-branch-marker-color', 'normal', 'color for nearpc command (branch marker line)')

def symbol(x):
    return generateColorFunction(config.nearpc_symbol_color)(x)

def address(x):
    return generateColorFunction(config.nearpc_address_color)(x)

def prefix(x):
    return generateColorFunction(config.nearpc_prefix_color)(x)

def syscall_name(x):
    return generateColorFunction(config.nearpc_syscall_name_color)(x)

def argument(x):
    return generateColorFunction(config.nearpc_argument_color)(x)

def ida_anterior(x):
    return generateColorFunction(config.nearpc_ida_anterior_color)(x)

def branch_marker(x):
    return generateColorFunction(config.nearpc_branch_marker_color)(x)
