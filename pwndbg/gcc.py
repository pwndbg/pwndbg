#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Functions for determining the architecture-dependent path to
GCC and any flags it should be executed with.
"""

import glob
import os
import platform

import gdb

import pwndbg.arch


def flags():

    if pwndbg.arch.current == 'i386':
        return ['-m32']
    if pwndbg.arch.current.endswith('x86-64'):
        return ['-m64']

    return []

def which():
    gcc = which_binutils('g++')

    if not gcc:
        global printed_message
        if not printed_message:
            printed_message=True
            print("Can't find appropriate GCC, using default version")

        if pwndbg.arch.ptrsize == 32:
            return ['g++','-m32']
        elif pwndbg.arch.ptrsize == 64:
            return ['g++','-m32']

    return [gcc] + flags()

printed_message = False


def which_binutils(util, **kwargs):
    ###############################
    # Borrowed from pwntools' code
    ###############################
    arch = pwndbg.arch.current
    bits = pwndbg.arch.ptrsize

    # Fix up binjitsu vs Debian triplet naming, and account
    # for 'thumb' being its own binjitsu architecture.
    arches = [arch] + {
        'thumb':  ['arm', 'armcm', 'aarch64'],
        'i386':   ['x86_64', 'amd64'],
        'i686':   ['x86_64', 'amd64'],
        'i386:x86-64': ['x86_64', 'amd64'],
        'amd64':  ['x86_64', 'i386'],
    }.get(arch, [])

    # If one of the candidate architectures matches the native
    # architecture, use that as a last resort.
    machine = platform.machine()
    machine = 'i386' if machine == 'i686' else machine

    if arch in arches:
        arches.append(None)

    for arch in arches:
        # hack for homebrew-installed binutils on mac
        for gutil in ['g'+util, util]:
            # e.g. objdump
            if arch is None: pattern = gutil

            # e.g. aarch64-linux-gnu-objdump
            else:       pattern = '%s*linux*-%s' % (arch,gutil)

            for dir in os.environ['PATH'].split(':'):
                res = sorted(glob.glob(os.path.join(dir, pattern)))
                if res:
                    return res[0]
