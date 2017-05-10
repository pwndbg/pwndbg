#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import functools
import os
import pickle
import re
import sys

import six

import pwndbg.compat

def get_cache_dir():
    dir = os.environ.get('PWNDBG_CACHE_DIR')
    if not dir:
        if sys.platform == 'darwin':
            dir = os.path.join(os.path.expanduser('~/Library/Caches'), 'pwndbg')
        elif sys.platform == 'win32':
            dir = os.path.join(os.getenv('LOCALAPPDATA'), 'pwndbg', 'Cache')
        else:
            dir = os.path.join(os.environ.get('XDG_CACHE_HOME') or os.path.expanduser('~/.cache'), 'pwndbg')
    try:
        os.makedirs(dir)
    except OSError:
        assert os.path.isdir(dir)
    return dir

cache_dir = get_cache_dir()

def makedirs(name):
    try:
        os.makedirs(name)
    except OSError:  # FileExistsError.__base__ is OSError in Python 3
        assert os.path.isdir(name)

def generic_file_cache(template, fn):
    def memoize(function):
        p = function.__module__.split('.')[1:] + [function.__name__]
        dirpath = os.path.join(cache_dir, *p)

        @functools.wraps(function)
        def wrapper(*args, **kwargs):
            return fn(os.path.join(dirpath, template.format(*args, **kwargs)), function, args, kwargs)

        return wrapper

    return memoize

def file_cache_for_pickle(template):
    def fn(path, function, args, kwargs):
        try:
            with open(path, 'rb') as f:
                ret = pickle.load(f)
        except:
            ret = function(*args, **kwargs)
            makedirs(os.path.dirname(path))
            with open(path, 'wb') as f:
                pickle.dump(ret, f)
        return ret

    return generic_file_cache(template, fn)

def file_cache_with_signature_for_pickle(template):
    def fn(path, function, args, kwargs):
        valid = False
        signature = kwargs.pop('signature')
        try:
            with open(path, 'rb') as f:
                (saved_signature, ret) = pickle.load(f)
                if saved_signature == signature:
                    valid = True
        except:
            pass
        if not valid:
            ret = function(*args, **kwargs)
            makedirs(os.path.dirname(path))
            with open(path, 'wb') as f:
                pickle.dump((signature, ret), f)
        return ret

    return generic_file_cache(template, fn)

def file_cache_for_text(template):
    def fn(path, function, args, kwargs):
        try:
            with open(path) as f:
                ret = f.read()
        except:
            ret = function(*args, **kwargs)
            assert isinstance(ret, six.string_types)
            makedirs(os.path.dirname(path))
            with open(path, 'w') as f:
                f.write(ret)
        return ret

    return generic_file_cache(template, fn)

def file_cache_with_signature_for_text(template):
    regex = re.compile(r'pwndbg:\s*signature=(\S+)')

    def fn(path, function, args, kwargs):
        valid = False
        signature = str(kwargs.pop('signature'))
        try:
            with open(path) as f:
                lines = f.readlines()
            if lines:
                match = regex.search(lines[0])
                if match:
                    saved_signature = match.group(1)
                    if saved_signature == signature:
                        ret = ''.join(lines[1:])
                        valid = True
        except:
            pass
        if not valid:
            ret = function(*args, **kwargs)
            assert isinstance(ret, six.string_types)
            makedirs(os.path.dirname(path))
            with open(path, 'w') as f:
                f.write('# -*- pwndbg: signature={} -*-\n'.format(signature))
                f.write(ret)
        return ret

    return generic_file_cache(template, fn)
