#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import codecs
import string

printable = set(string.printable)

def isprint(x):
    return set(x) < printable

try:
    import xmlrpc.client as xmlrpclib
    from xmlrpc.server import SimpleXMLRPCServer
except:
    import xmlrpclib
    from SimpleXMLRPCServer import SimpleXMLRPCServer

# Disable use of the accelerated Unmarshaller, so that we
# can add our own types.
xmlrpclib.FastUnmarshaller = None

# Declare code to marshal / unmarshal the only two types we really
# care about: Integers and Binary data.  The built-in marshallers
# are quite inferior.
def marshall_int(self, value, write):
    template = "<value><i8>%d</i8></value>"
    value = int(value)
    write(template % value)

def marshall_binary(self, value, write):
    if isprint(value):
        return self.dump_string(value, write)
    template = "<value><binary>%s</binary></value>"
    value = codecs.encode(value, 'hex')
    write(template % value)

def unmarshall_int(self, data):
    self.append(int(data))
    self._value = 0

def unmarshall_binary(self, data):
    self.append(bytearray(codecs.decode(data, 'hex')))
    self._value = 0

# Registration routines
def register_integer_type(t):
    xmlrpclib.Marshaller.dispatch[t] = marshall_int

def register_binary_type(t):
    xmlrpclib.Marshaller.dispatch[t] = marshall_binary

# We make some changes to the XMLRPC spec to support our needs
register_integer_type(type(1))
register_integer_type(type(1 << 100))

register_binary_type(type(''))  # Unicode strings
register_binary_type(type(b'')) # Byte strings
register_binary_type(bytearray) # Byte arrays

xmlrpclib.Unmarshaller.dispatch['binary'] = unmarshall_binary
