#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Lots of hacks around Python's SimpleXMLRPCServer and xmlrpclib.ServerProxy
to support various things that we need in Pwndbg.

In particular, there are two important modifications:

- Marshalling of extra data types is supported *and* transparent
  - Python2 str and unicode
  - Python3 str and bytes
  - bytearray
  - int and long
- Marshalling of properties and attributes, in addition to function calls
  - Lots of things in Pwndbg are exposed via 'magic' rather than
    getters.  This supports the magic.

"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import codecs
import six
import string

from six.moves import xmlrpc_client as xmlrpclib
from six.moves import xmlrpc_server as server

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
    template = "<value><binary>%s,%s</binary></value>"

    encoding = None

    # Python2 string and bytes are the same
    if isinstance(value, bytes):
        encoding = 'bytes'

    # Python2 unicode and Python3 string need to be *encoded* to bytes
    elif isinstance(value, six.string_types):
        try:
            value.encode('latin-1')
            encoding = 'latin-1'
        except Exception as e:
            pass

        try:
            value.encode('utf-8')
            encoding = 'utf-8'
        except Exception as e:
            pass

        value = value.encode(encoding)

    elif isinstance(value, bytearray):
        encoding = 'bytearray'

    value = codecs.encode(value, 'hex')
    value = value.decode('latin-1')

    write(template % (encoding, value))

def unmarshall_int(self, data):
    self.append(int(data))
    self._value = 0

def unmarshall_binary(self, data):
    encoding, data = data.split(',', 1)

    data = codecs.decode(data, 'hex')

    if encoding in ('latin-1', 'utf-8'):
        data = data.decode(encoding)
    elif encoding == 'bytes':
        pass
    elif encoding == 'bytearray':
        data = bytearray(data)

    self.append(data)
    self._value = 0

# Registration routines
def register_integer_type(t):
    xmlrpclib.Marshaller.dispatch[t] = marshall_int

def register_binary_type(t):
    xmlrpclib.Marshaller.dispatch[t] = marshall_binary

# We make some changes to the XMLRPC spec to support our needs
register_integer_type(type(1))          # int
register_integer_type(type(1 << 100))   # python2 long

register_binary_type(type(''))  # Python2 strings
register_binary_type(type('🤖'))  # Unicode strings
register_binary_type(type(b'')) # Byte strings
register_binary_type(bytearray) # Byte arrays

xmlrpclib.Unmarshaller.dispatch['binary'] = unmarshall_binary

# Declare our own SimpleXMLRPCServer type, which allows access
# to properties and attributes.
class SimpleXMLRPCServer(server.SimpleXMLRPCServer):
    def _dispatch(self, method, params):
        print('!', self, method, params)
        if self.instance:
            method = resolve_dotted_attribute(self.instance, method)
        if not callable(method) and not params:
            return method
        return super(SimpleXMLRPCServer, self)._dispatch(method, params)

def resolve_dotted_attribute(obj, attr):
    for i in attr.split('.'):
        obj = getattr(obj, i)
    return obj

class _Method:
    # some magic to bind an XML-RPC method to an RPC server.
    # supports "nested" methods (e.g. examples.getStateName)
    def __init__(self, send, name):
        self.__send = send
        self.__name = name
    def __getattr__(self, name):
        return _Method(self.__send, "%s.%s" % (self.__name, name))
    def __call__(self, *args):
        return self.__send(self.__name, args)

class ServerProxy(xmlrpclib.ServerProxy):
    def __getattr__(self, name):
        return _Method(self.__request, name)