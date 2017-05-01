#!/usr/bin/env python
# -*- coding: utf-8 -*-
import hacks
import sys
import threading

try:
    import xmlrpc.client as xmlrpclib
except ImportError:
    import xmlrpclib

try:
    from xmlrpc.server import SimpleXMLRPCServer
except ImportError:
    from SimpleXMLRPCServer import SimpleXMLRPCServer


host = '127.0.0.1'
port = 41414
addr = 'http://{host}:{port}'.format(host=host, port=port)
server = SimpleXMLRPCServer((host, port), allow_none=True)


def noop(a=0):
	return a

server.register_function(noop)

thread = threading.Thread(target=server.serve_forever)
thread.daemon = True
thread.start()

client = xmlrpclib.ServerProxy(addr, allow_none=True)

def assert_same(x):
	y = client.noop(x)
	assert x == y, "%r != %r" % (x, y)

def test_integer():
	assert_same(0)

def test_long():
	assert_same(1 << 100)

def test_string():
	assert_same('Hello!')

def test_null_terminated_string():
	assert_same('Null-terminated\x00')

def test_latin1_string():
	assert_same('\x00\x01\x02\x03\x04\xff')

def test_unicode():
	assert_same('🤖')

def test_bytes():
	assert_same(b'asdf\x00\xff')

def test_bytearray():
	assert_same(bytearray(b'asdf\x00\xff'))

def test_none():
	assert_same(None)

def test_bool():
	assert_same(True)
	assert_same(False)