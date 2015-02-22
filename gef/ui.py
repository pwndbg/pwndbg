import struct, termios, fcntl, sys
import gef.arch

def banner(title):
    title = title.upper()
    try:
        _height, width = struct.unpack('hh', fcntl.ioctl(sys.stdin.fileno(), termios.TIOCGWINSZ, '1234'))
    except:
        width = 80
    width -= 2
    return ("[{:-^%ss}]" % width).format(title)

def addrsz(address):
	address = int(address) & gef.arch.ptrmask
	return "%{}x".format(2*gef.arch.ptrsize) % address
