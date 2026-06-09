from scapy.all import *
from scapy.layers.tls.all import TLS
from .decode import *

### CHECKS ###

def is_empty_COPT(pck):
    if len (pck) != 7:
        return False
    if pck[0:6] != b'\x03\x00\x00\x07\x02\xf0':
        return False
    return True

def is_COTP_handshake(pck):
    if len(pck) != 0x23:
        return False
    if pck[0:6] != b'\x03\x00\x00\x23\x1e\xd0' and pck[0:6] != b'\x03\x00\x00\x23\x1e\xe0':
        return False
    return True

def is_s7(pck):
    if pck[7] != 0x72:
        return False
    return True

def is_tls(pck):
    if len(pck) < 9:
        return False        
    if pck[7:9] != b'\x17\x03':
        return False
    return True

def is_tls_handshake(pck):
    if len(pck) < 9:
        return False        
    if pck[7:9] not in [b'\x14\x03', b'\x15\x03', b'\x16\x03']:
        return False
    return True
