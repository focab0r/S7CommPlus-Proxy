### DECODES ###

def decode_tpkt(pck_tpkt):
    i = 0
    while True:
        if pck_tpkt[i:i+4] == b'\x03\x00\x00\x07':
            i+=7
            if len(pck_tpkt)-i == 7:
                return b''
        else:
            break
    return pck_tpkt[i+4:]

def decode_cotp(pck_cotp):
    return pck_cotp[3:]