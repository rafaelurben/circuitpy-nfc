def int2hex(data):
    return "{:02x}".format(data)

def list2hex(data):
    return ":".join(list(map(int2hex, data)))

def bytes2str(data):
    return " ".join(map(lambda x: f"{repr(chr(x))[1:-1]:>4}".replace(r'\x00', '----'), data))
