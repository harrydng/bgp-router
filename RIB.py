def handshake(socket, jsonObject):
    pass

def netmask_to_prefixlen(netmask):
    quads = [int(qdn) for qdn in netmask.split('.')]
    mask_int = (quads[0] << 24) + (quads[1] << 16) + (quads[2] << 8) + quads[3]
    return bin(mask_int).count('1')

def update(socket, jsonObject, routeTable):
    network = jsonObject["msg"]["network"]
    netmask = jsonObject["msg"]["netmask"]
    ASpath = jsonObject["msg"]["ASpath"]
    prefixlen = netmask_to_prefixlen(netmask)
    routeTable[network + "/" + str(prefixlen)] = jsonObject["msg"]
    return routeTable

def withdraw(socket, jsonObject):
    pass

def data(socket, jsonObject):
    pass

def dump(socket, jsonObject):
    pass