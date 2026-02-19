import json


def handshake(socket, jsonObject):
    pass

def netmask_to_prefixlen(netmask):
    quads = [int(qdn) for qdn in netmask.split('.')]
    mask_int = (quads[0] << 24) + (quads[1] << 16) + (quads[2] << 8) + quads[3]
    return bin(mask_int).count('1')

def update(socket, jsonObject, routeTable):
    network = jsonObject["msg"]["network"]
    netmask = jsonObject["msg"]["netmask"]
    ASPath = jsonObject["msg"]["ASPath"]
    prefixlen = netmask_to_prefixlen(netmask)
    routeTable[network + "/" + str(prefixlen)] = jsonObject["msg"]
    return routeTable


def withdraw(socket, jsonObject):
    """
    Handles withdrawal of routes, after broken and invalid routes are detected.
    Remove the specified route from the RIB, and notifying neighbors of the change.
    """
    pass


def ip_to_int(ip):
    quads = [int(qdn) for qdn in ip.split('.')]
    return (quads[0] << 24) + (quads[1] << 16) + (quads[2] << 8) + quads[3]

def data(self, socket, jsonObject):
    """
    Forwards data packets to the next hop, based on the routing table. 
    If no route is found, the packet is dropped.
    """
    destination_ip = ip_to_int(jsonObject["msg"]["dst"])
    
    
    #find matches routes
    matches = []
    for route in self.routeTable:
        network, prefixlen = route.split("/")
        prefixlen = int(prefixlen)
        netmask = ".".join(str((0xffffffff << (32 - prefixlen) >> i) & 0xff) for i in [24, 16, 8, 0])
        if ip_in_network(jsonObject["msg"]["dst"], network, netmask):
            matches.append((route, self.routeTable[route]))
    

# dump
def get_active_routes(self):
    """
    Returns a list of active routes in the routing table.
    """
    return [route for route in self.routeTable.values()
            if route.get("status") == "active"]

def aggregate_routes(self, routes):
    """
    Aggregates routes in the routing table to reduce the number of entries.
    This is done by combining routes that share a common prefix 
    into a single route with a shorter prefix.
    """
    return routes

def get_our_ip_from_socket(self, socket):
    """
    Returns the IP address of this router on the interface corresponding to the given socket.
    """
    for neighbor, sock in self.sockets.items():
        if sock == socket:
            return self.our_addr(neighbor)
    return None

def get_addr_from_socket(self, socket):
    """
    Returns the address of the neighbor corresponding to the given socket.
    """
    for neighbor, sock in self.sockets.items():
        if sock == socket:
            return ('localhost', self.ports[neighbor])
    return None

def dump(self, socket, jsonObject):
    """
    Show the current routing table.
    """
    routes = self.get_active_routes()
    routes = self.aggregate_routes(routes)
    
    table_list = []
    for route in routes:
        table_list.append({
            "network": route["network"],
            "netmask": route.netmask,
            "peer": route.peer,
            "localpref": route.localpref,
            "ASPath": route.ASPath,
            "selfOrigin": route.selfOrigin,
            "origin": route.origin,
        })
        
    response = {
        "src": self.get_our_ip_from_socket(socket),
        "dst": jsonObject["src"],
        "type": "table",
        "msg": table_list
    }
    
    socket.sendto(json.dumps(response).encode(), self.get_addr_from_socket(socket))