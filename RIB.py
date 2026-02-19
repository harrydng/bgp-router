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


# data
def ip_to_int(ip):
    a,b,c,d = [int(x) for x in ip.split(".")]
    return (a<<24) | (b<<16) | (c<<8) | d

def int_to_ip(n):
    return ".".join(str((n >> shift) & 255) for shift in (24,16,8,0))

def mask_to_prefix(netmask):
    return bin(ip_to_int(netmask)).count("1")

def prefix_to_mask(prefix):
    mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF if prefix > 0 else 0
    return int_to_ip(mask)

def data(self, socket, jsonObject):
    """
    Forwards data packets to the next hop, based on the routing table. 
    If no route is found, the packet is dropped.
    """
    pass

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
    def key(route):
        return(
            route["peer"],
            route["localpref"],
            route["selfOrigin"],
            route["origin"],
            tuple(route["ASPath"]),
            mask_to_prefix(route["netmask"])
        )
    
    #grouping routes from their mergable attributed and prefix length
    groups = {}
    for route in routes:
        groups.setdefault(key(route), []).append(route)
        
    aggregate_routes = []
    
    for k, grp in groups.items():
        prefix_len = k[-1]
        block = 1 << (32 - prefix_len)
        
        # sort based on numeric network address
        group_sorted = sorted(grp, key=lambda r: ip_to_int(r["network"]))
        
        changed = True
        while changed:
            changed = False
            new_list = []
            i = 0
            while i < len(group_sorted):
                if i + 1 < len(group_sorted):
                    a = group_sorted[i]
                    b = group_sorted[i + 1]
                    
                    na = ip_to_int(a["network"])
                    nb = ip_to_int(b["network"])
                    
                    low = min(na, nb)
                    high = max(na, nb)
                    
                    #check adjacent block?
                    adjacent = (high - low) == block
                    #aligned for supernet?
                    aligned = (low % (2 * block)) == 0
                    
                    if adjacent and aligned and prefix_len > 0:
                        #merge into supernet
                        new_prefix = prefix_len - 1
                        merged = dict(a)
                        merged["network"] = int_to_ip(low)
                        merged["netmask"] = prefix_to_mask(new_prefix)
                        new_list.append(merged)
                        
                        changed = True
                        i += 2
                        continue
                    #no merge
                    new_list.append(group_sorted[i])
                    i+=1
                    
                group_sorted = sorted(new_list, key=lambda r: ip_to_int(r["network"]))
                
        aggregate_routes.extend(group_sorted)
    
    #sort again     
    aggregate_routes.sort(key=lambda r: (ip_to_int(r["network"]), mask_to_prefix(r["netmask"])))
    return aggregate_routes

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
            "netmask": route["netmask"],
            "peer": route["peer"],
            "localpref": route["localpref"],
            "ASPath": route["ASPath"],
            "selfOrigin": route["selfOrigin"],
            "origin": route["origin"],
        })

        
    response = {
        "src": self.get_our_ip_from_socket(socket),
        "dst": jsonObject["src"],
        "type": "table",
        "msg": table_list
    }
    
    socket.sendto(json.dumps(response).encode(), self.get_addr_from_socket(socket))