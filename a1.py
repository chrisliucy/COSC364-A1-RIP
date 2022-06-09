"""
     COSC364 Assignment 1 RIP Protocol
     Authors: Canying Liu 47108377
              JIA HUA XIE CAO 87728076
"""

import socket
import sys
import time
import errno
import os
import random
from time import time
from select import select

LOCALHOST = "127.0.0.1"
COMMAND = 2
VERSION = 2
AFI = 2
UPDATE_PERIOD = 5
GARBAGE_COLLECTION_PERIOD = 20
ROUTE_TIMEOUT = 30
GARBAGE_TIMEOUT = 20



class Entry:
    
    def __init__(self, destination, next_hop, cost, flag):
        """initialise an entry object"""
        
        self.destination = destination
        self.next_hop = next_hop
        self.cost = cost
        self.flag = flag
        self.last_update = time()
        self.garbage_time = None
    
    
    
    def __str__(self):
        """string repr of the entry obj"""
        
        str_rep = "Entry(Destination: {}, Cost: {}, Next_hop: {}, Flag: {})"
        return str_rep.format(self.destination, self.cost, self.next_hop, self.flag)



class Packet:
    
    def __init__(self, header=None, rtes=None):
        """header: 4 bytes header of a RIP packet
           rtes: 20 * n bytes route entries"""
        
        if (header is None) and (rtes is None):
            self.header = bytearray()
            self.rtes = bytearray()
        else:
            self.header = bytearray(header)
            self.rtes = bytearray(rtes)
    
    
    
    def create_header(self, sender):
        """Fill in the header fields of a RIP packet"""
        
        self.header.append(COMMAND)
        self.header.append(VERSION)
        self.header.append(sender >> 8)
        self.header.append(sender & 0xff)
        
    
    
    def create_periodic_update(self, sender, entries, receiver):
        """Create a periodic update message"""
        
        self.create_header(sender)
        zeros = [0, 0, 0, 0]
        
        rte = [0, AFI] + zeros + [sender >> 8, sender & 0xff] + 3 * zeros
        self.rtes += bytearray(rte)
        
        for destination in entries:
            entry = entries[destination]
            cost = entry.cost
            if entry.next_hop == receiver:
                cost = 16
            rte = [0, AFI, 0, entry.flag, 0, 0, entry.destination >> 8, entry.destination & 0xff]
            rte += 2 * zeros + [0, 0, 0, cost]
            self.rtes += bytearray(rte)
    
   
   
    def crete_triggered_update(self, sender, entries, receiver):
        """Create a triggered update message"""
        
        self.create_header(sender)
        zeros = [0, 0, 0, 0]      
        
        for entry in entries:
            dest, cost = entry.destination, entry.cost
            rte = [0, AFI, 0, entry.flag, 0, 0, entry.destination >> 8, entry.destination & 0xff]
            rte += 2 * zeros + [0, 0, 0, entry.cost]
            self.rtes += bytearray(rte)

     
     
    def is_correct_rte_format(self, rte):
        """Return True if the fixed fields in RTES have right values"""    
        
        if ((rte[0] << 8) + rte[1]) != AFI:
            print("\nIncorrect value in AFI field, drop the RIP packet!")
            return False
        elif (sum(rte[2:4]) != 0) and (sum(rte[2:4]) != 1):
            print("\nIncorrect value in ROUTE FLAG field, drop the RIP packet!")
            return False            
        elif not(is_valid_id(str(sum(rte[4:6]) + (rte[6] << 8) + rte[7]))):
            print("\nIncorrect value in DESTINATION ROUTER ID field, drop the RIP packet!")
            return False
        elif sum(rte[8:16]) != 0:
            print("\nIncorrect value in MUST BE ZERO field, drop the RIP packet!")
            return False
        elif sum(rte[16:]) > 16:
            print("\nIncorrect value in MATRIC field, drop the RIP packet!")
            return False
        else:
            return True
            
            
            
    def is_correct_pkt_format(self):
        """Return True if the length of the packet is 4+20*n bytes and if the 
        fixed fields have right values"""
        
        if len(self.header) != 4 or ((len(self.rtes) % 20) != 0):
            print("\nIncorrect RIP packet length, drop the RIP packet!")
            return False
        elif self.header[0] != COMMAND:
            print("\nIncorrect value in COMMAND field, drop the RIP packet!")
            return False
        elif self.header[1] != VERSION:
            print("\nIncorrect value in VERSION field, drop the RIP packet!")
            return False
        elif not(is_valid_id(str((self.header[2] << 8) + self.header[3]))):
            print("\nIncorrect value in ORIGINATED ROUTER ID field, drop the RIP packet!")
            return False
        else:
            rtes = [self.rtes[i:i+20] for i in range(0, len(self.rtes), 20)]
            for rte in rtes:
                if not(self.is_correct_rte_format(rte)):
                    return False
            return True



class Router:
    
    def __init__(self, router_id, input_ports, outputs):
        """router_id: the int unique identifier of the router
           input_ports: a list of ports where the router listens to others
           outputs: a dict of the form {peer: (cost, port)}
        """
        
        self.router_id = router_id
        self.input_ports = input_ports
        self.outputs = outputs
        self.input_sockets = []
        self.output_socket = None
        self.entry_table = {}
        self.timer = time()
    
    
    
    def __str__(self):
        """string representation of the Router object"""
        
        router_info = "Router ID: {}\nInput Ports: {}\nOutput Ports:\n"
        for peer, (cost, port) in self.outputs.items():
            router_info += "Port Number: {}, Cost: {}, Peer ID: {}\n".format(port, cost, peer)
        return router_info.format(self.router_id, self.input_ports)
    
    
    
    def bind_sockets(self):
        """Create UDP sockets and bind them to the input ports"""
        
        for input_port in self.input_ports:
            try:
                skt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                skt.bind((LOCALHOST, input_port))
                self.input_sockets.append(skt)
            except:
                print("\Error binding sockets to input ports")
                self.switch_off()
        
        self.output_socket = self.input_sockets[0]
        
    
    
    def send_msg(self, is_triggered_update=False, entries=None, peer=None):
        """Send messages to the router's neighbors"""
        
        for dest in self.outputs.keys():
            pkt = Packet()
            if is_triggered_update:
                if (peer == None) or (dest != peer):
                    pkt.crete_triggered_update(self.router_id, entries, dest)
                else:
                    continue
            else:
                pkt.create_periodic_update(self.router_id, self.entry_table, dest)
            
            port = self.outputs[dest][1]
            self.output_socket.sendto(pkt.header + pkt.rtes, (LOCALHOST, port))
    
    
    
    def listen_to_ports(self, timeout):
        """Listen to the input ports and collectes messages if there are incoming packets"""
        
        ready_ports, _, _ = select(self.input_sockets, [], [], timeout)
        if len(ready_ports) > 0:
            pkts = []
            for port in ready_ports:
                try:
                    packet = port.recvfrom(1024)
                    raw_data = packet[0]
                    pkts.append(raw_data)
                except:
                    print("\nError listening to port")                  
            return pkts
          
          
            
    def read_msg(self, packet):
        """Extract information from the received packet and update the routing 
        table if required"""
        
        if not(packet.is_correct_pkt_format()):
            return
        
        next_hop = (packet.header[2] << 8) + packet.header[3]
        triggered_updates = []
        
        for i in range(0, len(packet.rtes), 20):
            dest = (packet.rtes[i+6] << 8) + packet.rtes[i+7]
            entry = self.entry_table.get(next_hop)
            
            if dest != self.router_id:
                flag = packet.rtes[i+3]
                received_cost = packet.rtes[i+19]
                
                if entry == None:
                    cost = received_cost + self.outputs[next_hop][0]
                else:
                    cost = received_cost + min(entry.cost, self.outputs[next_hop][0])
                
                if cost > 16:
                    cost = 16
                has_update = self.update_table(dest, next_hop, cost, flag)
                
                if has_update:
                    triggered_updates.append(self.entry_table[dest])
        
        if len(triggered_updates) != 0:
            router.send_msg(True, triggered_updates, next_hop)
            router.print_table()
        
      
      
    def update_table(self, dest, next_hop, cost, flag):
        """Update the routing table if and only if the cost of the given entry is
        less than current entry hold in the router's table or the cost of the 
        current route in the routing table is changed"""
        
        current_entry = self.entry_table.get(dest)
        has_no_entry = current_entry == None
        has_triggered_update = False
        is_reachable_dest = cost < 16
        
        if has_no_entry and is_reachable_dest:
            self.entry_table[dest] = Entry(dest, next_hop, cost, flag)
        elif (not has_no_entry) and (current_entry.next_hop == next_hop):
            if cost < 16:
                if current_entry.flag == 1:
                    current_entry.flag = 0
                    current_entry.garbage_time = None
                current_entry.last_update = time()
                current_entry.cost = cost
            elif (cost == 16) and (flag == 1) and (current_entry.flag == 0):
                current_entry.flag = 1
                current_entry.cost = cost
                current_entry.garbage_time = time()
                has_triggered_update = True
        elif (not has_no_entry) and (cost < current_entry.cost):
            self.entry_table[dest] = Entry(dest, next_hop, cost, flag)

        return has_triggered_update



    def print_table(self):
        """Print the routing table"""
        
        row_bars = "|" + 76 * "=" + "|\n"
        router_id = "| Router ID: {}                                                               |\n"
        headers = "| Destination | Next Hop | Cost | Garbage Flag | Route Timer | Garbage Timer |\n"
        values =  "|      {}      |     {}    |  {}   |      {}       |      {}      |       {}      |\n"

        current_time = time()
        table = (row_bars + router_id + row_bars + headers + row_bars).format(self.router_id)
        for dest in sorted(self.entry_table):
            entry = self.entry_table[dest]
            timeout = max(0, int(ROUTE_TIMEOUT - (current_time - entry.last_update)))
            if entry.garbage_time == None:
                garbage = GARBAGE_TIMEOUT
            else:
                garbage = int(GARBAGE_TIMEOUT - (current_time - entry.garbage_time))
                garbage = max(0, garbage)
            table += (values + row_bars).format(entry.destination, entry.next_hop, 
                        entry.cost, entry.flag, timeout, garbage)
        
        print(table)
  
  
    
    def delete_entry(self, entries):
        """Garbage the entry if timeout"""
        
        for entry in entries:
            self.entry_table.pop(entry)
    
    
    
    
    def check_entries(self):
        """Check if there are unreachable entries in the routing table"""
        
        c_time = time()
        delete_entries = []
        triggered_updates = []
        
        for dest in self.entry_table:
            entry = self.entry_table[dest]
            if (entry.flag == 1) and ((c_time - entry.garbage_time) >= GARBAGE_TIMEOUT):
                delete_entries.append(dest)
            elif (entry.flag == 0) and ((c_time - entry.last_update) >= ROUTE_TIMEOUT):
                entry.cost = 16
                entry.flag = 1
                entry.garbage_time = time()
                triggered_updates.append(entry)
        
        if len(triggered_updates) > 0:
            router.send_msg(True, triggered_updates)
            router.print_table()
        if len(delete_entries) > 0:
            router.delete_entry(delete_entries)
            router.print_table()
   
   
    
    def switch_off(self):
        """Close all input ports and switch off the router"""
        
        for skt in self.input_sockets:
            try:
                skt.close()
            except:
                print("\nError closing the sockets")
                return
        
        print("\nAll sockets are successfully closed. Switching off the router.")



def get_filename():
    """Read the filename of a configuration file from terminal and return it"""
    
    try:
        filename = sys.argv[1]
    except:
        sys.exit("\nERROR: No filename provided")
    
    return filename

def read_cfg_file(filename):
    """Read the configuration file and return a list of lines"""

    try:
        infile = open(filename, "r")
        info = infile.readlines()
        infile.close()
    except(FileNotFoundError):
        sys.exit("\nERROR: File({0}) is not found".format(filename))
        
    return info



def is_valid_id(router_id):
    """Return True if the router_id is valid"""
    return router_id.isdigit() and 1 <= int(router_id) <= 64000

def is_valid_port(port):
    """Return True if the port is valid"""
    return port.isdigit() and 1024 <= int(port) <= 64000

def is_valid_cost(cost):
    """Return True if the cost of a path is valid"""
    return cost.isdigit() and 1 <= int(cost) <= 16



def setup_router(info):
    """Initialise a router using information given in the configuration file 
    if and only if the data provided is valid"""
    
    router_id = 0
    input_ports = []
    output_ports = []
    outputs_dict = dict()
    
    for line in info:
        line = line.strip("\n")
        
        if line.startswith("router-id"):
            id_string = line.split(" ")[1]
            if is_valid_id(id_string):
                router_id = int(id_string)
            else:
                sys.exit("\nERROR: Router ID is invalid")
        
        elif line.startswith("input-ports"):
            inputs_str = line.split(" ")[1:]
            input_ports = [int(port) for port in inputs_str if is_valid_port(port)]
            if len(inputs_str) != len(input_ports):
                sys.exit("\nERROR: Input port is invalid")
        
        elif line.startswith("outputs"):
            outputs_str = line.split(" ")[1:]
            for output in outputs_str:
                port, cost, peer = output.split("-")
                if not is_valid_port(port):
                    sys.exit("\nERROR: Output port is invalid")
                if not is_valid_cost(cost):
                    sys.exit("\nERROR: Cost is invalid")
                if not (is_valid_id(peer) and (int(peer) != router_id)):
                    sys.exit("\nERROR: The peer router id is invalid")
                
                outputs_dict[int(peer)] = (int(cost), int(port))
                output_ports.append(int(port))

    if not ((router_id != 0) and (len(input_ports) > 0) and (len(outputs_dict) > 0)):
        sys.exit("\nERROR: Expected parametes are missing")
    elif len(set(input_ports) & set(output_ports)) != 0:
        sys.exit("\nERROR: Input ports and output ports are overlapping")
    else :
        return Router(router_id, input_ports, outputs_dict)



def main(router):
    """The main programe of router operation"""

    router.bind_sockets()
    router.send_msg()
    msg_sent_time = time()
    periodic_update = random.uniform(0.8, 1.2) * UPDATE_PERIOD

    while True:
        packets = router.listen_to_ports(3)          # Listen to the input ports
        if (packets != None):
            for packet in packets:
                pkt = Packet(packet[:4], packet[4:])
                router.read_msg(pkt)
    
        current_time = time()
        
        if (current_time - msg_sent_time) > periodic_update:
            router.send_msg()
            msg_sent_time = current_time
            router.print_table()
            periodic_update = random.uniform(0.8, 1.2) * UPDATE_PERIOD
        
        if (current_time - router.timer) > GARBAGE_COLLECTION_PERIOD:
            router.check_entries()
            router.print_table()
            router.timer = current_time



if __name__ =="__main__":
    
    filename = get_filename()
    info = read_cfg_file(filename)
    router = setup_router(info)
    print(router)
    
    try:
        main(router)
    except KeyboardInterrupt:
        router.switch_off()
        sys.exit()