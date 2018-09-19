# """""""""""""""""""""""""""""""""""""""""""""""""""""""" #
#                 --- DECRIPTION ---                       #
# Helper class for representing protocols and their layers #
# """""""""""""""""""""""""""""""""""""""""""""""""""""""" #

BASE_PROTOCOLS = []

def get_all_layers():
    """Retrieves a dictionary mapping scapy packet names to our classes"""
    return {
            # 'Raw': Raw,
            'Ethernet': Ethernet,
            'IP': IPv4,
            'IPv6': IPv6,
            'TCP': TCP,
            'UDP': UDP,
            'DNS': DNS,
            'Dot15d4Data': IEEE802_15_4,
            'RadioTap': RadioTap
           }

def ignore_layers():
    return ['Raw']
           
def get_protocol_profile(protocols, packet, add_if_not_found=True):
    """Retrieves a protocol object for an arbitrary packet"""
    cls = get_all_layers().get(packet.name)
    if cls is None and packet.name in ignore_layers():
        return None
        
    matches = [p for p in protocols if type(p) == cls and p.matches(packet)]
    if len(matches) != 1:
        if not matches:
            if add_if_not_found:
                if cls is None:
                    print("WARNING: No implementation for type "+packet.name)
                    return None
                match = cls(packet)
                protocols.append(match)
            else:
                return None
        else:
            raise ValueError("Multiple protocols matching same situation!")
    else:
        match = matches[0]
        match.increase_packet_counter()
    return match

def get_first_layer(packet, add_if_not_found=True):
    """Retrieves a protocol object for an unprocessed packet"""
    return get_protocol_profile(BASE_PROTOCOLS, packet, add_if_not_found)

def get_next_layer(protocol, packet, add_if_not_found=True):
    return get_protocol_profile(protocol.get_next_protocol(),
                                packet, add_if_not_found)

def get_property(packet, prop, default=None):
    try:
        val = packet.getfield_and_val(prop)
        if val is not None and len(val) == 2:
            return val[1]
        else:
            return default
    except AttributeError:
        return default



class Protocol(object):

    def __init__(self, name):
        """Initialize the object"""
        self._name = name
        self._next_protocol = []
        self._packet_counter = 1

    def get_name(self):
        return self._name
        
    def increase_packet_counter(self):
        """Increases the number of seen packets of this type"""
        self._packet_counter += 1

    def get_nbr_of_packets(self):
        """Retrieves the number of seen packets of this type"""
        return self._packet_counter

    def add_protocol(self, proto):
        """Adds a protocol object as a decendant to this one"""
        self._next_protocol.append(proto)

    def get_next_protocol(self):
        """Retrieves all decendant protocol objects"""
        return self._next_protocol
        
    def has_next_protocol(self):
        """Checks whether any decendant protocols object are found"""
        return len(self._next_protocol) > 0

    def matches(self, packet):
        """Checks whether the packet matches the data of this protocol"""
        return True

    def equals(self, protocol):
        """Checks whether this protocol object is the same as the given one"""
        return type(protocol) == type(self)
        
    def __str__(self):
        return self.get_name() + "(" + self._packet_counter + " packets)"


class SendRecvProtocol(Protocol):

    def __init__(self, name, packet):
        """Initialize the object"""
        Protocol.__init__(self, name)
        self._sender = self.extract_sender(packet)
        self._receiver = self.extract_receiver(packet)

    def get_sender(self):
        """Retrieves the sender data of the message"""
        return self._sender

    def get_receiver(self):
        """Retrieves the receiver data of the message"""
        return self._receiver

    def extract_sender(self, packet):
        """Extracts the data of a sender from packet"""
        return None

    def extract_receiver(self, packet):
        """Extracts the data of a receiver from packet"""
        return None

    def matches(self, packet):
        """Checks whether the packet matches the data of this protocol"""
        return (self.extract_sender(packet) == self._sender and
                self.extract_receiver(packet) == self._receiver)

    def equals(self, protocol):
        """Checks whether this protocol object is the same as the given one"""
        return (isinstance(protocol, SendRecvProtocol) and
                protocol.get_sender() == self.get_sender() and
                protocol.get_receiver() == self.get_receiver())
                
    def __str__(self):
        return (self.get_name() + " " +
                str(self._sender) + " --> " + str(self._receiver) +
                " (" + str(self.get_nbr_of_packets()) + " packets)")


class Raw(Protocol):

    def __init__(self, packet):
        Protocol.__init__(self, 'Raw')
        self._data = packet.load
        
    def get_raw_data():
        return self._data

    def matches(self, packet):
        """Checks whether the packet matches the data of this protocol"""
        return get_property(packet, 'load') == self._data

    def equals(self, protocol):
        """Checks whether this protocol object is the same as the given one"""
        return (Protocol.equals(self, protocol) and 
                protocol.get_raw_data() == self.get_raw_data())


class Ethernet(SendRecvProtocol):

    def __init__(self, packet):
        """Initialize the object"""
        SendRecvProtocol.__init__(self, 'Ethernet', packet)

    def extract_sender(self, packet):
        """Extracts the data of a sender from packet"""
        return get_property(packet, 'src')

    def extract_receiver(self, packet):
        """Extracts the data of a receiver from packet"""
        return get_property(packet, 'dst')


class IPv4(SendRecvProtocol):

    def __init__(self, packet):
        """Initialize the object"""
        SendRecvProtocol.__init__(self, 'IPv4', packet)

    def extract_sender(self, packet):
        """Extracts the data of a sender from packet"""
        return get_property(packet, 'src')

    def extract_receiver(self, packet):
        """Extracts the data of a receiver from packet"""
        return get_property(packet, 'dst')


    def is_sender_internal(self, nw, netmask):
        """Check whether the sender is on the local network"""
        return is_internal(self.get_sender(), nw, netmask)

    def is_receiver_internal(self, nw, netmask):
        """Check whether the receiver is on the local network"""
        return is_internal(self.get_receiver(), nw, netmask)

    @staticmethod
    def is_internal(ip_addr, nw, netmask):
        """Check whether an IP address is in the local network"""
        return list(map(lambda x: int(x[1]) & netmask[int(x[0])],
                        enumerate(ip_addr.split('.')))) == list(map(
                        lambda x: int(x), nw.split('.')))


class IPv6(SendRecvProtocol):

    def __init__(self, packet):
        """Initialize the object"""
        SendRecvProtocol.__init__(self, 'IPv6', packet)

    def extract_sender(self, packet):
        """Extracts the data of a sender from packet"""
        return get_property(packet, 'src')

    def extract_receiver(self, packet):
        """Extracts the data of a receiver from packet"""
        return get_property(packet, 'dst')


    def is_sender_internal(self):
        """Check whether the sender is on the local network"""
        return is_internal(self.get_sender())

    def is_receiver_internal(self):
        """Check whether the receiver is on the local network"""
        return is_internal(self.get_receiver())

    @staticmethod
    def is_internal(ip_addr):
        """Check whether the receiver is on the local network"""
        return (ip_addr[0:4] == 'fe80' or
                ip_addr[0:2] in ['fc', 'fd'] or
                ip_addr[0:3] in ['::1', '100'])


class TCP(SendRecvProtocol):

    def __init__(self, packet):
        """Initialize the object"""
        SendRecvProtocol.__init__(self, 'TCP', packet)

    def extract_sender(self, packet):
        """Extracts the data of a sender from packet"""
        return get_property(packet, 'sport')

    def extract_receiver(self, packet):
        """Extracts the data of a receiver from packet"""
        return get_property(packet, 'dport')


class UDP(SendRecvProtocol):
    
    def __init__(self, packet):
        """Initialize the object"""
        SendRecvProtocol.__init__(self, 'UDP', packet)

    def extract_sender(self, packet):
        """Extracts the data of a sender from packet"""
        return get_property(packet, 'sport')

    def extract_receiver(self, packet):
        """Extracts the data of a receiver from packet"""
        return get_property(packet, 'dport')


class DNS(Protocol):

    def __init__(self, packet):
        """Initialize the object"""
        Protocol.__init__(self, 'DNS')


class IEEE802_15_4(SendRecvProtocol):

    def __init__(self, packet):
        """Initialize the object"""
        SendRecvProtocol.__init__(self, 'IEEE 802.15.4', packet)

    def extract_sender(self, packet):
        """Extracts the data of a sender from packet"""
        return get_property(packet, 'src_addr')

    def extract_receiver(self, packet):
        """Extracts the data of a receiver from packet"""
        return get_property(packet, 'dest_addr')
        
        
class RadioTap(Protocol):

    def __init__(self, packet):
        """Initialize the object"""
        Protocol.__init__(self, 'RadioTap')