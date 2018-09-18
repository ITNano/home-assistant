# """""""""""""""""""""""""""""""""""""""""""""""""""""""" #
# -- DECRIPTION --                                         #
# Helper class for representing protocols and their layers #
# """""""""""""""""""""""""""""""""""""""""""""""""""""""" #


class Protocol(object):

    def __init__(self):
        self._next_protocol = []
        self._packet_counter = 0
        
    def increase_packet_counter(self):
        self._packet_counter += 1
        
    def get_nbr_of_packets(self):
        return self._packet_counter

    def add_protocol(self, proto):
        self._next_protocol.append(proto)

    def get_next_protocol(self, cls):
        def protocol_filter(obj):
            return type(obj) == cls
        return list(filter(protocol_filter, self._next_protocol))


class SendRecvProtocol(Protocol):

    def __init__(self, sender, receiver):
        Protocol.__init__(self)
        self._sender = sender
        self._receiver = receiver

    def get_sender(self):
        return self._sender

    def get_receiver(self):
        return self._receiver


class IPv4(SendRecvProtocol):

    def __init__(self, sender, receiver):
        SendRecvProtocol.__init__(self, sender, receiver)

    def is_sender_internal(self, nw, netmask):
        return is_internal(self.get_sender(), nw, netmask)

    def is_receiver_internal(self, nw, netmask):
        return is_internal(self.get_receiver(), nw, netmask)

    @staticmethod
    def is_internal(ip_addr, nw, netmask):
        return list(map(lambda x: int(x[1]) & netmask[int(x[0])],
                        enumerate(ip_addr.split('.')))) == list(map(
                        lambda x: int(x), nw.split('.')))


class IPv6(SendRecvProtocol):

    def __init__(self, sender, receiver):
        SendRecvProtocol.__init__(self, sender, receiver)

    def is_sender_internal(self):
        return is_internal(self.get_sender())

    def is_receiver_internal(self):
        return is_internal(self.get_receiver())

    @staticmethod
    def is_internal(ip_addr):
        return (ip_addr[0:4] == 'fe80' or
                ip_addr[0:2] in ['fc', 'fd'] or
                ip_addr[0:3] in ['::1', '100'])


class TCP(SendRecvProtocol):

    def __init__(self, sender_port, receiver_port):
        SendRecvProtocol.__init__(self, sender_port, receiver_port)


class UDP(SendRecvProtocol):
    
    def __init__(self, sender_port, receiver_port):
        SendRecvProtocol.__init__(self, sender_port, receiver_port)


class DNS(Protocol):

    def __init__(self):
        Protocol.__init__(self)


class IEEE802_15_4(SendRecvProtocol):

    def __init__(self, sender, receiver):
        SendRecvProtocol.__init__(self, sender, receiver)