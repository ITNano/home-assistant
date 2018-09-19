from protocol import *
from datetime import datetime, timedelta

PROFILES = []

class Profile(object):

    PROFILERS = {}
    ANALYSERS = {}
    
    def __init__(self, id):
        """Initialize the profile"""
        self._protocols = []
        self.profiling_length = 3600*24    # one day
        self._profiling_end = (datetime.now()+
                               timedelta(seconds=self.profiling_length))
        self._id = id
        
    def is_profiling(self):
        """Checks whether the profile is in the training phase"""
        return datetime.now() < self._profiling_end
        
    def id(self):
        return self._id
        
    def protocols(self):
        return self._protocols

    @staticmethod
    def add_profiler(cls, profiler):
        if not Profile.PROFILERS.get(cls):
            Profile.PROFILERS[cls] = [profiler]
        else:
            Profile.PROFILERS[cls].append(profiler)

    @staticmethod
    def add_analyser(cls, analyser):
        if not Profile.ANALYSERS.get(cls):
            Profile.ANALYSERS[cls] = [analyser]
        else:
            Profile.ANALYSERS[cls].append(analyser)
            

def find_profiles(layer):
    sender = [p for p in PROFILES if p._id == layer.get_sender()]
    receiver = [p for p in PROFILES if p._id == layer.get_receiver()]
    if not sender:
        sender = [Profile(layer.get_sender())]
        PROFILES.extend(sender)
    if not receiver:
        receiver = [Profile(layer.get_receiver())]
        PROFILES.extend(receiver)
    return [sender[0], receiver[0]]
    

def handle_packet(packet):
    # Find correct base tree
    layer = get_first_layer(packet)
    # Find/create matching profiles
    profiles = find_profiles(layer)
    
    if [p for p in profiles if p.is_profiling()]:
        profile_packet(profiles, packet, layer)
    else:
        return analyse_packet(packet, layer)
        

def profile_packet(profiles, packet, layer):
    # Construct tree
    curr_layer = layer
    curr_packet = packet
    while(curr_packet):
        # Run custom profilers
        for func in Profile.PROFILERS.get(type(curr_layer), []):
            func(curr_layer, curr_packet)
        # Iterate to next entry
        if curr_packet.payload:
            curr_layer = get_next_layer(curr_layer, curr_packet.payload)
        curr_packet = curr_packet.payload
        
    # Insert references to tree in profiles (if missing)
    for i in range(0, len(profiles)):
        if not [p for p in profiles[i]._protocols if p.matches(packet)]:
            profiles[i]._protocols.append(layer)


def analyse_packet(packet, layer):
    res = []
    curr_layer = layer
    while(packet):
        # Run custom analysers
        for analyser in ANALYSERS.get(type(curr_layer), []):
            res.append(func(curr_layer, packet))
        # Iterate to next entry
        if packet.payload:
            curr_layer = get_next_layer(curr_layer, packet.payload)
        packet = packet.payload
    return [r for r in res if r is not None]