from protocol import *
from datetime import datetime, timedelta

PROFILES = []

class Profile(object):

    PROFILERS = {}
    ANALYSERS = {}
    
    def __init__(self, id):
        """Initialize the profile"""
        self._protocols = []
        self._profiling_end = datetime.now()+timedelta(days=1)
        self._id = id
        
    def is_profiling(self):
        """Checks whether the profile is in the training phase"""
        return datetime.now() < self.profiling_end
        
        
    @staticmethod
    def find_profiles(layer):
        sender = [p for p in PROFILES if p._id == layer.get_sender()]
        reciever = [p for p in PROFILES if p._id == layer.get_receiver()]
        if not sender:
            sender = [Profile(layer.get_sender())]
            PROFILES.extend(sender)
        if not receiver:
            receiver = [Profile(layer.get_receiver())]
            PROFILES.extend(receiver)
        return [sender[0], receiver[0]]
        

    @staticmethod
    def handle_packet(packet):
        # Find correct base tree
        layer = get_first_layer(packet)
        # Find/create matching profiles
        profiles = find_profiles(layer)
        
        if [p for p in profiles if p.is_profiling()]:
            profile_packet(profiles, packet, layer)
        else:
            analyse_packet(packet, layer)
            

    @staticmethod
    def profile_packet(profiles, packet, layer):
        # Construct tree
        curr_layer = layer
        while(packet.payload):
            # Run custom profilers
            [func(curr_layer, packet) for func in PROFILERS[type(curr_layer)]]
            curr_layer = get_next_layer(curr_layer, packet.payload)
            packet = packet.payload
            
        # Insert references to tree in profiles (if missing)
        for i in range(0, len(profiles)):
            if not [p for p in profiles[i]._protocols if p.matches(packet)]:
                profiles[i]._protocols.append(layer)
                
    @staticmethod
    def analyse_packet(packet, layer):
        res = []
        curr_layer = layer
        while(packet.payload):
            # Run custom analysers
            res.extend([func(curr_layer, packet)
                        for func in ANALYSERS[type(curr_layer)]])
            curr_layer = get_next_layer(curr_layer, packet.payload)
            packet = packet.payload
        return [r for r in res if r is not None]


    @staticmethod
    def add_profiler(cls, profiler):
        if not PROFILERS.get(cls):
            PROFILERS[cls] = [profiler]
        else:
            PROFILERS[cls].append(profiler)

    @staticmethod
    def add_analyser(cls, analyser):
        if not ANALYSERS.get(cls):
            ANALYSERS[cls] = [analyser]
        else:
            ANALYSERS[cls].append(analyser)