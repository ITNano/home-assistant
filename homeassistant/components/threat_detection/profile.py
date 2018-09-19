# """""""""""""""""""""""""""""""""""""""""""""""""""""""" #
#                 --- DECRIPTION ---                       #
# Handles profiling and everything that has to do with it  #
# """""""""""""""""""""""""""""""""""""""""""""""""""""""" #

from protocol import *
from datetime import datetime, timedelta
import pickle

"""All current profiles in the system"""
PROFILES = {}
IGNORE_LIST = []

class Profile(object):

    """ External profilers on the form (protocol_type, profiler)"""
    PROFILERS = {}
    """ External analysers on the form (protocol_type, analyser)"""
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
        """Retrieves the unique ID of this profile"""
        return self._id
        
    def protocols(self):
        """Retrieves the protocol data profiled by this entity"""
        return self._protocols

    @staticmethod
    def add_profiler(protocol_type, profiler):
        """Adds the given function as a profiler for a certain protocol"""
        if not Profile.PROFILERS.get(protocol_type):
            Profile.PROFILERS[protocol_type] = [profiler]
        else:
            Profile.PROFILERS[protocol_type].append(profiler)

    @staticmethod
    def add_analyser(protocol_type, analyser):
        """Adds the given function as an analyser for a certain protocol"""
        if not Profile.ANALYSERS.get(protocol_type):
            Profile.ANALYSERS[protocol_type] = [analyser]
        else:
            Profile.ANALYSERS[protocol_type].append(analyser)


def handle_packet(packet):
    """Handles incoming packets and routes them to their destination"""
    # Find correct base tree
    layer = get_first_layer(packet)
    # Find/create matching profiles
    profiles = find_profiles(layer)
    
    if [p for p in profiles if p.is_profiling()]:
        profile_packet(profiles, packet, layer)
    else:
        return analyse_packet(packet, layer)


def find_profiles(layer):
    """Finds or creates the profiles for the communicating parties"""
    res = [get_profile(layer.get_sender()), get_profile(layer.get_receiver())]
    return [r for r in res if r is not None]


def get_profile(id):
    """Retrieves/creates the profile with the given ID"""
    if id not in IGNORE_LIST:
        if PROFILES.get(id) is None:
            PROFILES[id] = Profile(id)
        return PROFILES.get(id)


def profile_packet(profiles, packet, layer):
    """Performs a profiling of the packet and updates given profiles"""
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
    """Analyses the given packet"""
    res = []
    curr_layer = layer
    while(packet):
        # Run custom analysers
        for analyser in ANALYSERS.get(type(curr_layer), []):
            res.append(func(curr_layer, packet))
        # Iterate to next entry
        if packet.payload:
            curr_layer = get_next_layer(curr_layer, packet.payload, False)
        packet = packet.payload
    return [r for r in res if r is not None]


def save_profiles(filename):
    """Saves all current profiles to a savefile"""
    with open(filename, 'wb') as output:
        pickle.dump(PROFILES, output, pickle.HIGHEST_PROTOCOL)


def load_profiles(filename):
    """Loads saved profiles from a savefile"""
    try:
        with open(filename, 'rb') as input:
            global PROFILES
            PROFILES = pickle.load(input)
    except FileNotFoundError as e:
        print("WARNING: Cannot load entries from " + str(filename) + ".")


def all_profiles():
    """Retrieves all current profiles"""
    return PROFILES


def ignore_device(id):
    """Appends an ID to the profiling ignore list"""
    IGNORE_LIST.append(id)