"""
Component for detecting threats against the smart home.

For more information on this component see
todo add where to find documontation for the component.
"""

import os
from os.path import dirname, basename, isfile, join
from threading import Lock
from datetime import datetime, timedelta
import pickle
import logging
import voluptuous as vol
from homeassistant.helpers.entity import Entity
from homeassistant.helpers.entity_component import EntityComponent
import homeassistant.const as const

_LOGGER = logging.getLogger(__name__)

DOMAIN = "threat_detection"

ENTITIY_ID_FORMAT = DOMAIN + ".{}"

DEPENDENCIES = []

# Configuration input
# -- No config available yet.
# Here we need to add everything that is required from the conf-file if we
# need some input from the user.
CONFIG_SCHEMA = vol.Schema({
    DOMAIN: vol.Schema({})
}, extra=vol.ALLOW_EXTRA)

CAPTURER = None
DETECTION_OBJ = None
STORAGE_NAME = "td_profiles.pcl"


# @asyncio.coroutine
async def async_setup(hass, config=None):
    """Set up the threat_detection component."""
    component = EntityComponent(_LOGGER, DOMAIN, hass)
    # yield from component.async_setup(config)

    # Set up network properties
    for device in get_gateways():
        ignore_device(device)

    # Start capturing packets from network
    global CAPTURER
    CAPTURER = PacketCapturer(join(hass.config.config_dir, "traces"))
    CAPTURER.add_callback(on_network_capture)
    # Setup profiling
    load_profiles(join(hass.config.config_dir, STORAGE_NAME))
    add_profile_callbacks()

    def store_profiles(event):
        """Stores profiling data in home assistant conf dir"""
        save_profiles(join(hass.config.config_dir, STORAGE_NAME))
    hass.bus.async_listen(const.EVENT_HOMEASSISTANT_STOP, store_profiles)
    hass.bus.async_listen("trigger_profile_save", store_profiles)

    global DETECTION_OBJ
    DETECTION_OBJ = ThreatDetection(
        hass, "td_obj", "Threat Detection", "mdi:security-close")
    # Might require await call.
    await component.async_add_entities([DETECTION_OBJ])

    _LOGGER.info("The threat_detection component is set up!")

    def state_changed_listener(event):
        """Listens to and handle state changes in the state machine."""
        hass.async_add_job(state_changed_handler, event)

    hass.bus.async_listen(const.EVENT_STATE_CHANGED, state_changed_listener)

    return True


class ThreatDetection(Entity):
    """ Representation of threat detection state """

    def __init__(self, hass, obj_id, name, icon):
        self.entity_id = ENTITIY_ID_FORMAT.format(obj_id)
        self._hass = hass
        self._name = name
        self._icon = icon
        self._threats = []

    @property
    def should_poll(self):
        """If entity should be polled."""
        return True

    @property
    def name(self):
        """Return name of this module."""
        return self._name

    @property
    def icon(self):
        """Return the icon to be used for this entity."""
        return self._icon

    @property
    def state(self):
        """Return the current state (nbr of detections)."""
        return len(self._threats)

    @property
    def state_attributes(self):
        """Return state attributes of the component"""
        return {'version': '0.1.0.0',
                'latest_threat': self.get_latest_threat()}

    def add_threats(self, threats):
        """Adds newly found threats."""
        if isinstance(threats, list):
            self._threats.extend(threats)
        elif isinstance(threats, str):
            self._threats.append(threats)
        else:
            self._threats.append(str(threats))

    def get_latest_threat(self):
        """Retrieves the latest registered threat."""
        if self._threats:
            return self._threats[-1]


def state_changed_handler(event):
    """Handles what to do in the event of a state change."""
    event_dict = event.as_dict()
    entity_id = event_dict['data']['entity_id']
    new_state_dict = event_dict['data']['new_state'].as_dict()
    if event_dict['data']['old_state'] is not None:
        old_state_dict = event_dict['data']['old_state'].as_dict()
    else:
        old_state_dict = event_dict['data']['old_state'] = "NONE"
    _LOGGER.debug("State has changed! Event:  %s\n"
                  "ENTITY_ID: %s\n"
                  "NEW_STATE: %s\n"
                  "OLD_STATE: %s",
                  event_dict, entity_id, new_state_dict, old_state_dict)


def on_network_capture(packet_list):
    """Called when a network packet list has been captured. """
    _LOGGER.info(packet_list)
    for packet in packet_list:
        handle_packet(packet)
    _LOGGER.info("Done processing packets")


def get_gateways():
    return []


def add_profile_callbacks():
    pass













# --------------------------------- PROFILING ------------------------------ #
PROFILES = {}
IGNORE_LIST = []

class Profile:

    PROFILERS = []
    ANALYSERS = []

    def __init__(self, id):
        self._id = id
        self._data = {}
        self.profiling_length = 3600*24    # one day
        self._profiling_end = (datetime.now()+
                               timedelta(seconds=self.profiling_length))

    def is_profiling(self):
        """Checks whether the profile is in the training phase"""
        return datetime.now() < self._profiling_end
        
    def id(self):
        """Retrieves the unique ID of this profile"""
        return self._id

    def get_data(self, path):
        data = self._data
        for prop in path:
            data = Profile.get_prop(data, prop, create_if_needed=False)
        return data

    def set_data(self, path, value):
        data = self._data
        # Traverse data
        for prop, cls in path[:-1]:
            data = Profile.get_prop(data, prop, cls)

        # Create container for data if not existant
        Profile.get_prop(data, path[-1], type(value))
        # Fill container with data
        data[path[-1]] = value

    def __str__(self):
        return str(self._data)
        # return Profile.tree_to_string('Profile', self._data)

    @staticmethod
    def get_prop(obj, prop, new_cls=None, create_if_needed=True):
        cls = type(obj)
        if cls == dict:
            if create_if_needed and obj.get(prop) is None:
                obj[prop] = new_cls()
            return obj.get(prop)
        elif cls == list:
            if create_if_needed and prop >= len(obj):
                for i in range(prop-len(obj)):
                    obj.append(None)
                obj.append(new_cls())
            return obj[prop]
        else:
            return None

    @staticmethod
    def tree_to_string(name, data, level=0):
        res = '  '*level + str(name) + ': '
        if type(data) == dict:
            res += '\n'
            for prop in data:
                res += Profile.tree_to_string(prop, data[prop], level+1)
            return res
        elif type(data) == list:
            res += '\n'
            for i in range(len(data)):
                res += Profile.tree_to_string(str(i), data[i], level+1)
            return res
        else:
            return res + str(data) + '\n'

    @staticmethod
    def add_profiler(profiler):
        """Input should be on the form (condition, [(save_property, value_func)])"""
        if profiler not in Profile.PROFILERS:
            Profile.PROFILERS.append(profiler)
        
    @staticmethod
    def add_analyser(analyser):
        """Input should be on the form (condition, analyse_func)"""
        if analyser not in Profile.ANALYSERS:
            Profile.ANALYSERS.append(analyser)




def handle_packet(packet):
    """Handles incoming packets and routes them to their destination"""
    # Find/create matching profiles
    sender, receiver = get_communicators(packet)
    profiles = find_profiles(sender, receiver)
    
    profiling = len([p for p in profiles if p.is_profiling()]) > 0
    res = []
    for profile in profiles:
        if profiling:    
            profile_packet(profile, packet)
        else:
            res.extend(analyse_packet(profile, packet))
    return [r for r in res if r is not None]
    

def profile_packet(profile, packet):
    for condition, save_props in Profile.PROFILERS:
        if condition(profile, packet):
            for prop, value_func in save_props:
                profile.set_data(prop, value_func(profile, packet))


def analyse_packet(profile, packet):
    res = []
    for condition, analyse_func in Profile.ANALYSERS:
        if condition(profile, packet):
            res.append(analyse_func(profile, packet))
    return res


def find_profiles(sender, receiver):
    """Finds or creates the profiles for the communicating parties"""
    res = [get_profile(sender), get_profile(receiver)]
    return [r for r in res if r is not None]


def get_profile(id):
    """Retrieves/creates the profile with the given ID"""
    if id not in IGNORE_LIST:
        if PROFILES.get(id) is None:
            PROFILES[id] = Profile(id)
        return PROFILES.get(id)

        
def get_communicators(packet):
    from scapy.all import Ether
    if packet.haslayer(Ether):
        return (packet.src, packet.dst)
    else:
        return (None, None)


def ignore_device(id):
    """Appends an ID to the profiling ignore list"""
    IGNORE_LIST.append(id)


def save_profiles(filename):
    """Saves all current profiles to a savefile"""
    _LOGGER.info("Saving profile data: " + ' ; '.join([str(p) for p in PROFILES]))
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














# ------------------------------- NETWORKING ------------------------------- #
class PacketCapturer:
    """Reads network packet captures and provides a way to register
       callbacks to receive this data """

    from watchdog.events import FileSystemEventHandler

    def __init__(self, path):
        """Initializes and starts to monitor the given path """
        self.callbacks = []
        from watchdog.observers import Observer
        self.observer = Observer()
        self.observer.schedule(self.PacketCaptureHandler(self.on_event), path)
        self.observer.start()

    def on_event(self, packet_list):
        """Distributes new packets to registered callbacks """
        for callback in self.callbacks:
            callback(packet_list)

    def add_callback(self, callback):
        """Registers a callback for data """
        if callback is not None:
            self.callbacks.append(callback)

    def __del__(self):
        """Stop and remove path monitoring """
        if self.observer is not None:
            self.observer.stop()
            self.observer.join()
            self.observer = None

    class PacketCaptureHandler(FileSystemEventHandler):
        """Handler to handle pcap file read preprocessing """

        def __init__(self, callback):
            """Create a handler """
            super(PacketCapturer.PacketCaptureHandler, self).__init__()
            self.callback = callback
            self.lock = Lock()

        def on_created(self, event):
            """Reads, interprets and removes all pcap files in the monitored
               folder except for the newest one (due to tcpdump impl.) """
            # Avoid concurrent reads from same files
            if not self.lock.acquire(blocking=False):
                return

            from scapy.all import rdpcap, PacketList
            path = dirname(event.src_path)
            # Ignore directories and the most recent created file
            all_files = [f for f in os.listdir(path) if isfile(join(path, f))]
            files = list(filter(pcap_filter(event.src_path), all_files))
            # Parse data from pcap format
            _LOGGER.info("Reading network files")
            data = [safe_exc(rdpcap, [], join(path, file)) for file in files]
            _LOGGER.info("Done reading network files")
            # Remove read files so data are only read once
            for file in files:
                os.remove(join(path, file))
            # Allow new files to be read
            self.lock.release()
            # Notify the user of the found data
            self.callback(PacketList([pkt for pkts in data for pkt in pkts]))


def safe_exc(func, default, *args):
    """Excecutes a function and discards all exceptions it causes."""
    try:
        return func(*args)
    except Exception:
        _LOGGER.warning("Caught an exception for Threat Detection.")
        return default


def pcap_filter(ignore_file):
    """Create filter to use for PacketCaptureHandler """
    def filter_func(file):
        """Filter to select .pcap files and ignore the given file """
        return file.endswith('.pcap') and file != basename(ignore_file)
    return filter_func