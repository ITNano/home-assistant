"""
Component for detecting threats against the smart home.

For more information on this component see
todo add where to find documentation for the component.
"""

import subprocess
import os
from os.path import dirname, basename, isfile, join
from threading import Lock
from datetime import datetime, timedelta
import asyncio
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
DEVICES = {}
DETECTION_OBJ = None
STORAGE_NAME = 'td_profiles.pcl'
KNOWN_DEVICES = 'known_devices.yaml'


@asyncio.coroutine
def async_setup(hass, config=None):
    """Set up the threat_detection component."""
    component = EntityComponent(_LOGGER, DOMAIN, hass)
    # yield from component.async_setup(config)

    yield from async_load_device_data(hass)

    # Set up network properties
    for device in get_gateways():
        ignore_device(device)
    ignore_device('ff:ff:ff:ff:ff:ff')

    # Start capturing packets from network
    global CAPTURER
    CAPTURER = PacketCapturer(join(hass.config.config_dir, "traces"))
    CAPTURER.add_callback(on_network_capture)
    # Setup profiling
    load_profiles(join(hass.config.config_dir, STORAGE_NAME))
    add_profile_callbacks()

    def store_profiles(event):
        """Store profiling data in home assistant conf dir."""
        save_profiles(join(hass.config.config_dir, STORAGE_NAME))
    hass.bus.async_listen(const.EVENT_HOMEASSISTANT_STOP, store_profiles)
    hass.bus.async_listen("trigger_profile_save", store_profiles)

    global DETECTION_OBJ
    DETECTION_OBJ = ThreatDetection(
        hass, "td_obj", "Threat Detection", "mdi:security-close")
    # Might require await call.
    yield from component.async_add_entities([DETECTION_OBJ])

    _LOGGER.info("The threat_detection component is set up!")

    def state_changed_listener(event):
        """Listen to and handle state changes in the state machine."""
        hass.async_add_job(state_changed_handler, event)

    hass.bus.async_listen(const.EVENT_STATE_CHANGED, state_changed_listener)

    return True


class ThreatDetection(Entity):
    """Representation of threat detection state."""

    def __init__(self, hass, obj_id, name, icon):
        """Initiate this object."""
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
        """Return the current state, i.e. number of detections."""
        return len(self._threats)

    @property
    def state_attributes(self):
        """Return state attributes of the component."""
        return {'version': '0.1.0.0',
                'latest_threat': self.get_latest_threat()}

    def add_threats(self, threats):
        """Add newly found threats."""
        if isinstance(threats, list):
            self._threats.extend(threats)
        elif isinstance(threats, str):
            self._threats.append(threats)
        else:
            self._threats.append(str(threats))

    def get_latest_threat(self):
        """Retrieve the latest registered threat."""
        if self._threats:
            return self._threats[-1]


def state_changed_handler(event):
    """Handle what to do in the event of a state change."""
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


@asyncio.coroutine
def async_load_device_data(hass):
    """Load meta data about devices from hass configuration into DEVICES."""
    devices = yield from hass.components.device_tracker.async_load_config(
        os.path.join(hass.config.config_dir, KNOWN_DEVICES), hass, 0)
    for device in devices:
        device_id = str(device.mac).lower()
        DEVICES.update({device_id: {'entity_id': device.entity_id,
                                    'name': device.name}})

        # Backwards compat (add devices already existing)
        if PROFILES.get(device_id):
            for prop in DEVICES[device_id]:
                PROFILES.set_data([prop], DEVICES[device_id][prop])


def get_device_information(device_id):
    """Retrieve device meta data."""
    return DEVICES.get(device_id, {'name': 'Unknown'})


def on_network_capture(packet_list):
    """Called when a network packet list has been captured."""
    _LOGGER.info(packet_list)
    for packet in packet_list:
        handle_packet(packet)
    _LOGGER.info("Done processing packets")


def get_gateways():
    """Retrieve the mac addresses of all network gateways on the device."""
    cmd = (" ip neigh | grep \"$(ip route list | grep default | cut -d\\  -f3"
           " | uniq) \" | cut -d\\  -f5 | uniq ")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
    (output, err) = proc.communicate()
    if not err:
        return str(output.decode()).splitlines()


# ------------------------ PROFILERS and ANALYSERS ------------------------- #
def add_profile_callbacks():
    """Create default profilers and analysers and activates them."""
    from scapy.all import Ether, IP, IPv6, TCP, UDP
    eth_profiler = (lambda prof, pkt: pkt.haslayer(Ether),
                    [map_packet_prop(eth_prop, 'src', Ether, 'src'),
                     map_packet_prop(eth_prop, 'dst', Ether, 'dst'),
                     transform_prop(eth_prop, 'count', 0, increase)])
    ip_profiler = (lambda prof, pkt: pkt.haslayer(IP),
                   [map_packet_prop(ipvx_prop(IP), 'src', IP, 'src'),
                    map_packet_prop(ipvx_prop(IP), 'dst', IP, 'dst'),
                    transform_prop(ipvx_prop(IP), 'count', 0, increase)])
    ipv6_profiler = (lambda prof, pkt: pkt.haslayer(IPv6),
                   [map_packet_prop(ipvx_prop(IPv6), 'src', IPv6, 'src'),
                    map_packet_prop(ipvx_prop(IPv6), 'dst', IPv6, 'dst'),
                    transform_prop(ipvx_prop(IPv6), 'count', 0, increase)])
    tcp_profiler = (lambda prof, pkt: pkt.haslayer(TCP),
                    [map_packet_prop(tcp_prop, 'src', IP, 'sport'),
                     map_packet_prop(tcp_prop, 'dst', IP, 'dport'),
                     transform_prop(tcp_prop, 'count', 0, increase),
                     transform_prop(tcp_prop, 'minsize', 99999, min_size(TCP)),
                     transform_prop(tcp_prop, 'maxsize', 0, max_size(TCP))])
    udp_profiler = (lambda prof, pkt: pkt.haslayer(UDP),
                    [map_packet_prop(udp_prop, 'src', IP, 'sport'),
                     map_packet_prop(udp_prop, 'dst', IP, 'dport'),
                     transform_prop(udp_prop, 'count', 0, increase),
                     transform_prop(udp_prop, 'minsize', 99999, min_size(UDP)),
                     transform_prop(udp_prop, 'maxsize', 0, max_size(UDP))])
    Profile.add_profiler(eth_profiler)
    Profile.add_profiler(ip_profiler)
    Profile.add_profiler(ipv6_profiler)
    Profile.add_profiler(tcp_profiler)
    Profile.add_profiler(udp_profiler)
    
    ddos_analyser_ipv4 = (ddos_condition(IP), check_ddos(IP))
    ddos_analyser_ipv6 = (ddos_condition(IPv6), check_ddos(IPv6))
    Profile.add_analyser(ddos_analyser_ipv4)
    Profile.add_analyser(ddos_analyser_ipv6)


def map_packet_prop(layer_func, prop, layer, prop_name):
    """Profiler help function to map a packet property into a profile."""
    return (lambda prof, pkt: layer_func(prof, pkt, prop, True),
            lambda prof, pkt: pkt.getlayer(layer).getfieldval(prop_name))


def transform_prop(layer_func, prop, defval, func):
    """Profiler help function to update a property.

    Performs some sort of transformation of a property within a profile
    (e.g. count appearances, max/min values, ...)
    """
    def val_func(prof, pkt):
        """Apply prop from profile to the given function func(pkt, x)."""
        func(pkt, profile_data(prof, layer_func(prof, pkt, prop), defval))
    return lambda prof, pkt: layer_func(prof, pkt, prop, True), val_func


def increase(_, val):
    """Increase the received value by 1."""
    return val+1


def max_size(layer):
    """Retrieve a function which retrieves the maximum packet length."""
    def func(pkt, val):
        """Retrieve the maximum packet length."""
        return max(val, len(pkt.getlayer(layer)))
    return func


def min_size(layer):
    """Retrieve a function which retrieves the minimum packet length."""
    def func(pkt, val):
        """Retrieve the minimum packet length."""
        return min(val, len(pkt.getlayer(layer)))
    return func


def eth_prop(prof, pkt, name, types=False):
    """Return the path of an Ethernet packet.

    types denotes whether this path should include the type of each path
    element, i.e. if it is supposed to be used with profile.set_data.
    """
    mac = pkt.dst if pkt.src == prof.get_id() else pkt.src
    return [typechoice(mac, dict, types), name]


def ipvx_prop(proto):
    """Return a function to retrieve the path of an IPv4/IPv6 packet."""
    def ip_prop(prof, pkt, name, types=False):
        """Return the path of an IP packet.

        types denotes whether this path should include the type of each path
        element, i.e. if it is supposed to be used with profile.set_data.
        """
        ip_layer = pkt.getlayer(proto)
        mac = pkt.dst if pkt.src == prof.get_id() else pkt.src
        ip_addr = ip_layer.dst if pkt.src == prof.get_id() else ip_layer.src
        return [typechoice(mac, dict, types),
                typechoice(ip_addr, dict, types), name]


def tcp_prop(prof, pkt, name, types=False):
    """Return the path of a TCP packet.

    types denotes whether this path should include the type of each path
    element, i.e. if it is supposed to be used with profile.set_data.
    """
    from scapy.all import TCP
    return ip_layer4_prop(prof, pkt, TCP, 'TCP', name, types)


def udp_prop(prof, pkt, name, types=False):
    """Return the path of a UDP packet.

    types denotes whether this path should include the type of each path
    element, i.e. if it is supposed to be used with profile.set_data.
    """
    from scapy.all import UDP
    return ip_layer4_prop(prof, pkt, UDP, 'UDP', name, types)


def ip_layer4_prop(prof, pkt, layer, layer_name, name, types=False):
    """Return the path of a UDP/TCP packet.

    layer denotes the scapy layer object whilst layer_name is the canonical
    name of the layer. types denotes whether this path should include
    the type of each path element, i.e. if it is supposed to be used
    with profile.set_data.
    """
    from scapy.all import IP
    ip_layer = pkt.getlayer(IP)
    layer4 = pkt.getlayer(layer)
    mac = pkt.dst if pkt.src == prof.get_id() else pkt.src
    ip_addr = ip_layer.dst if pkt.src == prof.get_id() else ip_layer.src
    l4_port = layer4.dport if pkt.src == prof.get_id() else layer4.sport
    return [typechoice(mac, dict, types),
            typechoice(ip_addr, dict, types),
            typechoice(layer_name + str(l4_port), dict, types), name]


def typechoice(value, cls, use_type):
    """Retrieve either the value or a tuple (value, cls)."""
    return value, cls if use_type else value


def profile_data(profile, path, default=None):
    """Retrieve profile data with a fallback default value."""
    res = profile.get_data(path)
    if res is None:
        return default
    return res


def botnet_condition(proto):
    return lambda prof, pkt: pkt.haslayer(proto) and prof.get_id() == pkt.src


def check_botnet(proto):
    def check(prof, pkt):
        records = profile_data(prof, ipvx_prop(proto)(prof, pkt, 'count'))
        if not records:
            ip = pkt.getlayer(proto)
            return ("Potential botnet activity detected. Device %s sent data"
                    "to %s at %s"
                   ) % (ip.src, ip.dst, datetime.now().strftime('%H:%M'))
    return check

# --------------------------------- PROFILING ------------------------------ #
PROFILES = {}
IGNORE_LIST = []


class Profile:
    """Representation of a device profile."""

    PROFILERS = []
    ANALYSERS = []

    def __init__(self, identifier):
        """Initiate the profile object."""
        self._id = identifier
        self._data = {}
        self.profiling_length = 3600 * 24    # one day
        self._profiling_end = (datetime.now() +
                               timedelta(seconds=self.profiling_length))

    def is_profiling(self):
        """Check whether the profile is in the training phase."""
        return datetime.now() < self._profiling_end

    def get_id(self):
        """Retrieve the unique ID of this profile."""
        return self._id

    def get_data(self, path):
        """Retrieve data from a path (a list of hierarchical names)."""
        data = self._data
        for prop in path:
            data = Profile.get_prop(data, prop, create_if_needed=False)
        return data

    def set_data(self, path, value):
        """Set data on an annotated path.

        The path should be a list on the form
        [(name, type), (name, type), .... , (name, type), name].
        """
        data = self._data
        # Traverse data
        for prop, cls in path[:-1]:
            data = Profile.get_prop(data, prop, cls)

        # Create container for data if not existant
        Profile.get_prop(data, path[-1], type(value))
        # Fill container with data
        data[path[-1]] = value

    def __str__(self):
        """Retrieve a string representation of this object."""
        return str(self._data)

    @staticmethod
    def get_prop(obj, prop, new_cls=None, create_if_needed=True):
        """Retrieve a property of an object and might create it if needed.

        The parameter new_cls() is required if create_if_needed is True.
        """
        cls = type(obj)
        if cls == dict:
            if create_if_needed and obj.get(prop) is None:
                obj[prop] = new_cls()
            return obj.get(prop)
        elif cls == list:
            if create_if_needed and prop >= len(obj):
                for _ in range(prop-len(obj)):
                    obj.append(None)
                obj.append(new_cls())
            return obj[prop]
        else:
            return None

    @staticmethod
    def tree_to_string(name, data, level=0):
        """Convert this object to a string representation for debugging."""
        res = '  '*level + str(name) + ': '
        if isinstance(data, dict):
            res += '\n'
            for prop in data:
                res += Profile.tree_to_string(prop, data[prop], level+1)
            return res
        elif isinstance(data, list):
            res += '\n'
            for i, val in enumerate(data):
                res += Profile.tree_to_string(str(i), val, level+1)
            return res

        return res + str(data) + '\n'

    @staticmethod
    def add_profiler(profiler):
        """Add a profiler to all profiles.

        Profilers should be on the following form:
        (condition, [(save_property, value_func)])
        """
        if profiler not in Profile.PROFILERS:
            Profile.PROFILERS.append(profiler)

    @staticmethod
    def add_analyser(analyser):
        """Add an analyser to all profiles.

        An analyser should be a tuple on the form (condition, analyse_func)
        """
        if analyser not in Profile.ANALYSERS:
            Profile.ANALYSERS.append(analyser)


def handle_packet(packet):
    """Handle incoming packets and route them to their destination."""
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
    """Profile packets against matching profilers."""
    for condition, save_props in Profile.PROFILERS:
        if condition(profile, packet):
            for prop_func, value_func in save_props:
                profile.set_data(prop_func(profile, packet),
                                 value_func(profile, packet))


def analyse_packet(profile, packet):
    """Analyse packets according to matching analysers."""
    res = []
    for condition, analyse_func in Profile.ANALYSERS:
        if condition(profile, packet):
            res.append(analyse_func(profile, packet))
    return res


def find_profiles(sender, receiver):
    """Find or create the profiles for the communicating parties."""
    res = [get_profile(sender), get_profile(receiver)]
    return [r for r in res if r is not None]


def get_profile(identifier):
    """Retrieve/create the profile with the given ID."""
    if identifier not in IGNORE_LIST:
        if PROFILES.get(identifier) is None:
            PROFILES[identifier] = Profile(identifier)
            device_info = get_device_information(identifier)
            for prop in device_info:
                PROFILES[identifier].set_data([prop], device_info[prop])
        return PROFILES.get(identifier)


def get_communicators(packet):
    """Retrieve the IDs of communicating parts from a packet.

    NOTE: This is not modular atm.
    """
    from scapy.all import Ether
    if packet.haslayer(Ether):
        return packet.src, packet.dst

    return None, None


def ignore_device(identifier):
    """Append an ID to the profiling ignore list."""
    IGNORE_LIST.append(identifier)


def save_profiles(filename):
    """Save all current profiles to a savefile."""
    text = ("{" + ", ".join(["'" + str(p) + "': " + str(PROFILES[p])
                             for p in PROFILES]) + "}")
    _LOGGER.info("Saving profile data: %s", text.replace("'", '"'))
    with open(filename, 'wb') as output:
        pickle.dump(PROFILES, output, pickle.HIGHEST_PROTOCOL)


def load_profiles(filename):
    """Load saved profiles from a savefile."""
    try:
        with open(filename, 'rb') as infile:
            global PROFILES
            PROFILES = pickle.load(infile)
    except FileNotFoundError:
        print("WARNING: Cannot load entries from " + str(filename) + ".")


def all_profiles():
    """Retrieve all current profiles."""
    return PROFILES


# ------------------------------- NETWORKING ------------------------------- #
class PacketCapturer:
    """Read network captures and provides this data through callbacks."""

    from watchdog.events import FileSystemEventHandler

    def __init__(self, path):
        """Initialize and starts to monitor the given path."""
        self.callbacks = []
        from watchdog.observers import Observer
        self.observer = Observer()
        self.observer.schedule(self.PacketCaptureHandler(self.on_event), path)
        self.observer.start()

    def on_event(self, packet_list):
        """Distribute new packets to registered callbacks."""
        for callback in self.callbacks:
            callback(packet_list)

    def add_callback(self, callback):
        """Register a callback for data."""
        if callback is not None:
            self.callbacks.append(callback)

    def __del__(self):
        """Stop and remove path monitoring."""
        if self.observer is not None:
            self.observer.stop()
            self.observer.join()
            self.observer = None

    class PacketCaptureHandler(FileSystemEventHandler):
        """Handler to handle pcap file read preprocessing."""

        def __init__(self, callback):
            """Create a handler."""
            super(PacketCapturer.PacketCaptureHandler, self).__init__()
            self.callback = callback
            self.lock = Lock()

        def on_created(self, event):
            """Read, interpret and remove existing pcap files."""
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
    """Execute a function and discards all exceptions it causes."""
    try:
        return func(*args)
    except Exception:
        _LOGGER.warning("Caught an exception for Threat Detection.")
        return default


def pcap_filter(ignore_file):
    """Create filter to use for PacketCaptureHandler."""
    def filter_func(file):
        """Filter to select .pcap files and ignore the given file."""
        return file.endswith('.pcap') and file != basename(ignore_file)
    return filter_func
