"""
Component for detecting threats against the smart home.

For more information on this component see
todo add where to find documentation for the component.
"""

import subprocess
import os
import json
from os.path import dirname, basename, isfile, join, getsize
from threading import Lock, Timer
from datetime import datetime, timedelta
import asyncio
import pickle
import logging
import voluptuous as vol
from homeassistant.helpers.entity import Entity
from homeassistant.helpers.entity_component import EntityComponent
import homeassistant.const as const
import homeassistant.helpers.config_validation as cv

_LOGGER = logging.getLogger(__name__)

DOMAIN = "threat_detection"

ENTITIY_ID_FORMAT = DOMAIN + ".{}"

REQUIREMENTS = ['pypacker==4.5', 'watchdog==0.9.0']

# Configuration input
CONF_PROFILING_TIME = 'profiling_time'
CONF_DEBUG_EVILTWIN = 'debug_eviltwin'
DEF_PROFILING_TIME = 86400
# Here we need to add everything that is required from the conf-file if we
# need some input from the user.
PLATFORM_SCHEMA = vol.Schema({
    DOMAIN: vol.Schema({
        vol.Optional(CONF_PROFILING_TIME,
                     default=DEF_PROFILING_TIME): cv.positive_int,
        vol.Optional(CONF_DEBUG_EVILTWIN, default=None) : cv.string,
    })
}, extra=vol.ALLOW_EXTRA)

CAPTURER = None
BEACON_CAPTURER = None
DEVICES = {}
DEVICE_TYPES = {}
DETECTION_OBJ = None
PROFILING_TIME = DEF_PROFILING_TIME
STORAGE_NAME = 'td_profiles.pcl'
KNOWN_DEVICES = 'known_devices.yaml'


@asyncio.coroutine
def async_setup(hass, config=None):
    """Set up the threat_detection component."""
    component = EntityComponent(_LOGGER, DOMAIN, hass)
    yield from component.async_setup(config)
    
    global PROFILING_TIME
    # FIXME: Temporary solution.
    PROFILING_TIME = config[DOMAIN][0].get(CONF_PROFILING_TIME,
                                        DEF_PROFILING_TIME)

    yield from async_load_device_data(hass, config)

    # Set up network properties
    for device in get_gateways():
        ignore_device(device)
    ignore_device('ffffffffffff')

    # Start capturing packets from network
    global CAPTURER
    CAPTURER = PacketCapturer(join(hass.config.config_dir, "traces"))
    CAPTURER.add_callback(on_network_capture)
    global BEACON_CAPTURER
    beacon_folder = join(hass.config.config_dir, "traces", "beacon")
    BEACON_CAPTURER = PacketCapturer(beacon_folder)
    BEACON_CAPTURER.add_callback(on_network_beacon_capture)
    # Setup profiling
    add_profile_callbacks()
    load_profiles(join(hass.config.config_dir, STORAGE_NAME))

    debug_eviltwin = config[DOMAIN][0].get(CONF_DEBUG_EVILTWIN, None)
    if debug_eviltwin:
        with open(debug_eviltwin, encoding='utf-8') as infile:
            data = json.load(infile)
        profile = get_profile('AP_' + data.get('ap', 'ASUS'))
        profile.data['rssi'] = data['rssi']
        profile.start_profile_end_countdown(30)

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
    #_LOGGER.debug("State has changed! Event:  %s\n"
    #              "ENTITY_ID: %s\n"
    #              "NEW_STATE: %s\n"
    #              "OLD_STATE: %s",
    #              event_dict, entity_id, new_state_dict, old_state_dict)


@asyncio.coroutine
def async_load_device_data(hass, config):
    """Load meta data about devices from hass configuration into DEVICES."""
    devices = yield from hass.components.device_tracker.async_load_config(
        os.path.join(hass.config.config_dir, KNOWN_DEVICES), hass, 0)

    global DEVICE_TYPES
    DEVICE_TYPES = get_configuration_types(config)
    
    for device in devices:
        device_id = str(device.mac).lower()
        DEVICES.update({device_id: {'entity_id': device.entity_id,
                                    'name': device.name}})
    for profile in PROFILES:
        profile.update_meta_properties()


def get_configuration_types(config):
    res = {}
    for type in config:
        addresses = get_addresses_from_config(config[type])
        for address in addresses:
            res[address] = type
    return res


def get_addresses_from_config(config):
    res = []
    valid_keys = ['host', 'ip_address', 'mac', 'device']
    valid_multikeys = ['hosts', 'devices']
    if isinstance(config, dict):
        for key, value in config.items():
            if key in valid_keys:
                res.append(value)
            elif key in valid_multikeys:
                res.extend(value)
            else:
                res.extend(get_addresses_from_config(config[key]))
    elif isinstance(config, list):
        for entry in config:
            res.extend(get_addresses_from_config(entry))
    return res


def get_device_information(device_id):
    """Retrieve device meta data."""
    return DEVICES.get(device_id, {'name': 'Unknown'})


def on_network_capture(packet_list):
    """Called when a network packet list has been captured."""
    from pypacker.layer12.ethernet import Ethernet
    forward_packets(packet_list, Ethernet, 'ethernet')


def on_network_beacon_capture(packet_list):
    from pypacker.layer12.radiotap import Radiotap
    forward_packets(packet_list, Radiotap, 'beacon')


def forward_packets(packet_list, wrapper_class, type=''):
    # Timestamp, buffer
    _LOGGER.debug("Forwarding %i %s packets" % (len(packet_list), type))
    for ts, buf in packet_list:
        handle_packet(wrapper_class(buf))
    _LOGGER.debug("Done processing packets")


def get_gateways():
    """Retrieve the mac addresses of all network gateways on the device."""
    cmd = (" ip neigh | grep \"$(ip route list | grep default | cut -d\\  -f3"
           " | uniq) \" | cut -d\\  -f5 | uniq ")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
    (output, err) = proc.communicate()
    if not err:
        return [gw.replace(':', '') for gw in str(output.decode()).splitlines()]


# ------------------------ PROFILERS and ANALYSERS ------------------------- #
def add_profile_callbacks():
    """Create default profilers and analysers and activates them."""
    Profile.add_profiler(get_eth_profiler())
    Profile.add_profiler(get_ip_profiler())
    Profile.add_profiler(get_tcp_profiler())
    Profile.add_profiler(get_udp_profiler())


def get_eth_profiler():
    from pypacker.layer12.ethernet import Ethernet
    def profile_eth(profile, pkt):
        # Update eventual identifiers
        if eth_addr(pkt.src) == profile.get_id():
            profile.add_identifier(pretty_eth_addr(pkt.src))
        else:
            profile.add_identifier(pretty_eth_addr(pkt.dst))

        # Profile the rest
        addr = get_eth_address(profile, pkt)
        if not profile.data.get(addr):
            profile.data[addr] = {}
        container = profile.data[addr]
        container['src'] = eth_addr(pkt.src)
        container['dst'] = eth_addr(pkt.dst)
        container['count'] = container.get('count', 0) + 1

    return {'device_selector': lambda prof: True,
            'condition': lambda prof, pkt: pkt[Ethernet],
            'profiler_func': profile_eth}


def get_ip_profiler():
    from pypacker.layer3 import ip, ip6
    def profile_ip(profile, pkt):
        eth_address = get_eth_address(profile, pkt)
        ip_address = get_ip_address(profile, pkt)
        if not profile.data[eth_address].get(ip_address):
            profile.data[eth_address][ip_address] = {}
        container = profile.data[eth_address][ip_address]
        layer = pkt[ip.IP] if pkt[ip.IP] else pkt[ip6.IP6]
        my_ip = pretty_ip_addr(layer.src) if eth_addr(pkt.src) == profile.get_id() else pretty_ip_addr(layer.dst)
        profile.add_identifier(my_ip)
        container['src'] = ip_addr(layer.src)
        container['dst'] = ip_addr(layer.dst)
        container['count'] = container.get('count', 0) + 1

    def condition(profile, pkt):
        return pkt[ip.IP] or pkt[ip6.IP6]

    return {'device_selector': lambda prof: True,
            'condition': condition,
            'profiler_func': profile_ip}


def get_tcp_profiler():
    from pypacker.layer4 import tcp
    def profile_tcp(profile, pkt):
        eth_address = get_eth_address(profile, pkt)
        ip_address = get_ip_address(profile, pkt)
        tcp_address = get_tcp_address(profile, pkt)
        if not profile.data[eth_address][ip_address].get(tcp_address):
            profile.data[eth_address][ip_address][tcp_address] = {}
        container = profile.data[eth_address][ip_address][tcp_address]
        layer = pkt[tcp.TCP]
        container['src'] = layer.sport
        container['dst'] = layer.dport
        container['count'] = container.get('count', 0) + 1
        container['minsize'] = min(container.get('minsize', 99999), len(layer.body_bytes))
        container['maxsize'] = max(container.get('maxsize', 0), len(layer.body_bytes))

    return {'device_selector': lambda prof: True,
            'condition': lambda prof, pkt: pkt[tcp.TCP],
            'profiler_func': profile_tcp}


def get_udp_profiler():
    from pypacker.layer4 import udp
    def profile_udp(profile, pkt):
        eth_address = get_eth_address(profile, pkt)
        ip_address = get_ip_address(profile, pkt)
        udp_address = get_udp_address(profile, pkt)
        if not profile.data[eth_address][ip_address].get(udp_address):
            profile.data[eth_address][ip_address][udp_address] = {}
        container = profile.data[eth_address][ip_address][udp_address]
        layer = pkt[udp.UDP]
        container['src'] = layer.sport
        container['dst'] = layer.dport
        container['count'] = container.get('count', 0) + 1
        container['minsize'] = min(container.get('minsize', 99999), len(layer.body_bytes))
        container['maxsize'] = max(container.get('maxsize', 0), len(layer.body_bytes))

    return {'device_selector': lambda prof: True,
            'condition': lambda prof, pkt: pkt[udp.UDP],
            'profiler_func': profile_udp}


def get_address(is_sender, src, dst):
    return dst if is_sender else src


def eth_addr(raw):
    return raw.hex()


def pretty_eth_addr(raw):
    tmp = raw.hex()
    return ':'.join(tmp[2*i:2*i+2] for i in range(int(len(tmp)/2)))


def ip_addr(raw):
    return raw.hex()


def pretty_ip_addr(raw):
    if len(raw) == 4:  # IPv4
        return '.'.join([str(int.from_bytes(raw[i:i+1], byteorder='big')) for i in range(len(raw))])
    else:
        tmp = raw.hex()
        return ':'.join(tmp[2*i:2*i+2] for i in range(int(len(tmp)/2)))


def get_eth_address(profile, pkt):
    return get_address(profile.get_id() == eth_addr(pkt.src), eth_addr(pkt.src), eth_addr(pkt.dst))


def get_ip_address(profile, pkt):
    from pypacker.layer3 import ip, ip6
    layer = pkt[ip.IP] if pkt[ip.IP] else pkt[ip6.IP6]
    return get_address(profile.get_id() == eth_addr(pkt.src), ip_addr(layer.src), ip_addr(layer.dst))


def get_tcp_address(profile, pkt):
    from pypacker.layer4 import tcp
    layer = pkt[tcp.TCP]
    port = get_address(profile.get_id() == eth_addr(pkt.src), layer.sport, layer.dport)
    return "TCP" + str(port)


def get_udp_address(profile, pkt):
    from pypacker.layer4 import udp
    layer = pkt[udp.UDP]
    port = get_address(profile.get_id() == eth_addr(pkt.src), layer.sport, layer.dport)
    return "UDP" + str(port)


# --------------------------------- PROFILING ------------------------------ #
PROFILES = {}
IGNORE_LIST = []


class Profile:
    """Representation of a device profile."""

    PROFILERS = []
    ANALYSERS = []

    def __init__(self, profile_id, profiling_time=86400):
        """Initiate the profile object."""
        self._id = profile_id
        self.data = {"identifiers": []}
        self.profiling_time = profiling_time
        self._profiling_end = (datetime.now() +
                               timedelta(seconds=profiling_time))
        self.reload_profilers()
        self.reload_analysers()
        self.start_profile_end_countdown(profiling_time)

    def add_identifier(self, identifier):
        if identifier not in self.data['identifiers']:
            self.data['identifiers'].append(identifier)
            self.update_meta_properties()

    def update_meta_properties(self):
        for identifier in self.data['identifiers']:
            if DEVICE_TYPES.get(identifier):
                self.data['device_type'] = DEVICE_TYPES[identifier]
            if DEVICES.get(identifier):
                for prop in DEVICES[identifier]:
                    self.data[prop] = DEVICES[identifier][prop]
        self.reload_profilers()
        self.reload_analysers()

    def start_profile_end_countdown(self, time_left):
        """Starts a timer which calls on_profiling_end when profiling ends."""
        self._timer = Timer(time_left, self.on_profiling_end)
        self._timer.start()

    def on_profiling_end(self):
        """Runs the on_profiling_end function of all assigned profilers."""
        _LOGGER.debug("Running on_profiling_end for %s" % (self.get_id()))
        for profiler in self._profilers:
            if profiler.get('on_profiling_end'):
                profiler['on_profiling_end'](self)

    def get_profilers(self):
        """Retrieve the profilers of the profile"""
        return self._profilers

    def get_analysers(self):
        """Retrieve the analysers of the profile"""
        return self._analysers

    def reload_profilers(self):
        """Reload all profilers to keep up to date"""
        self._profilers = Profile.get_aop_list(self, Profile.PROFILERS)

    def reload_analysers(self):
        """Reload all analysers to keep up to date"""
        self._analysers = Profile.get_aop_list(self, Profile.ANALYSERS)

    def is_profiling(self):
        """Check whether the profile is in the training phase."""
        return datetime.now() < self._profiling_end

    def get_id(self):
        """Retrieve the unique ID of this profile."""
        return self._id

    def __getstate__(self):
        """Returns an representation of this object for the pickle module."""
        profiling_left = -1
        if self.is_profiling():
            profiling_left = (self._profiling_end.timestamp() -
                                  datetime.now().timestamp())
        return (self._id, self.data, self.profiling_time, profiling_left)

    def __setstate__(self, state):
        """Loads the object from a pickle object (from file)."""
        self._id, self.data, self.profiling_time, profiling_left = state
        self.reload_profilers()
        self.reload_analysers()
        _LOGGER.info("Loaded profile %s. Profiling time left: %s", self._id, str(profiling_left))
        self._profiling_end = (datetime.now() +
                               timedelta(seconds=profiling_left))
        if profiling_left >= 0:
            self.start_profile_end_countdown(profiling_left)

    def __str__(self):
        """Retrieve a string representation of this object."""
        return str(self.data)

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
            # Reload profiler list for each client
            for profile in PROFILES.values():
                if Profile.selector_matches(profile, profiler):
                    profile._profilers.append(profiler)

    @staticmethod
    def add_analyser(analyser):
        """Add an analyser to all profiles.

        An analyser should be a tuple on the form (condition, analyse_func)
        """
        if analyser not in Profile.ANALYSERS:
            Profile.ANALYSERS.append(analyser)
            # Reload analyser list for each client
            for profile in PROFILES.values():
                if Profile.selector_matches(profile, analyser):
                    profile._analysers.append(analyser)

    @staticmethod
    def get_aop_list(profile, data_list):
        """Return the list with entries matching the selector function."""
        return [entry for entry in data_list
                      if Profile.selector_matches(profile, entry)]
        
    @staticmethod
    def selector_matches(profile, entry):
        return entry['device_selector'](profile)


def handle_packet(packet):
    """Handle incoming packets and route them to their destination."""
    # Find/create matching profiles
    profile_ids = get_IDs_from_packet(packet)
    profiles = find_profiles(profile_ids)

    # If a new device is added, we must allow for old devices to include the
    # new device in their profiles.
    profiling = len([p for p in profiles if p.is_profiling()]) > 0
    res = []
    for profile in profiles:
        if profiling:
            profile_packet(profile, packet)
        else:
            profile_packet(profile, packet, only_inf=True)
            res.extend(analyse_packet(profile, packet))

    threats = [r for r in res if r is not None]
    if threats:
        DETECTION_OBJ.add_threats(threats)


def profile_packet(profile, packet, only_inf=False):
    """Profile packets against matching profilers."""
    for profiler in profile.get_profilers():
        if not only_inf or profiler.get('run_always'):
            if profiler['condition'](profile, packet):
                profiler['profiler_func'](profile, packet)


def analyse_packet(profile, packet):
    """Analyse packets according to matching analysers."""
    res = []
    for analyser in profile.get_analysers():
        if analyser['condition'](profile, packet):
            res.append(analyser['analyse_func'](profile, packet))
    return res


def find_profiles(profile_ids):
    """Find or create the profiles for the communicating parties."""
    res = [get_profile(id) for id in profile_ids]
    return [r for r in res if r is not None]


def get_profile(identifier):
    """Retrieve/create the profile with the given ID."""
    if identifier not in IGNORE_LIST:
        if PROFILES.get(identifier) is None:
            _LOGGER.info("Adding TD profile for " + str(identifier) + 
                         ". Profiling length: " + str(PROFILING_TIME) + "s")
            PROFILES[identifier] = Profile(identifier, PROFILING_TIME)
            device_info = get_device_information(identifier)
            for prop in device_info:
                PROFILES[identifier].data[prop] = device_info[prop]
        return PROFILES.get(identifier)


def get_profiles(filter_func):
    return [p for p in PROFILES if filter_func(p)]


def get_IDs_from_packet(packet):
    """Retrieve the IDs of communicating parts from a packet.

    NOTE: This is not modular atm.
    """
    from pypacker.layer12 import ethernet, radiotap, ieee80211
    if isinstance(packet, ethernet.Ethernet):
        return [eth_addr(packet.src), eth_addr(packet.dst)]
    elif isinstance(packet, radiotap.Radiotap):
        for entry in packet[ieee80211.IEEE80211.Beacon].params:
            if entry.id == 0:
                return ["AP_" + entry.body_bytes.decode('utf-8')]
    return []


def ignore_device(identifier):
    """Append an ID to the profiling ignore list."""
    IGNORE_LIST.append(identifier)


def save_profiles(filename):
    """Save all current profiles to a savefile."""
    with open(filename, 'wb') as output:
        pickle.dump(PROFILES, output, pickle.HIGHEST_PROTOCOL)

    for id, profile in PROFILES.items():
        if not id.startswith("AP_"):
            print(Profile.tree_to_string(id, profile.data))
        if id is None:
            id = '__None__'
        try:
            with open('/home/scionova/.homeassistant/profile_debug_'+id.replace(':', '.')+'.json', 'w') as jsonout:
                json.dump(profile.data, jsonout)
        except Exception as e:
            _LOGGER.exception("Could not write JSON file", exc_info=1)


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

    def __init__(self, path, recursive=False):
        """Initialize and starts to monitor the given path."""
        self.callbacks = []
        from watchdog.observers import Observer
        self.observer = Observer()
        self.observer.schedule(self.PacketCaptureHandler(self.on_event), path, recursive=recursive)
        self.observer.start()

    def on_event(self, packet_list):
        """Distribute new packets to registered callbacks."""
        for callback in self.callbacks:
            safe_exc(callback, None, packet_list)

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

            path = dirname(event.src_path)
            # Ignore directories, empty files and the file in progress
            files = [join(path, f) for f in os.listdir(path) if (
                      isfile(join(path, f)) and
                      getsize(join(path, f)) > 0 and
                      join(path, f) != event.src_path and
                      f.endswith('.pcap'))]
            # Parse data from pcap format
            _LOGGER.debug("Reading network files")
            data = [pkt for file in files for pkt in self.read_pcap(file)]
            _LOGGER.debug("Done reading network files")
            # Remove read files so data are only read once
            for file in files:
                safe_exc(os.remove, None, join(path, file))
            # Allow new files to be read
            self.lock.release()
            # Notify the user of the found data
            self.callback(data)

        def read_pcap(self, file):
            from pypacker import ppcap
            try:
                return [pkt for pkt in ppcap.Reader(filename=file)]
            except Exception as e:
                _LOGGER.warning("Could not parse packets correctly")
                return []


def safe_exc(func, default, *args):
    """Execute a function and discards all exceptions it causes."""
    try:
        return func(*args)
    except Exception:
        _LOGGER.exception("Exception in threat detection", exc_info=1)
        return default
