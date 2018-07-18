"""
Component for detecting threats against the smart home.

For more information on this component see
todo add where to find documontation for the component.
"""

import sys
import time
import os
from os.path import dirname, basename, isfile, join
from datetime import datetime, timedelta
from threading import Lock
import yaml
import asyncio
import logging
import voluptuous as vol
import homeassistant.const as const
import homeassistant.helpers.config_validation as cv
from homeassistant.helpers.entity_component import EntityComponent

_LOGGER = logging.getLogger(__name__)

DOMAIN = 'threat_detection'

ENTITIY_ID_FORMAT = DOMAIN + '.[]'

DEPENDENCIES = []

# Configuration input
CONF_TEXT = 'test'
DEFAULT_TEXT = 'default'
DEFAULT_DETECTIONS = 0
# Here we need to add everything that is required from the conf-file if we need
# some input from the user.
CONFIG_SCHEMA = vol.Schema({
    DOMAIN: vol.Schema({
        vol.Required(CONF_TEXT, default=DEFAULT_TEXT): cv.string,
    })
}, extra=vol.ALLOW_EXTRA)

CAPTURER = None
PROFILES = {}
IGNORE_LIST = ['ff:ff:ff:ff:ff:ff', '2c:4d:54:75:05:10']
STORAGE_NAME = 'td_profiles.yaml'


@asyncio.coroutine
def async_setup(hass, config=None):
    """Set up the threat_detection component."""
    # This seems to be a thing. I don't know what it does. May have to do with
    # getting things to and from dependent
    # platforms? It seems to break our stuff.
    component = EntityComponent(_LOGGER, DOMAIN, hass)

    yield from component.async_setup(config)

    userinput = config[DOMAIN].get(CONF_TEXT, DEFAULT_TEXT)

    hass.states.async_set(
        'threat_detection.Threats_Detected', DEFAULT_DETECTIONS)
    hass.states.async_set('threat_detection.Input', userinput)
    
    # Start capturing packets from network
    global CAPTURER
    CAPTURER = PacketCapturer(join(hass.config.config_dir, "traces"))
    CAPTURER.add_callback(on_network_capture)
    # Setup profiling
    load_profiles(join(hass.config.config_dir, STORAGE_NAME))
    add_profile_callbacks()
    def save_profiles(event):
        store_profiles(join(hass.config.config_dir, STORAGE_NAME))
    hass.bus.async_listen(const.EVENT_HOMEASSISTANT_STOP, save_profiles)
    hass.bus.async_listen('trigger_profile_save', save_profiles)

    _LOGGER.info("The threat_detection component is set up!")

    return True
    
def on_network_capture(packet_list):
    """Called when a network packet list has been captured """
    _LOGGER.info(packet_list)
    transfer_data_to_profile(packet_list)


# @property
# def state_attributes(self):
#     """Return state attributes of the component"""
#     return self._attributes

def safe_exc(func, default, *args):
    try:
        return func(*args)
    except:
        _LOGGER.warning("Caught an exception for Threat Detection.")
        return default


""" Handling of network traffic """
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
            if self.lock.acquire(blocking=False):
                from scapy.all import rdpcap, PacketList
                path = dirname(event.src_path)
                # Ignore directories and the most recent created file
                all_files = [f for f in os.listdir(path) if isfile(join(path, f))]
                files = list(filter(self.file_filter(event.src_path), all_files))
                # Parse data from pcap format
                data = [safe_exc(rdpcap, [], join(path, file)) for file in files]
                # Remove read files so data are only read once
                for file in files:
                    os.remove(join(path, file))
                # Notify the user of the found data
                self.callback(PacketList([pkt for pkts in data for pkt in pkts]))
                self.lock.release()
                
        def file_filter(self, ignore_file):
            """Filter to select .pcap files and ignore the given file """
            def f_filter(f):
                return f.endswith('.pcap') and f != basename(ignore_file)
            return f_filter

            

""" Handling of profiling """
def load_profiles(filename):
    try:
        with open(filename, 'r') as infile:
            indata = yaml.load(infile)
        for mac, prof in indata.items():
            if assure_profile_exists(mac):
                PROFILES[mac].profiling_end = prof['prof_end']
                PROFILES[mac].profile = prof['prof']
    except FileNotFoundError:
        # Will happen on first run due to no previous save file. 
        pass

def store_profiles(filename):
    outdata = {}
    for mac, prof in PROFILES.items():
        outdata[mac] = {'prof_end': prof.profiling_end, 'prof': prof.profile}
    _LOGGER.info(outdata)
    with open(filename, 'w') as outfile:
        yaml.dump(outdata, outfile, default_flow_style=False)

def assure_profile_exists(mac):
    if not mac in IGNORE_LIST:
        if PROFILES.get(mac) is None:
            PROFILES[mac] = Profile(mac)
        return True
    else:
        return False

def transfer_data_to_profile(packets):
    for packet in packets:
        if packet.haslayer("Ether"):
            feed_profile_data(packet.getlayer("Ether").src, packet)
            feed_profile_data(packet.getlayer("Ether").dst, packet)
        else:
            _LOGGER.debug("Unknown packet: "+packet.summary())

def feed_profile_data(mac, packet):
    if assure_profile_exists(mac):
        response = PROFILES[mac].handle_packet(packet)
        if response is not None:
            _LOGGER.warning("THREAT WARNING: "+str(response))


class Profile(object):

    updaters = []
    checkers = []

    @staticmethod
    def add_updater(callback):
        if callback is not None:
            Profile.updaters.append(callback)

    @staticmethod
    def add_checker(callback):
        if callback is not None:
            Profile.checkers.append(callback)

    def __init__(self, mac):
        self.mac = mac
        self.profiling_end = datetime.now()+timedelta(days=1)
        self.profile = {'sender': {whitelist: []}, 'receiver': {whitelist: []}}

    def is_profiling(self):
        return datetime.now() < self.profiling_end

    def handle_packet(self, packet):
        if self.is_profiling():
            self.update(packet)
        else:
            self.check(packet)

    def update(self, packet):
        [updater(self, packet) for updater in Profile.updaters]

    def check(self, packet):
        checks = (checker(self, packet) for checker in Profile.checkers)
        errors = [check for check in checks if check is not None]
        return errors if len(errors) != 0 else None

    def set(self, key, value):
        self.profile[key] = value

    def get(self, key, default_val=None):
        return self.profile.get(key, default_val)
        
        
def add_profile_callbacks():
    Profile.add_updater(update_whitelist_ip)
    Profile.add_updater(update_whitelist_tcp)
    Profile.add_updater(update_whitelist_udp)
    
""" Helpers for profile updating """
def get_IP_layer(pkt):
    if pkt.haslayer("IP"):
        return pkt.getlayer("IP")
    elif pkt.haslayer("IPv6"):
        return pkt.getlayer("IPv6")
    else:
        return None
        
def check_if_sender(profile, pkt):
    return profile.mac == pkt.getlayer("Ether").src
    
def find_whitelist_entry(profile, pkt, domain):
    macp = pkt.getlayer("Ether")
    ipp = get_IP_layer(pkt)
    is_sender = check_if_sender(profile, pkt)
    mac = macp.src if is_sender else macp.dst
    ip = ipp.src if is_sender else ipp.dst
    data = profile.get('sender') if is_sender else profile.get('receiver')
    wlists = data.get("whitelist")
    # More recent entries are more likely to be at the end of the list.
    for i, wlist in reversed(list(enumerate(wlists))):
        if wlist.get('mac') == mac or ip in wlist.get('ip', []) or
           domain in wlist.get('domain', []):
            return wlist
    # Entry not found yet, so create it.
    wlists.append({"mac": mac, "ip": [], "domain": [], protocols: {}})
    return wlists[:-1]
    
""" Handle data that is supposed to be stored """
def update_whitelist_ip(profile, pkt):
    ipp = get_IP_layer(pkt)
    if ipp is not None:
        ip = ipp.dst if check_if_sender(profile, pkt) else ipp.src
        wlist, found = find_whitelist_entry(profile, pkt, None)
        if ip not in whitelist.get("ip", []):
            whitelist["ip"].append(ip)
            
def update_whitelist_tcp(profile, pkt):
    if pkt.haslayer("TCP"):
        tcpp = pkt.getlayer("TCP")
        update_whitelist_layer4(profile, pkt, tcpp, "tcp")
        
def update_whitelist_udp(profile, pkt):
    if pkt.haslayer("UDP"):
        udpp = pkt.getlayer("UDP")
        update_whitelist_layer4(profile, pkt, udpp, "udp")
            
def update_whitelist_layer4(profile, pkt, layer, proto):
    port = layer.dport if check_if_sender(profile, pkt) else layer.sport
    wlist = find_whitelist_entry(profile, pkt)
    protocols = wlist.get("protocols")
    if protocols.get(proto) is None:
        protocols[proto] = {}
    if protocols[proto].get(port) is None:
        protocols[proto][port] = {"msgs": 0, "min_size": sys.max_size,
                                  "max_size": 0, "total_size": 0}
    data = protocols[proto][port]
    data["msgs"] += 1
    packet_len = len(layer.load)
    data["min_size"] = min(data["min_size"], packet_len)
    data["max_size"] = max(data["max_size"], packet_len)
    data["total_size"] += packet_len
    

""" Handle data that is supposed to be checked """

""" END """
    
    
