"""
Component for detecting threats against the smart home.

For more information on this component see
todo add where to find documontation for the component.
"""

import sys
import subprocess
import os
from os.path import dirname, basename, isfile, join
from datetime import datetime, timedelta
from threading import Lock
import logging
import yaml
import voluptuous as vol
import homeassistant.const as const
from homeassistant.helpers.entity import Entity
from homeassistant.helpers.entity_component import EntityComponent

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
PROFILES = {}
IGNORE_LIST = ["ff:ff:ff:ff:ff:ff"]
SUBNETS = []
DETECTION_OBJ = None
STORAGE_NAME = "td_profiles.yaml"


# @asyncio.coroutine
async def async_setup(hass, config=None):
    """Set up the threat_detection component."""
    # This seems to be a thing. I don't know what it does. May have to do with
    # getting things to and from dependent platforms?
    # It seems to break our stuff.
    component = EntityComponent(_LOGGER, DOMAIN, hass)

    # yield from component.async_setup(config)

    # Set up network properties
    IGNORE_LIST.extend(get_gateway_macs())
    SUBNETS.extend(get_subnets())

    # Start capturing packets from network
    global CAPTURER
    CAPTURER = PacketCapturer(join(hass.config.config_dir, "traces"))
    CAPTURER.add_callback(on_network_capture)
    # Setup profiling
    load_profiles(join(hass.config.config_dir, STORAGE_NAME))
    add_profile_callbacks()

    def save_profiles(event):
        """Stores profiling data in home assistant conf dir"""
        store_profiles(join(hass.config.config_dir, STORAGE_NAME))
    hass.bus.async_listen(const.EVENT_HOMEASSISTANT_STOP, save_profiles)
    hass.bus.async_listen("trigger_profile_save", save_profiles)

    global DETECTION_OBJ
    DETECTION_OBJ = ThreatDetection(
        hass, "td_obj", "Threat Detection", "mdi:security-close")
    # Might require await call.
    await component.async_add_entities([DETECTION_OBJ])

    _LOGGER.info("The threat_detection component is set up!")

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


def on_network_capture(packet_list):
    """Called when a network packet list has been captured. """
    _LOGGER.info(packet_list)
    transfer_data_to_profile(packet_list)
    _LOGGER.info("Done processing packets")


def safe_exc(func, default, *args):
    """Excecutes a function and discards all exceptions it causes."""
    try:
        return func(*args)
    except Exception:
        _LOGGER.warning("Caught an exception for Threat Detection.")
        return default


# ------------------------------- NETWORK ----------------------------- #

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


def pcap_filter(ignore_file):
    """Create filter to use for PacketCaptureHandler """
    def filter_func(file):
        """Filter to select .pcap files and ignore the given file """
        return file.endswith('.pcap') and file != basename(ignore_file)
    return filter_func


def get_gateway_macs():
    """Retrieves the mac addresses of all network gateways on the device"""
    cmd = (" ip neigh | grep \"$(ip route list | grep default | cut -d\\  -f3"
           " | uniq) \" | cut -d\\  -f5 | uniq ")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
    (output, err) = proc.communicate()
    if not err:
        return output.decode().splitlines()


def get_subnets():
    """Retrieves all subnets on the device on the form (base_ip, netmask)"""
    cmd = "ifconfig | grep netmask | awk '{print $2 \" \" $4}'"
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
    (output, err) = proc.communicate()
    if not err:
        output = output.decode()
        subnets = [find_subnet(*line.split()) for line in output.splitlines()]
        return [s for i, s in enumerate(subnets) if s not in subnets[i+1:]]


def find_subnet(ip_addr, netmask):
    """Retrieves a certain subnet by using any IP on the network and its
       netmask. The netmask should be given as a string"""
    numeric_netmask = [int(nm) for nm in netmask.split(".")]
    return get_subnet(ip_addr, numeric_netmask)


def get_subnet(ip_addr, netmask):
    """Retrieves a certain subnet by using any IP on the network and its
       netmask. The netmask should be a list[4] of integers 0-255."""
    parts = zip(ip_addr.split("."), netmask)
    base_ip = [int(ip) & nm for ip, nm in parts]
    return (base_ip, netmask)


def in_network(ip_addr):
    """Check whether the given IP is accessible in a local network"""
    if ip_addr is not None:
        return any(get_subnet(ip_addr, nm)[0] == ip2 for ip2, nm in SUBNETS)


# ------------------------------- PROFILES ----------------------------- #
def load_profiles(filename):
    """Loads device profiles from te given yaml file"""
    try:
        with open(filename, "r") as infile:
            indata = yaml.load(infile)
        for mac, prof in indata.items():
            if assure_profile_exists(mac):
                PROFILES[mac].profiling_end = prof["prof_end"]
                PROFILES[mac].profile = prof["prof"]
    except FileNotFoundError:
        # Will happen on first run due to no previous save file.
        pass


def store_profiles(filename):
    """Stores the current profiling data to the given yaml file"""
    outdata = {}
    for mac, prof in PROFILES.items():
        outdata[mac] = {"prof_end": prof.profiling_end, "prof": prof.profile}
    with open(filename, "w") as outfile:
        yaml.dump(outdata, outfile, default_flow_style=False)


def assure_profile_exists(mac):
    """Checks whether the given mac address is bound to a profile. If it
       is not, and should not explicitly be ignored, the profile is created"""
    if mac not in IGNORE_LIST:
        if PROFILES.get(mac) is None:
            PROFILES[mac] = Profile(mac)
        return True
    else:
        return False


def transfer_data_to_profile(packets):
    """Callback for PacketCapturer. Feeds packets into the correct profiles
       in order to handle updates/checks according to profilings"""
    for packet in packets:
        if packet.haslayer("Ether"):
            feed_profile_data(packet.getlayer("Ether").src, packet)
            feed_profile_data(packet.getlayer("Ether").dst, packet)
        else:
            _LOGGER.debug("Unknown packet: %s", packet.summary())


def feed_profile_data(mac, packet):
    """Makes sure the given mac has a profile and feeds the packet to it"""
    if assure_profile_exists(mac):
        response = PROFILES[mac].handle_packet(packet)
        if response is not None:
            _LOGGER.warning("THREAT WARNING: %s", str(response))
            DETECTION_OBJ.add_threats(response)


class Profile(object):
    """Holds data and functionality to profile a device"""

    updaters = []
    checkers = []

    @staticmethod
    def add_updater(callback):
        """Adds a callback to be run when profile should be trained
           against incoming packets """
        if callback is not None:
            Profile.updaters.append(callback)

    @staticmethod
    def add_checker(callback):
        """Adds a callback to be run when profile integrity should
           be checked against incoming packets"""
        if callback is not None:
            Profile.checkers.append(callback)

    def __init__(self, mac):
        """Initialize the profile"""
        self.mac = mac
        self.profiling_end = datetime.now()+timedelta(days=1)
        self.profile = {"ip": [], "send": {"whitelist": []},
                        "recv": {"whitelist": []}}

    def is_profiling(self):
        """Checks whether the profile is in the training phase"""
        return datetime.now() < self.profiling_end

    def handle_packet(self, packet):
        """Redirects incoming packets based on whether the profile is in
           training or checking mode"""
        if self.is_profiling():
            self.update(packet)
        else:
            return self.check(packet)

    def update(self, packet):
        """Calls all functions to update the profile with packet data"""
        for updater in Profile.updaters:
            updater(self, packet)

    def check(self, packet):
        """Check whether the incoming packet is accepted by all aspects
           of the trained profile. Any results which are not None
           from checker functions will be treated as error messages"""
        checks = (checker(self, packet) for checker in Profile.checkers)
        errors = [check for check in checks if check is not None]
        return errors if errors else None

    def get(self, key, default_val=None):
        """Retrieves an entry from the profile dictionary"""
        return self.profile.get(key, default_val)


def add_profile_callbacks():
    """Registers all profile callbacks that are enabled"""
    Profile.add_updater(update_whitelist_ip)
    Profile.add_updater(update_whitelist_tcp)
    Profile.add_updater(update_whitelist_udp)
    Profile.add_updater(update_whitelist_dns)
    Profile.add_checker(check_ddos_tcp)
    Profile.add_checker(check_ddos_udp)


# ----------------------------- PACKET UTILS -------------------------- #

def get_ip_layer(pkt):
    """Retrieves the IP layer of a packet, whether it is IPv4 or IPv6. If
       the packet has no IP layer, None is returned"""
    if pkt.haslayer("IP"):
        return pkt.getlayer("IP")
    elif pkt.haslayer("IPv6"):
        return pkt.getlayer("IPv6")


def get_ip_address(profile, pkt):
    """Retrieves the IP layer from pkt."""
    is_sender = check_if_sender(profile, pkt)
    ipp = get_ip_layer(pkt)
    return None if ipp is None else ipp.dst if is_sender else ipp.src


def check_if_sender(profile, pkt):
    """Checks whether the profile owner sent the given packet"""
    return profile.mac == pkt.getlayer("Ether").src


def default_wlist_entry(mac=None):
    """Creates an empty whitelist object which can be used in a profile"""
    return {"mac": mac, "ip": [], "domain": [], "protocols": {}}


def find_whitelist_entry(profile, pkt, add_if_not_found=True, domain=None):
    """Searches for a whitelist entry in the given profile for one that
       matches the data in the packet. If no such entry is found, it is
       created"""
    is_sender = check_if_sender(profile, pkt)
    ip = get_ip_address(profile, pkt)
    macp = pkt.getlayer("Ether")
    mac = None if not in_network(ip) else macp.dst if is_sender else macp.src
    data = profile.get("send") if is_sender else profile.get("recv")
    wlists = data.get("whitelist")
    # More recent entries are more likely to be at the end of the list.
    for wlist in reversed(wlists):
        if ((mac is not None and wlist.get("mac") == mac)
                or ip in wlist.get("ip") or domain in wlist.get("domain")):
            return wlist

    # Entry not found yet, so create it.
    if add_if_not_found:
        wlists.append(default_wlist_entry(mac))
        return wlists[-1]


# --------------------------- MAINTAIN PROFILE ------------------------- #

def update_whitelist_ip(profile, pkt):
    """Updates profile based on the IP layer"""
    ipp = get_ip_layer(pkt)
    if ipp is not None:
        is_sender = check_if_sender(profile, pkt)
        ip_addr = ipp.dst if is_sender else ipp.src
        wlist = find_whitelist_entry(profile, pkt)
        if ip_addr not in wlist.get("ip"):
            wlist["ip"].append(ip_addr)
        if is_sender and ipp.src not in profile.get("ip"):
            profile.get("ip").append(ipp.src)


def update_whitelist_tcp(profile, pkt):
    """Updates profile based on the TCP layer"""
    if pkt.haslayer("TCP"):
        tcpp = pkt.getlayer("TCP")
        update_whitelist_layer4(profile, pkt, tcpp, "tcp")


def update_whitelist_udp(profile, pkt):
    """Updates profile based on the UDP layer"""
    if pkt.haslayer("UDP"):
        udpp = pkt.getlayer("UDP")
        update_whitelist_layer4(profile, pkt, udpp, "udp")


def update_whitelist_layer4(profile, pkt, layer, proto):
    """Updates profile based on data in packet and a given protocol. The
       given protocol can either be TCP or UDP"""
    port = layer.dport if check_if_sender(profile, pkt) else layer.sport
    wlist = find_whitelist_entry(profile, pkt)
    protocols = wlist.get("protocols")
    if protocols.get(proto) is None:
        protocols[proto] = {}
    if protocols[proto].get(port) is None:
        protocols[proto][port] = {"msgs": 0, "min_size": sys.maxsize,
                                  "max_size": 0, "total_size": 0}
    data = protocols[proto][port]
    data["msgs"] += 1
    packet_len = len(pkt)
    data["min_size"] = min(data["min_size"], packet_len)
    data["max_size"] = max(data["max_size"], packet_len)
    data["total_size"] += packet_len


def update_whitelist_dns(profile, pkt):
    """Updates profile based on DNS responses"""
    if pkt.haslayer("DNS"):
        is_sender = check_if_sender(profile, pkt)
        dnsp = pkt.getlayer("DNS")
        if not is_sender and dnsp.ancount > 0:
            dns_rr = pkt.getlayer("DNSRR")
            records = [dns_rr[i] for i in range(dnsp.ancount)]
            domains = [r.rrname.decode() for r in records]
            ips = [r.rdata for r in records]
            wlists = profile.get("send").get("whitelist")
            entries = [wlist for wlist in wlists
                       for ip, domain in zip(ips, domains)
                       if (ip in wlist.get("ip")
                           or domain in wlist.get("domain"))]
            if len(entries) >= 1:
                entry = entries[0]
            else:
                entry = default_wlist_entry()
                wlists.append(entry)
            uniq_domain = [d for d in domains if d not in entry["domain"]]
            entry["domain"].extend(uniq_domain)
            entry["ip"].extend([ip for ip in ips if ip not in entry["ip"]])


# ----------------------------- CHECK PROFILE --------------------------- #

def check_ddos_tcp(profile, pkt):
    """Checks that pkt conforms to tcp profile."""
    if pkt.haslayer("TCP"):
        return check_ddos_layer4(profile, pkt, pkt.getlayer("TCP"), "tcp")


def check_ddos_udp(profile, pkt):
    """Checks that network traffic conforms to UDP format."""
    if pkt.haslayer("UDP"):
        return check_ddos_layer4(profile, pkt, pkt.getlayer("UDP"), "udp")


def check_ddos_layer4(profile, pkt, layer, proto):
    """Checks that the network traffic conforms to profile at layer4."""
    _LOGGER.debug("Checking Layer4 %s", proto)
    is_sender = check_if_sender(profile, pkt)
    if is_sender:
        wlist = find_whitelist_entry(profile, pkt, add_if_not_found=False)
        if wlist is not None:
            port = layer.dport
            protocols = wlist.get("protocols")
            if protocols.get(proto) is not None:
                if protocols.get(proto).get(port) is not None:
                    return None     # Entry found -> Valid call.
        ip = get_ip_address(profile, pkt)
        return ("A device is doing unexpected network calls. This might "
                "be an indication that the device has been compromised. "
                "Additional information: %s %s:%i") % (proto, ip, port)
