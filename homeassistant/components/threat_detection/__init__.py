"""
Component for detecting threats against the smart home.

For more information on this component see
todo add where to find documontation for the component.
"""

import sys
import time
import os
from os.path import dirname, basename, isfile, join
import asyncio
import logging
import voluptuous as vol
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

    _LOGGER.info("The threat_detection component is set up!")

    return True
    
def on_network_capture(packet_list):
    """Called when a network packet list has been captured """
    _LOGGER.info(packet_list)


# @property
# def state_attributes(self):
#     """Return state attributes of the component"""
#     return self._attributes


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

        def on_created(self, event):
            """Reads, interprets and removes all pcap files in the monitored
               folder except for the newest one (due to tcpdump impl.) """
            from scapy.all import rdpcap, PacketList
            path = dirname(event.src_path)
            # Ignore directories and the most recent created file
            all_files = [f for f in os.listdir(path) if isfile(join(path, f))]
            files = list(filter(self.file_filter(event.src_path), all_files))
            # Parse data from pcap format
            data = [rdpcap(join(path, file)) for file in files]
            # Remove read files so data are only read once
            for file in files:
                os.remove(join(path, file))
            # Notify the user of the found data
            self.callback(PacketList([pkt for pkts in data for pkt in pkts]))
                
        def file_filter(self, ignore_file):
            """Filter to select .pcap files and ignore the given file """
            def f_filter(f):
                return f.endswith('.pcap') and f != basename(ignore_file)
            return f_filter

