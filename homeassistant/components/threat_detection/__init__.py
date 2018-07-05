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
    capturer = PacketCapturer(join(hass.config.config_dir, "traces"))
    capturer.add_callback(on_network_capture)

    _LOGGER.info("The threat_detection component is set up!")

    return True
    
def on_network_capture(packet_list):
    _LOGGER.info(packet_list)


# @property
# def state_attributes(self):
#     """Return state attributes of the component"""
#     return self._attributes


class PacketCapturer:

    from watchdog.events import FileSystemEventHandler

    def __init__(self, path):
        self.callbacks = []
        from watchdog.observers import Observer
        self.observer = Observer()
        self.observer.schedule(self.PacketCaptureHandler(self.on_event), path)
        self.observer.start()
        
    def on_event(self, packet_list):
        for callback in self.callbacks:
            callback(packet_list)
            
    def add_callback(self, callback):
        if callback is not None:
            self.callbacks.append(callback)

    def __del__(self):
        if self.observer is not None:
            self.observer.stop()
            self.observer.join()
            self.observer = None
            
    class PacketCaptureHandler(FileSystemEventHandler):

        def __init__(self, callback):
            super(PacketCapturer.PacketCaptureHandler, self).__init__()
            self.callback = callback

        def on_created(self, event):
            from scapy.all import rdpcap, PacketList
            path = dirname(event.src_path)
            all_files = [f for f in os.listdir(path) if isfile(join(path, f))]
            files = list(filter(self.file_filter(event.src_path), all_files))
            data = [rdpcap(join(path, file)) for file in files]
            for file in files:
                os.remove(join(path, file))
            self.callback(PacketList([pkt for pkts in data for pkt in pkts]))
                
        def file_filter(self, ignore_file):
            def f_filter(f):
                return f.endswith('.pcap') and f != basename(ignore_file)
            return f_filter

