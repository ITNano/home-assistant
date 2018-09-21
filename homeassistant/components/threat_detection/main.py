"""
Component for detecting threats against the smart home.

For more information on this component see
todo add where to find documontation for the component.
"""

from threat_detection.network import PacketCapturer
from threat_detection.profile import load_profiles, save_profiles, ignore_device, handle_packet
from os.path import join
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
    