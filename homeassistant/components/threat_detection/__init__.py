"""
Component for detecting threats against the smart home.

For more information on this component see
todo add where to find documontation for the component.
"""

import os
import asyncio
import logging
import voluptuous as vol
import homeassistant.helpers.config_validation as cv
from homeassistant.helpers.entity_component import EntityComponent


_LOGGER = logging.getLogger(__name__)

DOMAIN = 'threat_detection'

ENTITIY_ID_FORMAT = DOMAIN + '.[]'

DEPENDENCIES = []

#
KNOWN_DEVICES = 'known_devices.yaml'

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

DEVICES = {}


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

    devices = yield from hass.components.device_tracker.async_load_config(
        os.path.join(hass.config.config_dir, KNOWN_DEVICES), hass, 0)

    pretty = setup_devices(devices)
    _LOGGER.info(pretty)

    _LOGGER.info("The threat_detection component is set up!")

    return True


def setup_devices(devices):
    """Sets up the data structure for the information about the devices."""
    for device in devices:
        DEVICES.update({device.entity_id: {'mac': device.mac,
                                           'platform': device.platform}})

    return pretty_string(DEVICES, [])


def pretty_string(obj, string):
    """Prints a dict to log, may or may not be done prettily."""
    if isinstance(obj, dict):
        for key, value in obj.items():
            if hasattr(value, '__iter__'):
                string.append("KEY = ")
                if key is None:
                    string.append(" ")
                else:
                    string.append(str(key))
                string.append("\n")
                pretty_string(value, string)
            else:
                if key is None:
                    string.append(" ")
                else:
                    string.append(str(key))
                string.append(" : ")
                if key is None:
                    string.append(" ")
                else:
                    string.append(str(value))
                string.append("\n")
                return "".join(string)
    elif isinstance(obj, list):
        for value in obj:
            if hasattr(value, '__iter__'):
                pretty_string(value, string)
            else:
                string.append(str(value))
                return "".join(string)
    else:
        return obj


# @property
# def state_attributes(self):
#     """Return state attributes of the component"""
#     return self._attributes
