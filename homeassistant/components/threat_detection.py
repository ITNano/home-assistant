"""
Component for detecting threats against the smart home.

For more information on this component see \todo add where to find documontation for the component.
"""

import asyncio
import logging
import voluptuous as vol
import homeassistant.helpers.config_validation as cv
from homeassistant.helpers.entity_component import EntityComponent

_LOGGER = logging.getLogger(__name__)

DOMAIN = 'threat_detection'
ENTITIY_ID_FORMAT = DOMAIN + '.[]'
DEPENDENCIES = []

CONF_TEXT = 'text'
DEFAULT_TEXT = 'No text!'

@asyncio.coroutine
def async_setup(hass, config=None):
    """Set up the threat_detection component."""
    #This seems to be a thing. I don't know what it does. May have to do with getting things to and from dependent
    #platforms? It seems to break our stuff.
    component = EntityComponent(_LOGGER, DOMAIN, hass)
    yield from component.async_setup(config)

    hass.states.set('ids.detections', 0)

    _LOGGER.info("The threat_detection component is running!")

    return True

def setup(hass, config):
    hass.states.set('threat_detection.detections', 0)
    return True



