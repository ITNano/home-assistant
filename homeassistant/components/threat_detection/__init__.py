"""
Component for detecting threats against the smart home.

For more information on this component see \todo add where to find documontation for the component.
"""

import asyncio
import logging
import voluptuous as vol
import homeassistant.helpers.config_validation as cv
from homeassistant.helpers.entity_component import EntityComponent
from homeassistant.components.group import \
    ENTITY_ID_FORMAT as GROUP_ENTITY_ID_FORMAT

_LOGGER = logging.getLogger(__name__)

DOMAIN = 'threat_detection'
ENTITIY_ID_FORMAT = DOMAIN + '.[]'
DEPENDENCIES = ['group']

GROUP_NAME_ALL_IDS = 'all_ids'
ENTITY_ID_ALL_IDS = GROUP_ENTITY_ID_FORMAT.format('all_ids')

CONF_TEXT = 'text'
DEFAULT_TEXT = 'No text!'

# @asyncio.coroutine
# def async_setup(hass, config=None):
#     """Set up the threat_detection component."""
#     #This seems to be a thing. I don't know what it does. May have to do with getting things to and from dependent
#     #platforms? It seems to break our stuff.
#     component = EntityComponent(_LOGGER, DOMAIN, hass, GROUP_NAME_ALL_IDS)
#     yield from component.async_setup(config)
#
#
#     _LOGGER.info("The threat_detection component is set up through the async_setup() method.")
#
#     return True

def setup(hass, config):
    hass.states.set('threat_detection.detections', 0)
    _LOGGER.info("The threat detection component is set up through the setup() method.")
    return True



