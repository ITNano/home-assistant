"""
Component for detecting threats against the smart home.

For more information on this component see \todo add where to find documontation for the component.
"""

import asyncio
import logging
import voluptuous as vol
import homeassistant.helpers.config_validation as cv

_LOGGER = logging.getLogger(__name__)

DOMAIN = 'threat_detection'
DEPENDENCIES = []

CONF_TEXT = 'text'
DEFAULT_TEXT = 'No text!'

@asyncio.coroutine
def async_setup(hass, config=None):
    """Set up the threat_detection component."""
    text = "test"
    hass.states.set('threat_detection', text)

    _LOGGER.info("The threat_detection component is running!")

    return True

