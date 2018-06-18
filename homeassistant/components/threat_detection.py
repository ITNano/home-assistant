"""
Component for detecting threats against the smart home.

For more information on this component see \todo add where to find documontation for the component.
"""

import asyncio
import logging

_LOGGER = logging.getLogger(__name__)

DOMAIN = 'threat_detection'

@asyncio.coroutine
def async_setup(hass, config=None):
    """Set up the threat_detection component."""



    _LOGGER.info("The threat_detection component is running!")

    return True