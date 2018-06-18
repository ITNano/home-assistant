"""
Component for detecting threats against the smart home.

For more information on this component see \todo add where to find documontation for the component.
"""

import logging

DOMAIN = 'threat_detection'

@asyncio.coroutine
def async_setup(hass, config=None):
    """Set up the threat_detection component."""
    log = logging.getLogger(__name__)
    log.info("""This is a test to se if the threat_detection component can write to the logs""")

    return True