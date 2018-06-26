"""
Component for detecting threats against the smart home.

For more information on this component see
todo add where to find documontation for the component.
"""

import asyncio

import logging
import voluptuous as vol

import homeassistant.const as const
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

    _LOGGER.info("The threat_detection component is set up!")

    def event_listener(event):
        """Sends all events that happens to the event handler that does IO."""
        hass.async_add_job(handler, event)

    def state_changed_listener(event):
        """Listens to and handle state changes in the state machine."""
        hass.async_add_job(state_changed_handler, event)

    hass.bus.async_listen(const.MATCH_ALL, event_listener)
    hass.bus.async_listen(const.EVENT_STATE_CHANGED, state_changed_listener)

    return True


def handler(event):
    """Handles the events that the listener listens to."""
    _LOGGER.info("Event has happened! Event: %s ", event.as_dict())


def state_changed_handler(event):
    """Handles what to do in the event of a state change."""
    _LOGGER.info("State has changed! Entity ID:  %s, New state: %s ",
                 event.as_dict()['data']['entity_id'],
                 event.as_dict()['data']['new_state'])

# @property
# def state_attributes(self):
#     """Return state attributes of the component"""
#     return self._attributes
