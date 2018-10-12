"""
Intermediary platform to load all default threat detection platforms.

For more details about this platform, please refer to the documentation
https://home-assistant.io/components/threat_detection/
"""

import logging
import asyncio

import voluptuous as vol
from homeassistant.const import CONF_EXCLUDE, CONF_INCLUDE, CONF_PLATFORM
import homeassistant.helpers.config_validation as cv
from homeassistant.helpers.discovery import async_load_platform

from homeassistant.components.threat_detection import (PLATFORM_SCHEMA,
                                                       DOMAIN)

_LOGGER = logging.getLogger(__name__)
CONF_MODULES = 'modules'

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend({
    vol.Optional(CONF_EXCLUDE): vol.All(cv.ensure_list, [cv.string]),
    vol.Optional(CONF_INCLUDE) : vol.All(cv.ensure_list, [cv.string]),
    vol.Optional(CONF_MODULES) : vol.All(cv.ensure_list),
})

DEFAULT_PLATFORMS = ['botnet', 'eviltwin']


@asyncio.coroutine
def async_setup_platform(hass, config, async_add_entities, discovery_info=None):
    """Set up the platform."""
    _LOGGER.info("Config: %s", str(config))
    platforms = DEFAULT_PLATFORMS
    if config.get(CONF_EXCLUDE):
        exclude = config.get(CONF_EXCLUDE)
        platforms = [p for p in platforms if p not in exclude]
    elif config.get(CONF_INCLUDE):
        platforms = config.get(CONF_INCLUDE)

    _LOGGER.info("Loading modules for threat_detection: %s", str(platforms))

    for platform in platforms:
        load_platform(hass, platform, config)


def load_platform(hass, platform, config):
    platform_config = {CONF_PLATFORM: platform}
    if config.get(CONF_MODULES):
        for conf in config[CONF_MODULES]:
            if conf.get(CONF_PLATFORM) == platform:
                platform_config = conf
    hass.async_create_task(async_load_platform(
        hass, 'threat_detection', platform, hass_config=platform_config
    ))
