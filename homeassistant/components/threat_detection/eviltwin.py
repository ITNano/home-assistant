"""
Defence mechanism to detect evil twin access points.

For more details about this platform, please refer to the documentation
https://home-assistant.io/components/threat_detection/eviltwin/
"""

import math
from homeassistant.components.threat_detection import (Profile,
                                                       PLATFORM_SCHEMA,
                                                       DOMAIN
                                                       )


async def async_setup_platform(hass, config, async_add_entities,
                               discovery_info=None):
    """Setup the platform."""
    from scapy.all import Dot11Elt
    eviltwin_analyser = {'device_selector': device_selector,
                         'condition': condition,
                         'analyse_func': analyse}
    eviltwin_profiler = {'device_selector': device_selector,
                         'condition': condition,
                         'profiler_func': profiler,
                         'on_profiling_end': on_profiling_end}

    Profile.add_analyser(eviltwin_analyser)
    Profile.add_profiler(eviltwin_profiler)


def condition(profile, packet):
    from scapy.all import Dot11Elt, RadioTap
    return packet.haslayer(Dot11Elt) and packet.haslayer(RadioTap)

def device_selector(profile):
    return profile.get_id().startswith("AP_")

def analyse(profile, packet):
    from scapy.all import RadioTap

    current_rssi = abs(packet.getlayer(RadioTap).dBm_AntSignal)
    mean = profile.data.get("mean")
    sigma = profile.data.get("standard_deviation")
    if abs((current_rssi - mean) / sigma) > 3:
        ssid = profile.get_id()
        return "It is likely that " + ssid + "is a rouge access point." \
               "Consider dissconnecting from the network!"


def profiler(profile, packet):
    from scapy.all import RadioTap
    rssi = profile.data.get("rssi")

    if not rssi:
        profile.data['rssi'] = [0]*150

    current_rssi = abs(packet.getlayer(RadioTap).dBm_AntSignal)
    profile.data['rssi'][current_rssi] += 1


def on_profiling_end(profile):
    rssi = profile.data.get("rssi")
    n = sum(rssi)
    total = 0
    for index, value in enumerate(rssi):
        total += index*value
    mean = total/n

    total = 0
    for index, value in enumerate(rssi):
        total += math.sqrt(abs(index-mean))*value

    variance = total/(n-1)

    standard_deviation = math.sqrt(variance)

    profile.data['mean'] = mean
    profile.data['standard_deviation'] = standard_deviation



