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
                         'analyse_func': analyse_maxmin}
    eviltwin_profiler = {'device_selector': device_selector,
                         'condition': condition,
                         'profiler_func': profiler,
                         'on_profiling_end': on_profiling_end_maxmin}

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
    if mean and sigma:
        if abs((current_rssi - mean) / sigma) > 3:
            ssid = profile.get_id()
            return "It is likely that " + ssid + "is a rouge access point." \
                   "Consider dissconnecting from the network!"


def analyse_maxmin(profile, packet):
    from scapy.all import RadioTap
    current_rssi = abs(packet.getlayer(RadioTap).dBm_AntSignal)
    minimum = profile.data.get("rssi_min")
    maximum = profile.data.get("rssi_max")
    if current_rssi < minimum or current_rssi > maximum:
        ssid = profile.get_id().split("_")[1]
        return "A fake router may be broadcasting under the name " + ssid


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

    if n >= 5: # we need at least 5 samples
        variance = total/(n-1)
        standard_deviation = math.sqrt(variance)

        profile.data['mean'] = mean
        profile.data['standard_deviation'] = standard_deviation


def on_profiling_end_maxmin(profile):
    rssi = profile.data.get("rssi")
    n = sum(rssi)
    if n > 0:
        filtered_rssi = [index for index, val in enumerate(rssi) if val > 0]
        profile.data["rssi_min"] = filtered_rssi[0]
        profile.data["rssi_max"] = filtered_rssi[-1]
