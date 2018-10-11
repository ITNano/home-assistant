"""
Defence mechanism to detect evil twin access points.

For more details about this platform, please refer to the documentation
https://home-assistant.io/components/threat_detection/eviltwin/
"""

import math
import datetime
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
                         'analyse_func': analyse_mix}
    eviltwin_profiler = {'device_selector': device_selector,
                         'condition': condition,
                         'profiler_func': profiler,
                         'on_profiling_end': on_profiling_end_mix}

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
                   "Consider disconnecting from the network!"


def analyse_maxmin(profile, packet):
    from scapy.all import RadioTap
    current_rssi = abs(packet.getlayer(RadioTap).dBm_AntSignal)
    minimum = profile.data.get("rssi_min")
    maximum = profile.data.get("rssi_max")
    if current_rssi < minimum or current_rssi > maximum:
        ssid = profile.get_id().split("_")[1]
        return "A fake router may be broadcasting under the name " + ssid


def analyse_mix(profile, packet):
    from scapy.all import RadioTap
    current_rssi = abs(packet.getlayer(RadioTap).dBm_AntSignal)
    list_name, limit_name = (None, None)
    if current_rssi > profile.data.get("rssi_max"):
        list_name, limit_name = ("rssi_current_above", "rssi_more_limit")
    elif current_rssi < profile.data.get("rssi_min"):
        list_name, limit_name = ("rssi_current_below", "rssi_less_limit")

    if list_name and limit_name:
        data = profile.data[list_name]
        limit = profile.data[limit_name]
        profile.data[list_name], detection = check_time_threshold(data, limit)
        if detection:
            return "It is likely that " + ssid + "is a rouge access point." \
                   "Consider disconnecting from the network!"


def check_time_threshold(time_list, limit):
    """Checks & updates a list of timestamps compared to a certain limit.
    
    The list of time stamps should be on the form of UTC time (second
    resolution). Adds current timestamp to the list, ignores all timestamps
    before the last 60 seconds, and checks it against the given limit."""
    # find current timestamp (resolution: seconds)
    current_time = datetime.datetime.now().timestamp()
    # clean up list (we only care about last 60 seconds)
    new_list = [val for val in time_list if val > current_time - 60]
    # add this new data point
    new_list.append(current_time)
    # check if we are above the threshold
    if len(new_list) > limit:
        return [], True
    else:
        return new_list, False


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


def on_profiling_end_mix(profile):
    """Function to run at end of profiling for evil twin module.
    
    Values that are assumed in this functionality:
    Standard deviations: 3
    Allowed increase of data points: 20%
    Time frame for limits: 60 seconds
    Allows for asymmetric behaviour above/below the profile.
    """
    on_profiling_end(profile)
    rssi = profile.data.get("rssi")
    mean = profile.data.get("mean")
    deviation = profile.data.get("standard_deviation")
    profile_time = profile.profiling_time/60  # measured in minutes
    nbr_of_lower = sum([val for i, val in enumerate(rssi) if i < mean - 3 * deviation])
    profile.data["rssi_min"] = mean - 3 * deviation
    profile.data["rssi_less_limit"] = int((nbr_of_lower/profile_time)*1.2)
    profile.data["rssi_current_below"] = []
    nbr_of_higher = sum([val for i, val in enumerate(rssi) if i > mean + 3 * deviation])
    profile.data["rssi_max"] = mean + 3 * deviation
    profile.data["rssi_more_limit"] = int((nbr_of_higher/profile_time)*1.2)
    profile.data["rssi_current_above"] = []
