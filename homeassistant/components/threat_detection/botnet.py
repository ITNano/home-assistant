"""
Defence mechanism to detect against botnet creation.

For more details about this platform, please refer to the documentation
https://home-assistant.io/components/threat_detection/botnet/
"""

from datetime import datetime
from homeassistant.components.threat_detection import (Profile,
                                                       PLATFORM_SCHEMA,
                                                       DOMAIN)


async def async_setup_platform(hass, config, async_add_entities, discovery_info=None):
    """Set up the platform."""
    from scapy.all import IP, IPv6
    botnet_analyser_ipv4 = {'device_selector': (lambda prof: True),
                            'condition': botnet_condition(IP),
                            'analyse_func': check_botnet(IP)}
    botnet_analyser_ipv6 = {'device_selector': (lambda prof: True),
                            'condition': botnet_condition(IPv6),
                            'analyse_func': check_botnet(IPv6)}
    Profile.add_analyser(botnet_analyser_ipv4)
    Profile.add_analyser(botnet_analyser_ipv6)
    Profile.add_profiler(get_dns_profiler())


def botnet_condition(proto):
    return lambda prof, pkt: pkt.haslayer(proto) and prof.get_id() == pkt.src


def check_botnet(proto):
    def check(prof, pkt):
        records = profile_data(prof, ipvx_prop(proto)(prof, pkt, 'count'))
        if not records:
            dns_entries = profile_data(prof, ['dns'], {})
            remote_ip = pkt.getlayer(proto).dst
            if [ip for entry in dns_entries.values() for ip in entry if ip == remote_ip]:
                # Service has changed IP. Update profile.
                profile_packet(prof, pkt)
            else:
                # Botnet device detected
                ip = pkt.getlayer(proto)
                return ("Potential botnet activity detected. Device %s sent"
                        " data to %s at %s"
                       ) % (ip.src, ip.dst, datetime.now().strftime('%H:%M'))
    return check


def get_dns_profiler():
    from scapy.all import DNSRR
    def selector(prof):
        return True
    def condition(prof, pkt):
        if pkt.haslayer(DNSRR):
            domain = pkt.getlayer(DNSRR).rrname.decode('utf-8')
            data = prof.data.get("dns", {}).get(domain, [])
            return (prof.get_id() == pkt.dst and
                    (prof.is_profiling() or data) and
                    pkt.getlayer(DNSRR).rdata not in data)
    def profiler(profile, pkt):
        domain = pkt.getlayer(DNSRR).rrname.decode('utf-8')
        ip = pkt.getlayer(DNSRR).rdata
        if not profile.data.get("dns"):
            profile.data["dns"] = {}
        if not profile.data["dns"].get(domain):
            profile.data["dns"][domain] = []
        if ip not in profile.data["dns"][domain]:
            profile.data["dns"][domain].append(ip)
    return {'device_selector': selector,
            'condition': condition,
            'profiler_func': profiler,
            'run_always': True}
