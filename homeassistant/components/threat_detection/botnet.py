"""
Defence mechanism to detect against botnet creation.

For more details about this platform, please refer to the documentation
https://home-assistant.io/components/threat_detection/botnet/
"""

from datetime import datetime
from homeassistant.components.threat_detection import (Profile,
                                                       eth_addr, ip_addr,
                                                       pretty_ip_addr,
                                                       get_eth_address,
                                                       get_ip_address,
                                                       profile_packet,
                                                       PLATFORM_SCHEMA,
                                                       DOMAIN)

DNS_RECORD_A = 12848
DNS_RECORD_AAAA = -1
VALID_DNS_TYPES = [DNS_RECORD_A, DNS_RECORD_AAAA]


async def async_setup_platform(hass, config, async_add_entities, discovery_info=None):
    """Set up the platform."""
    from pypacker.layer3 import ip, ip6
    botnet_analyser_ipv4 = {'device_selector': (lambda prof: True),
                            'condition': botnet_condition(ip.IP),
                            'analyse_func': check_botnet(ip.IP)}
    botnet_analyser_ipv6 = {'device_selector': (lambda prof: True),
                            'condition': botnet_condition(ip6.IP6),
                            'analyse_func': check_botnet(ip6.IP6)}
    Profile.add_analyser(botnet_analyser_ipv4)
    Profile.add_analyser(botnet_analyser_ipv6)
    Profile.add_profiler(get_dns_profiler())


def botnet_condition(proto):
    return lambda prof, pkt: pkt[proto] and prof.get_id() == eth_addr(pkt.src)


def check_botnet(proto):
    def check(prof, pkt):
        eth_address = get_eth_address(prof, pkt)
        ip_address = get_ip_address(prof, pkt)
        records = prof.data.get(eth_address, {}).get(ip_address, {}).get('count')
        if not records:
            dns_entries = prof.data.get("dns", {})
            remote_ip = ip_addr(pkt[proto].dst)
            if [ip for entry in dns_entries.values() for ip in entry if ip == remote_ip]:
                # Service has changed IP. Update profile.
                profile_packet(prof, pkt)
            else:
                # Botnet device detected
                layer = pkt[proto]
                return ("Potential botnet activity detected. Device %s sent"
                        " data to %s at %s"
                        ) % (pretty_ip_addr(layer.src),
                             pretty_ip_addr(layer.dst),
                             datetime.now().strftime('%H:%M'))
    return check


def get_dns_profiler():
    from pypacker.layer567 import dns
    def selector(prof):
        return True
    def condition(prof, pkt):
        if pkt[dns.DNS] and prof.get_id() == eth_addr(pkt.dst):
            layer = pkt[dns.DNS]
            if layer.queries and [answer for answer in layer.answers if answer.type in VALID_DNS_TYPES]:
                domain = layer.queries[0].name.decode('utf-8')
                data = prof.data.get("dns", {}).get(domain, [])
                return prof.is_profiling() or data
            else:
                print(pkt[dns.DNS])
    def profiler(profile, pkt):
        layer = pkt[dns.DNS]
        domain = layer.queries[0].name.decode('utf-8')
        if not profile.data.get("dns"):
            profile.data["dns"] = {}
        if not profile.data["dns"].get(domain):
            profile.data["dns"][domain] = []
        for answer in layer.answers:
            if answer.type in VALID_DNS_TYPES:
                ip = ip_addr(answer.address)
                if ip not in profile.data["dns"][domain]:
                    profile.data["dns"][domain].append(ip)
    return {'device_selector': selector,
            'condition': condition,
            'profiler_func': profiler,
            'run_always': True}
