PORT_SCAN_WINDOW_SECONDS = 10
PORT_SCAN_THRESHOLD = 10

HOST_SWEEP_WINDOW_SECONDS = 10
HOST_SWEEP_THRESHOLD = 10

DNS_FAILURE_WINDOW_SECONDS = 60
DNS_FAILURE_THRESHOLD = 15

CONNECTION_SPIKE_WINDOW_SECONDS = 10
CONNECTION_SPIKE_THRESHOLD = 200

# Read packets and if TCP identify an initial TCP connection attempt: SYN is set and ACK is unset
def is_initial_tcp_attempt(fields):
    flags = fields.get("tcp_flags")

    if flags is None:
        return None

    syn_set = (flags & 0x02) != 0
    ack_set = (flags & 0x10) != 0 

    return syn_set and not ack_set

# Used to update recent details for PortScanRule and HostSweepRule and DNSFailureRule
def update_window(groups, group, target, timestamp, window_seconds, threshold):
    cutoff = timestamp - window_seconds
    recent = {}

    for value, last_seen in groups.get(group, {}).items():
        if last_seen >= cutoff:
            recent[value] = last_seen

    # Adding new port or refreshing port timestamp and keeping track of count before
    count_before = len(recent)
    recent[target] = timestamp
    groups[group] = recent

    # Checking if threshold exceeded for target and returning alert details
    # Also ensuring not to repeat alerts if it had already passed threshold before
    if count_before < threshold <= len(recent):
        return sorted(recent)

    return None


# Detects one source attempting connections to many distinct ports on one destination within a time window
# May indicate reconnaissance to identify reachable services on a host for further attack
class PortScanRule:

    # Stores ports and their latest attempt times for each IP pair
    def __init__(self):
        self.port_by_pair = {}

    def process_packet(self, fields):

        if not is_initial_tcp_attempt(fields):
            return None

        # Getting details and updating recent ports based on new cutoff before adding new port then returning whether threshold exceeded
        pair = (fields["src_ip"], fields["dst_ip"])
        ports = update_window(
            self.port_by_pair, pair, fields["dst_port"], fields["timestamp"],
            PORT_SCAN_WINDOW_SECONDS, PORT_SCAN_THRESHOLD
        )

        # If threshold is exceeded return alert details
        if ports is None:
            return None

        return {
            "src_ip": fields["src_ip"],
            "dst_ip": fields["dst_ip"],
            "ports": ports,
            "distinct_port_count": len(ports),
            "timestamp": fields["timestamp"],
            "window_seconds": PORT_SCAN_WINDOW_SECONDS,
            "rule": "Possible port scan"
        }


# Detects one source attempting connections to the same port on many distinct destinations within a time window
# May indicate reconnaissance to find hosts offering a particular service for further attack
class HostSweepRule:

    # Stores destination hosts and their latest attempt times for each source IP and destination port
    def __init__(self):
        self.hosts_by_service = {}

    def process_packet(self, fields):

        if not is_initial_tcp_attempt(fields):
            return None

        # Getting details and updating recent IPs based on new cutoff before adding new IP then returning whether threshold exceeded
        group = (fields["src_ip"], fields["dst_port"])
        hosts = update_window(
            self.hosts_by_service, group, fields["dst_ip"], fields["timestamp"],
            HOST_SWEEP_WINDOW_SECONDS, HOST_SWEEP_THRESHOLD
        )

        # If threshold is exceeded return alert details
        if hosts is None:
            return None

        return {
            "rule": "Possible host sweep",
            "src_ip": fields["src_ip"],
            "dst_port": fields["dst_port"],
            "hosts": hosts,
            "distinct_host_count": len(hosts),
            "timestamp": fields["timestamp"],
            "window_seconds": HOST_SWEEP_WINDOW_SECONDS,
        }


# Detects one client receiving NXDOMAIN responses for many distinct domain names within a time window
# May indicate DGA activity, DNS reconnaissance, or application/DNS misconfiguration
class DNSFailureRule:

    # Stores failed domain names and their latest response times for each client IP
    def __init__(self):
        self.names_by_client = {}

    def process_packet(self, fields):

        # Only processes NXDOMAIN (failed : response code = 3) responses where the queried domain name does not exist
        if fields.get("dns_rcode") != 3:
            return None

        # Getting details and updating recent domain names based on new cutoff before adding new domain name then returning whether threshold exceeded
        client = fields["dst_ip"]
        names = update_window(
            self.names_by_client, client, fields["dns_name"], fields["timestamp"],
            DNS_FAILURE_WINDOW_SECONDS, DNS_FAILURE_THRESHOLD
        )

        # If threshold is exceeded return alert details
        if names is None:
            return None

        return {
            "rule": "Suspicious DNS activity - burst of failed DNS lookups",
            "timestamp": fields["timestamp"],
            "client": client,
            "distinct_name_count": len(names),
            "example_names": names[:3],
            "window_seconds": DNS_FAILURE_WINDOW_SECONDS,
        }


# Detects many new TCP connection attempts to one destination IP and port within a time window
# May indicate denial-of-service activity, legitimate demand, or repeated client reconnections
class ConnectionSpikeRule:

    # Stores connection attempts and their first-seen and last-seen times for each destination service
    def __init__(self):
        self.attempts_by_service = {}

    def process_packet(self, fields):

        if not is_initial_tcp_attempt(fields):
            return None
        
        service = (fields["dst_ip"], fields["dst_port"])
        attempt = (fields["src_ip"], fields["src_port"], fields["tcp_seq"])
        now = fields["timestamp"]
        cutoff = now - CONNECTION_SPIKE_WINDOW_SECONDS

        # Update attempts whose SYN packets were seen recently based on new cutoff
        recent = {}
        for key, times in self.attempts_by_service.get(service, {}).items():
            first_seen, last_seen = times
            if last_seen >= cutoff:
                recent[key] = times

        self.attempts_by_service[service] = recent

        # If retry update last_seen but do not count as a new attempt and vice versa
        if attempt in recent:
            first_seen, _ = recent[attempt]
            recent[attempt] = (first_seen, now)
            return None

        recent[attempt] = (now, now)

        # Count only attempts that started within the window and alert if threshold reached
        active = []
        for key, times in recent.items():
            first_seen, last_seen = times
            if first_seen >= cutoff:
                active.append(key)

        if len(active) != CONNECTION_SPIKE_THRESHOLD:
            return None

        # Count distinct source IPs among the active attempts and return alert details
        sources = set()
        for key in active:
            sources.add(key[0])

        return {
            "rule": "TCP connection-attempt spike : possible DoS attack",
            "timestamp": now,
            "dst_ip": fields["dst_ip"],
            "dst_port": fields["dst_port"],
            "attempt_count": len(active),
            "source_count": len(sources),
            "window_seconds": CONNECTION_SPIKE_WINDOW_SECONDS,
        }