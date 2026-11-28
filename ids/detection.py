PORT_SCAN_WINDOW_SECONDS = 10
PORT_SCAN_THRESHOLD = 10

HOST_SWEEP_WINDOW_SECONDS = 10
HOST_SWEEP_THRESHOLD = 10

# Read packets and if TCP identify an initial TCP connection attempt: SYN is set and ACK is unset
def is_initial_tcp_attempt(fields):
    flags = fields.get("tcp_flags")

    if flags is None:
        return None

    syn_set = (flags & 0x02) != 0
    ack_set = (flags & 0x10) != 0 

    return syn_set and not ack_set

# Used to update recent details for PortScanRule and HostSweepRule
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