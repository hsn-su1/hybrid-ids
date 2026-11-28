import unittest
from ids.detection import PortScanRule, HostSweepRule, DNSFailureRule, ConnectionSpikeRule

# Creates a fake SYN only packet record 
def syn(port, timestamp, dst_ip="198.51.100.20", src_ip="192.0.2.10"):
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": port,
        "timestamp": timestamp,
        "tcp_flags": 0x02,
    }

# Creates a fake DNS reply record with a an NXDOMAIN response
def dns_reply(name, timestamp, client="192.0.2.10", rcode=3):
    return {
        "src_ip": "192.0.2.53",
        "dst_ip": client,
        "dns_name": name,
        "dns_rcode": rcode,
        "timestamp": timestamp,
    }

# Creates a fake SYN packet record with a distinct source port and sequence number for each numbered attempt
def spike_syn(number, timestamp, dst_ip="198.51.100.20", dst_port=443):
    # Spread the attempts across four clients
    src_ip = f"192.0.2.{10 + number % 4}"
    packet = syn(dst_port, timestamp, dst_ip=dst_ip, src_ip=src_ip)
    packet["src_port"] = 49000 + number
    packet["tcp_seq"] = 1000 + number
    return packet



class PortScanTests(unittest.TestCase):
    
    # Checks that an alert occurs on the tenth distinct port but not the ninth or eleventh
    def test_alerts_on_tenth_port_only(self):
        rule = PortScanRule()
        for second, port in enumerate(range(80, 89)):
            self.assertIsNone(rule.process_packet(syn(port, second)))

        alert = rule.process_packet(syn(89, 9))
        self.assertEqual(alert["ports"], list(range(80, 90)))
        self.assertIsNone(rule.process_packet(syn(90, 10)))

    # Checks that retries count once while refreshing the ports timestamp
    def test_retries_count_once_but_refresh_timestamp(self):
        rule = PortScanRule()
        for second in range(10):
            self.assertIsNone(rule.process_packet(syn(80, second)))

        for second, port in enumerate(range(81, 89), start=10):
            self.assertIsNone(rule.process_packet(syn(port, second)))

        alert = rule.process_packet(syn(89, 18))
        self.assertEqual(alert["distinct_port_count"], 10)

    # Checks that expired ports are excluded from the distinct port count
    def test_expired_port_does_not_count(self):
        rule = PortScanRule()
        rule.process_packet(syn(80, 0))
        for second, port in enumerate(range(81, 90), start=11):
            self.assertIsNone(rule.process_packet(syn(port, second)))



class HostSweepTests(unittest.TestCase):

    # Creates a fresh host-sweep detector and a list of eleven hosts before each test
    def setUp(self):
        self.rule = HostSweepRule()
        self.hosts = [f"198.51.100.{n}" for n in range(20, 31)]

    # Sends attempts to nine distinct hosts and checks that none triggers an alert
    def try_first_nine_hosts(self):
        for host in self.hosts[:9]:
            self.assertIsNone(self.rule.process_packet(syn(22, 0, host)))

    # Checks that the tenth host triggers an alert with the expected details and the eleventh does not
    def test_alerts_on_tenth_host_and_reports_evidence_only_once(self):
        self.try_first_nine_hosts()
        alert = self.rule.process_packet(syn(22, 9, self.hosts[9]))
        self.assertIsNotNone(alert)
        self.assertEqual(alert["rule"], "Possible host sweep")
        self.assertEqual(alert["src_ip"], "192.0.2.10")
        self.assertEqual(alert["dst_port"], 22)
        self.assertEqual(alert["distinct_host_count"], 10)
        self.assertCountEqual(alert["hosts"], self.hosts[:10])
        self.assertEqual(alert["timestamp"], 9)
        self.assertEqual(alert["window_seconds"], 10)
        self.assertIsNone(self.rule.process_packet(syn(22, 10, self.hosts[10])))

    # Checks that retries refresh a host’s timestamp without counting it more than once
    def test_retry_refreshes_host_without_counting_it_twice(self):
        for second in range(10):
            self.assertIsNone(self.rule.process_packet(syn(22, second, self.hosts[0])))

        # At second 18 the first attempt has expired, but the retry at 9 still counts
        for host in self.hosts[1:9]:
            self.assertIsNone(self.rule.process_packet(syn(22, 18, host)))
        alert = self.rule.process_packet(syn(22, 18, self.hosts[9]))
        self.assertIsNotNone(alert)
        self.assertCountEqual(alert["hosts"], self.hosts[:10])

    # Checks that an attempt exactly ten seconds old counts, but one older than ten seconds does not
    def test_ten_second_window_boundary(self):
        for elapsed, should_alert in [(10, True), (10.001, False)]:
            with self.subTest(elapsed=elapsed):
                rule = HostSweepRule()
                self.assertIsNone(rule.process_packet(syn(22, 0, self.hosts[0])))
                for host in self.hosts[1:9]:
                    self.assertIsNone(rule.process_packet(syn(22, 1, host)))
                alert = rule.process_packet(syn(22, elapsed, self.hosts[9]))
                self.assertEqual(alert is not None, should_alert)

    # Checks that attempts from different sources or to different destination ports are counted separately
    def test_sources_and_destination_ports_are_tracked_separately(self):
        self.try_first_nine_hosts()
        tenth_host = self.hosts[9]
        other_source = syn(22, 1, tenth_host, src_ip="192.0.2.11")
        self.assertIsNone(self.rule.process_packet(other_source))
        self.assertIsNone(self.rule.process_packet(syn(443, 1, tenth_host)))
        self.assertIsNotNone(self.rule.process_packet(syn(22, 1, tenth_host)))

    # Checks that only SYN-without-ACK packets count, excluding SYN-ACK, ACK, and records without TCP flags
    def test_only_initial_tcp_attempts_count(self):
        self.try_first_nine_hosts()
        for flags in (0x12, 0x10, None):  # SYN-ACK, ACK, UDP
            with self.subTest(flags=flags):
                packet = syn(22, 1, self.hosts[9])
                packet["tcp_flags"] = flags
                self.assertIsNone(self.rule.process_packet(packet))
        self.assertIsNotNone(self.rule.process_packet(syn(22, 1, self.hosts[9])))

    # Checks that a new burst can trigger another alert after the previous attempts expire
    def test_a_later_burst_can_raise_a_new_alert(self):
        for start in (0, 30):
            for host in self.hosts[:9]:
                self.assertIsNone(self.rule.process_packet(syn(22, start, host)))
            self.assertIsNotNone(
                self.rule.process_packet(syn(22, start + 1, self.hosts[9]))
            )



class DNSFailureTests(unittest.TestCase):

     # Creates a fresh DNS-failure detector and sixteen distinct domain names before each test
    def setUp(self):
        self.rule = DNSFailureRule()
        self.names = [f"missing{i:02d}.example." for i in range(1, 17)]

    # Checks that the fifteenth distinct failed name triggers an alert with the expected details while the first fourteen and the sixteenth do not
    def test_alerts_on_fifteenth_distinct_name_only(self):
        for second, name in enumerate(self.names[:14]):
            self.assertIsNone(self.rule.process_packet(dns_reply(name, second)))

        alert = self.rule.process_packet(dns_reply(self.names[14], 14))
        self.assertIsNotNone(alert)
        self.assertEqual(alert["client"], "192.0.2.10")
        self.assertEqual(alert["distinct_name_count"], 15)
        self.assertEqual(alert["example_names"], self.names[:3])
        self.assertEqual(alert["window_seconds"], 60)
        self.assertEqual(alert["timestamp"], 14)
        self.assertIsNone(self.rule.process_packet(dns_reply(self.names[15], 15)))

    # Checks that repeated failures for one name count once but refresh its timestamp
    def test_repeated_name_counts_once_and_refreshes_its_time(self):
        for second in range(16):
            self.assertIsNone(self.rule.process_packet(dns_reply(self.names[0], second)))

        # At second 70, the original failure has expired, but the retry at 15 still counts
        for name in self.names[1:14]:
            self.assertIsNone(self.rule.process_packet(dns_reply(name, 70)))

        self.assertIsNotNone(self.rule.process_packet(dns_reply(self.names[14], 70)))

    # Checks that failed names received by different clients are counted separately
    def test_clients_are_counted_separately(self):
        for name in self.names[:14]:
            self.assertIsNone(self.rule.process_packet(dns_reply(name, 0)))

        other_client = dns_reply(self.names[14], 1, client="192.0.2.11")
        self.assertIsNone(self.rule.process_packet(other_client))
        self.assertIsNotNone(self.rule.process_packet(dns_reply(self.names[14], 1)))

    # Checks that a failure exactly sixty seconds old counts but one older than sixty seconds does not
    def test_sixty_second_window_boundary(self):
        for elapsed, should_alert in [(60, True), (60.001, False)]:
            with self.subTest(elapsed=elapsed):
                rule = DNSFailureRule()
                rule.process_packet(dns_reply(self.names[0], 0))
                for name in self.names[1:14]:
                    rule.process_packet(dns_reply(name, 1))

                alert = rule.process_packet(dns_reply(self.names[14], elapsed))
                self.assertEqual(alert is not None, should_alert)

    # Checks that only NXDOMAIN responses count excluding no-error and server-failure responses
    def test_only_nxdomain_responses_count(self):
        for name in self.names[:14]:
            self.assertIsNone(self.rule.process_packet(dns_reply(name, 0)))

        for rcode in (0, 2):  # No error and server failure
            reply = dns_reply(self.names[14], 1, rcode=rcode)
            self.assertIsNone(self.rule.process_packet(reply))

        self.assertIsNotNone(self.rule.process_packet(dns_reply(self.names[14], 1)))



class ConnectionSpikeTests(unittest.TestCase):

     # Creates a fresh connection-spike detector before each test
    def setUp(self):
        self.rule = ConnectionSpikeRule()

    # Sends 199 distinct connection attempts and checks that none triggers an alert
    def send_199_attempts(self, timestamp=0):
        for number in range(199):
            self.assertIsNone(self.rule.process_packet(spike_syn(number, timestamp)))

    # Checks that retries do not increase the count and only the 200th attempt triggers an alert 
    def test_retry_stays_quiet_and_200th_attempt_alerts_once(self):
        self.send_199_attempts()
        self.assertIsNone(self.rule.process_packet(spike_syn(198, 1)))

        alert = self.rule.process_packet(spike_syn(199, 2))
        self.assertIsNotNone(alert)
        self.assertEqual(alert["attempt_count"], 200)
        self.assertEqual(alert["source_count"], 4)
        self.assertEqual(alert["dst_ip"], "198.51.100.20")
        self.assertEqual(alert["dst_port"], 443)
        self.assertEqual(alert["timestamp"], 2)
        self.assertEqual(alert["window_seconds"], 10)
        self.assertIsNone(self.rule.process_packet(spike_syn(200, 3)))

      # Checks that retries of an attempt started outside the window do not count as new attempts
    def test_retry_does_not_restart_an_expired_attempt(self):
        self.assertIsNone(self.rule.process_packet(spike_syn(0, 0)))
        self.assertIsNone(self.rule.process_packet(spike_syn(0, 9)))

        # At second 12, attempt 0 is recognisable but started outside the window.
        for number in range(1, 200):
            self.assertIsNone(self.rule.process_packet(spike_syn(number, 12)))
        self.assertIsNone(self.rule.process_packet(spike_syn(0, 12)))
        self.assertIsNotNone(self.rule.process_packet(spike_syn(200, 12)))

    # Checks that attempts started exactly ten seconds ago count but older attempts do not
    def test_ten_second_window_boundary(self):
        for elapsed, should_alert in [(10, True), (10.001, False)]:
            with self.subTest(elapsed=elapsed):
                rule = ConnectionSpikeRule()
                for number in range(199):
                    rule.process_packet(spike_syn(number, 0))
                alert = rule.process_packet(spike_syn(199, elapsed))
                self.assertEqual(alert is not None, should_alert)

    # Checks that attempts to different destination IPs or ports are counted separately
    def test_destination_services_are_counted_separately(self):
        self.send_199_attempts()
        other_port = spike_syn(199, 1, dst_port=80)
        other_host = spike_syn(199, 1, dst_ip="198.51.100.21")
        self.assertIsNone(self.rule.process_packet(other_port))
        self.assertIsNone(self.rule.process_packet(other_host))
        self.assertIsNotNone(self.rule.process_packet(spike_syn(199, 1)))

     # Checks that only SYN-without-ACK packets count, excluding SYN-ACK, ACK, and records without TCP flags
    def test_only_initial_syn_packets_count(self):
        self.send_199_attempts()
        for flags in (0x12, 0x10, None):  # SYN-ACK, ACK, UDP
            with self.subTest(flags=flags):
                packet = spike_syn(199, 1)
                packet["tcp_flags"] = flags
                self.assertIsNone(self.rule.process_packet(packet))
        self.assertIsNotNone(self.rule.process_packet(spike_syn(199, 1)))

    # Checks that a new sequence number counts as a separate attempt even when the endpoint IPs and ports are unchanged
    def test_same_endpoints_with_new_sequence_number_count_again(self):
        self.send_199_attempts()
        packet = spike_syn(198, 1)
        packet["tcp_seq"] += 1
        self.assertIsNotNone(self.rule.process_packet(packet))