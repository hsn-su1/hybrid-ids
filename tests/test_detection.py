import unittest
from ids.detection import PortScanRule, HostSweepRule

# Creates a fake SYN only packet record 
def syn(port, timestamp, dst_ip="198.51.100.20", src_ip="192.0.2.10"):
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": port,
        "timestamp": timestamp,
        "tcp_flags": 0x02,
    }

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