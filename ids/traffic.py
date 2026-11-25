from scapy.all import PcapReader, IP, UDP, TCP
import argparse

# Extracts the fields from TCP/UDP packets used for flow analysis
def extract_packet_fields(packet):

    if TCP in packet:
        protocol = TCP
    elif UDP in packet:
        protocol = UDP
    else:
        return None

    src_port = packet[protocol].sport
    dst_port = packet[protocol].dport

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
    else:
        return None

    size_bytes = len(packet)
    timestamp = packet.time

    packet_dict = {
        "src_ip" : src_ip,
        "dst_ip" : dst_ip,
        "src_port" : src_port,
        "dst_port" : dst_port,
        "protocol" : protocol.__name__,
        "size_bytes" : size_bytes,
        "timestamp" : timestamp 
    }

    return packet_dict

# Builds a bi-directional flow key that groups packets by the two IP/port endpoints involved 
def flow_key(fields):

    source = (fields["src_ip"], fields["src_port"])
    destination = (fields["dst_ip"], fields["dst_port"])

    # Sorting keeps the key the same even when a reply swaps source and destination
    endpoint_a, endpoint_b = sorted((source, destination))

    return (fields["protocol"], endpoint_a, endpoint_b)

if __name__ == "__main__":

    flows = {}

    parser = argparse.ArgumentParser()
    parser.add_argument("capture_path")
    args = parser.parse_args()

    # Read one packet at a time so large captures can be processed in memory
    with PcapReader(args.capture_path) as packets:
        for packet in packets:

            fields = extract_packet_fields(packet)

            # Initializing new flows from the packets captured and updating statistics
            if fields is not None:
                key = flow_key(fields)

                if key not in flows:
                    flows[key] = {"packet_count": 0, "total_bytes": 0, "first_seen": fields["timestamp"], "last_seen": fields["timestamp"]}

                flows[key]["packet_count"] += 1
                flows[key]["total_bytes"] += fields["size_bytes"]

                flows[key]["first_seen"] = min(flows[key]["first_seen"], fields["timestamp"])
                flows[key]["last_seen"] = max(flows[key]["last_seen"], fields["timestamp"])

    # Once the capture is processed we calculate each flow's duration and average packet rate and output it
    for flow in flows.values():

        duration = flow["last_seen"] - flow["first_seen"]

        if duration != 0:
            packets_per_second = flow["packet_count"] / duration
        else:
            packets_per_second = None

        flow["duration_seconds"] = duration
        flow["packets_per_second"] = packets_per_second

    print(flows)
