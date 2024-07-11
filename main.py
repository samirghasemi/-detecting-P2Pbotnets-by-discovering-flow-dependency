from scapy.all import sniff, IP, TCP
import time
import json
import math

# Constants
WAITING_TIME = 30
MAX_BYTES_THRESHOLD = 5000
MAX_DURATION_THRESHOLD = 300
MIN_PACKET_COUNT_THRESHOLD = 5
T_dep = 60  # Time threshold in seconds
N_dep = 5   # Difference in occurrences threshold
Sdep_th = 0.5  # Dependency score threshold

def create_flow_key_from_packet(packet):
    """Generate a unique flow key based on packet IP and TCP headers."""
    return f"{packet[IP].src}:{packet[TCP].sport}-{packet[IP].dst}:{packet[TCP].dport}"

def update_or_create_stream(streams, flow_key, packet, current_time):
    """Update an existing stream or create a new one based on the WAITING_TIME."""
    if flow_key in streams:
        last_session = streams[flow_key][-1]
        last_packet_time = last_session['end_time']
        if current_time - last_packet_time < WAITING_TIME:
            last_session['packets'].append(packet.summary())
            last_session['end_time'] = current_time
            last_session['total_bytes'] += len(packet)
        else:
            new_session = {
                'packets': [packet.summary()],
                'start_time': current_time,
                'end_time': current_time,
                'total_bytes': len(packet)
            }
            streams[flow_key].append(new_session)
    else:
        streams[flow_key] = [{
            'packets': [packet.summary()],
            'start_time': current_time,
            'end_time': current_time,
            'total_bytes': len(packet)
        }]
    return streams

def manage_stream(packet, streams):
    """Process each packet to manage stream data."""
    if IP in packet and TCP in packet:
        flow_key = create_flow_key_from_packet(packet)
        current_time = time.time()
        streams = update_or_create_stream(streams, flow_key, packet, current_time)
    return streams

def filter_streams(streams):
    """Filter streams based on criteria such as bytes, duration, and packet count."""
    filtered_streams = {}
    for flow_key, sessions in streams.items():
        for session in sessions:
            if (session['total_bytes'] < MAX_BYTES_THRESHOLD and
                (session['end_time'] - session['start_time']) < MAX_DURATION_THRESHOLD and
                len(session['packets']) > MIN_PACKET_COUNT_THRESHOLD):
                if flow_key not in filtered_streams:
                    filtered_streams[flow_key] = []
                filtered_streams[flow_key].append(session)
    return filtered_streams

def compute_occurrences(streams):
    """Compute the number of occurrences for each flow."""
    occurrences = {}
    for flow_key, sessions in streams.items():
        occurrences[flow_key] = sum(len(session['packets']) for session in sessions)
    return occurrences

def find_dependencies(streams, occurrences, T_dep, N_dep, Sdep_th):
    """Extract two-level flow dependencies."""
    dependencies = {}
    for flow_key in streams:
        sorted_flows = sorted(streams[flow_key], key=lambda x: x['start_time'])
        for i in range(len(sorted_flows)):
            fi = sorted_flows[i]
            print(fi)
            if fi[flow_key] not in dependencies:
                dependencies[fi[flow_key]] = {}
            for j in range(i + 1, len(sorted_flows)):
                fj = sorted_flows[j]
                if abs(occurrences[fi[flow_key]] - occurrences[fj[flow_key]]) < N_dep:
                    time_diff = fj['start_time'] - fi['end_time']
                    if time_diff < T_dep:
                        pair_key = f"{fi[flow_key]}->{fj[flow_key]}"
                        if pair_key in dependencies[fi[flow_key]]:
                            dependencies[fi[flow_key]][pair_key] += 1
                        else:
                            dependencies[fi[flow_key]][pair_key] = 1
                        Tij = dependencies[fi[flow_key]][pair_key]
                        Ni, Nj = occurrences[fi[flow_key]], occurrences[fj[flow_key]]
                        Sdep = math.sqrt((Tij**2) / (Ni * Nj))
                        if Sdep > Sdep_th:
                            dependencies[fi[flow_key]][pair_key] = Sdep
                        else:
                            del dependencies[fi[flow_key]][pair_key]
    return dependencies


def read_pcap_file(pcap_file):
    """Read packets from a pcap file and manage streams."""
    streams = {}
    def packet_processor(packet):
        nonlocal streams
        streams = manage_stream(packet, streams)
    sniff(offline=pcap_file, prn=packet_processor, store=False)
    return streams

def save_data(data, file_path):
    """Save data to a JSON file."""
    with open(file_path, 'w') as f:
        json.dump(data, f, indent=4)

def read_data(file_path):
    """Read data from a JSON file."""
    with open(file_path, 'r') as f:
        return json.load(f)
# Main flow
if __name__ == "__main__":
    # streams = read_pcap_file('EX-3.pcap')
    # save_data(streams, './streams_data.json')

    # filtered_streams = filter_streams(streams)
    # save_data(filtered_streams, './filtered_streams_data.json')

    # occurrences = compute_occurrences(filtered_streams)
    # save_data(occurrences, './occurrences_data.json')

    streams = read_data('./streams_data.json')
    filtered_streams = read_data('./filtered_streams_data.json')
    occurrences = read_data('./occurrences_data.json')

    dependencies = find_dependencies(filtered_streams, occurrences, T_dep, N_dep, Sdep_th)
    save_data(dependencies, './stream_dependencies.json')
    print(json.dumps(dependencies, indent=4))



    # streams = read_data('./streams_data.json')
    # filtered_streams = read_data('./filtered_streams_data.json')
    # occurrences = read_data('./occurrences_data.json')
    # host_flows = read_data('./host_flows_data.json')
    
    # dependencies = find_dependencies(host_flows, occurrences, T_dep, N_dep, Sdep_th)
    # save_data(dependencies, './stream_dependencies.json')
    # print(json.dumps(dependencies, indent=4))
