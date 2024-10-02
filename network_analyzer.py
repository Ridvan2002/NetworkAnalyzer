import sys
import logging
from scapy.layers.inet import IP, TCP, UDP
from scapy.all import Scapy_Exception, rdpcap
import pandas as pd
import matplotlib.pyplot as plt
from tqdm import tqdm

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__) 

def read_pcap(pcap_file):
    try:
        return rdpcap(pcap_file)  
    except FileNotFoundError:
        logger.error(f"PCAP file not found: {pcap_file}")  
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error reading PCAP file: {e}") 
        sys.exit(1)  

def extract_packet_data(packets):
    packet_data = []
    for packet in tqdm(packets, desc="Processing packets", unit="packet"):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            size = len(packet)
            timestamp = packet.time
            dst_port = packet[TCP].dport if TCP in packet else None
            packet_data.append({
                "src_ip": src_ip, 
                "dst_ip": dst_ip, 
                "protocol": protocol, 
                "size": size, 
                "dst_port": dst_port, 
                "timestamp": timestamp
            })
    return pd.DataFrame(packet_data)

def protocol_name(number):
    protocol_dict = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
    return protocol_dict.get(number, f"Unknown({number})")

def analyze_packet_data(df):
    if 'protocol' not in df.columns:
        logging.error("DataFrame does not contain 'protocol' column.")
        return df

    df['protocol'] = df['protocol'].apply(protocol_name)
    communication_pairs = df.groupby(['src_ip', 'dst_ip']).size().reset_index(name='count')
    most_common_pairs = communication_pairs.sort_values('count', ascending=False).head(15)
    packet_size_distribution = df['size'].describe()
    protocol_usage = df['protocol'].value_counts()
    top_talkers = df['src_ip'].value_counts().head(15)
    top_listeners = df['dst_ip'].value_counts().head(15)
    logger.info("\nMost Common Communication Pairs:\n")
    logger.info(most_common_pairs.to_string(index=False))
    logger.info("\nPacket Size Distribution:\n")
    logger.info(packet_size_distribution.to_string())
    logger.info("\nProtocol Usage:\n")
    logger.info(protocol_usage.to_string())
    logger.info("\nTop Talkers (Source IPs with most packets):\n")
    logger.info(top_talkers.to_string())
    logger.info("\nTop Listeners (Destination IPs with most packets):\n")
    logger.info(top_listeners.to_string())
    return df

def detect_port_scanning(df, port_scan_threshold):
    if 'dst_port' not in df.columns:
        logging.error("DataFrame does not contain 'dst_port' column.")
        return

    port_scan_df = df[df['dst_port'].notna()].groupby(['src_ip', 'dst_port']).size().reset_index(name='count')
    unique_ports_per_ip = port_scan_df.groupby('src_ip').size().reset_index(name='unique_ports')
    potential_port_scanners = unique_ports_per_ip[unique_ports_per_ip['unique_ports'] >= port_scan_threshold]
    if not potential_port_scanners.empty:
        logger.warning(f"Potential port scanning detected from IP addresses: {', '.join(potential_port_scanners['src_ip'].unique())}")

def detect_suspicious_activity(df):
    if 'timestamp' not in df.columns:
        logger.error("DataFrame does not contain 'timestamp' column.")
        return

    try:
        df['timestamp'] = pd.to_numeric(df['timestamp'], errors='coerce')
        df.dropna(subset=['timestamp'], inplace=True)
        df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s', errors='coerce')

        grouped = df.groupby('src_ip')
        suspicious_ips = []
        for name, group in grouped:
            if not group.empty:
                duration = (group['timestamp'].max() - group['timestamp'].min()).total_seconds()
                if duration < 60 and len(group) > 1000:
                    suspicious_ips.append(name)
                    logger.info(f"Suspicious activity by {name}: {len(group)} packets in {duration} seconds.")
        
        if suspicious_ips:
            logger.warning(f"Suspicious activity detected from IPs: {', '.join(suspicious_ips)}")
        else:
            logger.info("No suspicious activity detected based on current thresholds.")

    except Exception as e:
        logger.error(f"Error in processing suspicious activity detection: {e}")
        
def filter_data(df, ip=None, protocol=None):
    if df.empty:
        logger.info("No data to work with.")
        return df

    if 'src_ip' not in df.columns or 'dst_ip' not in df.columns or 'protocol' not in df.columns:
        logger.error("Essential columns are missing.")
        return df

    logger.info(f"Total TCP packets before filtering: {df[df['protocol'] == 'TCP'].shape[0]}")
    logger.info(f"Total packets for IP {ip} before filtering: {df[(df['src_ip'] == ip) | (df['dst_ip'] == ip)].shape[0]}")

    if ip:
        df = df[(df['src_ip'] == ip) | (df['dst_ip'] == ip)]
    if protocol:
        df = df[df['protocol'] == protocol]

    logger.info(f"Data count after filtering by IP and protocol: {df.shape[0]}")

    return df

def export_data(df, file_name, file_format='csv'):
    if file_format == 'excel':
        file_name += '.xlsx'
        df.to_excel(file_name, index=False)
    else:
        file_name += '.csv'
        df.to_csv(file_name, index=False)
    logger.info(f"Data exported to {file_name}")

def plot_protocol_distribution(df):
    if not df.empty:
        protocol_counts = df['protocol'].value_counts()
        if not protocol_counts.empty:
            plt.figure(figsize=(10, 6))
            ax = protocol_counts.plot(kind='bar')  
            plt.title('Protocol Distribution')
            plt.xlabel('Protocol')
            plt.ylabel('Number of Packets')
            plt.xticks(rotation=45)
            plt.tight_layout()

            for p in ax.patches:
                ax.annotate(f"{p.get_height():.0f}", 
                            (p.get_x() + p.get_width() / 2., p.get_height()), 
                            ha='center', 
                            va='bottom')

            plt.show()
        else:
            logger.info("No protocol data to plot for the specified filters.")
    else:
        logger.info("No data to plot for the specified filters.")


def plot_packet_size_distribution(df):
    plt.figure(figsize=(10, 6))
    df['size'].plot(kind='hist', bins=20, title='Packet Size Distribution')
    plt.xlabel('Packet Size (bytes)')
    plt.ylabel('Frequency')
    plt.grid(True)
    plt.show()

def plot_top_talkers_listeners(df):
    if df.empty:
        logger.info("No data available to plot for talkers and listeners.")
        return

    if 'src_ip' not in df.columns or 'dst_ip' not in df.columns:
        logger.info("Necessary columns for plotting top talkers and listeners are missing.")
        return

    top_talkers = df['src_ip'].value_counts().head(20)
    top_listeners = df['dst_ip'].value_counts().head(20)

    if top_talkers.empty or top_listeners.empty:
        logger.info("No sufficient data to plot top talkers or listeners.")
        return

    fig, axes = plt.subplots(nrows=1, ncols=2, figsize=(15, 6))

    top_talkers.plot(kind='bar', ax=axes[0], color='skyblue')
    axes[0].set_title('Top Talkers (Source IPs)')
    axes[0].set_xlabel('Source IP')
    axes[0].set_ylabel('Number of Packets')
    axes[0].tick_params(rotation=45)

    top_listeners.plot(kind='bar', ax=axes[1], color='lightgreen')
    axes[1].set_title('Top Listeners (Destination IPs)')
    axes[1].set_xlabel('Destination IP')
    axes[1].tick_params(rotation=45)

    plt.tight_layout()
    plt.show()

def plot_all_graphs(df):
    if not df.empty:
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
            df.dropna(subset=['timestamp'], inplace=True)
        
        plot_protocol_distribution(df)
        plot_packet_size_distribution(df)
        plot_top_talkers_listeners(df)
        
        if 'timestamp' in df.columns:
            plot_traffic_flow_rate(df)
            
        
        plot_protocol_breakdown(df)

    else:
        logger.info("No data available to plot.")

def main(pcap_file, port_scan_threshold):
    packets = read_pcap(pcap_file)
    df = extract_packet_data(packets)
    df = analyze_packet_data(df)
    detect_port_scanning(df, port_scan_threshold)
    detect_suspicious_activity(df)
    
    filter_ip = input("Enter an IP to filter (or press Enter to skip): ")
    filter_protocol = input("Enter a protocol to filter (or press Enter to skip): ")
    filtered_df = filter_data(df, filter_ip, filter_protocol)
    
    if not filtered_df.empty:
        export_choice = input("Do you want to export the data? (yes/no): ")
        if export_choice.lower() == 'yes':
            file_name = input("Enter the filename to export: ")
            file_format = input("Enter the file format (csv/excel): ")
            export_data(filtered_df, file_name, file_format)
        
        plot_all_graphs(filtered_df)
    else:
        logger.info("No data after filtering. Exiting.")
    
def plot_traffic_flow_rate(df):
    if 'timestamp' not in df.columns:
        logging.error("DataFrame does not contain 'timestamp' column.")
        return
    
    if isinstance(df['timestamp'].iloc[0], str):
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce') 
    elif pd.api.types.is_numeric_dtype(df['timestamp']):
        df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s', errors='coerce') 

    if df['timestamp'].isnull().any():
        logging.warning("Some timestamps could not be converted.")
        df.dropna(subset=['timestamp'], inplace=True)  

    df.set_index('timestamp', inplace=True)
    df['size_cumsum'] = df['size'].cumsum()
    resample_span = (df.index.max() - df.index.min()).total_seconds()

    if resample_span < 60:
        freq = 's'  
    elif resample_span < 3600:
        freq = 'min'
    else:
        freq = 'H'

    df_resampled = df['size_cumsum'].resample(freq).mean()

    plt.figure(figsize=(12, 6))
    plt.plot(df_resampled.index, df_resampled.values, marker='o', linestyle='-')
    plt.title(f'Traffic Flow Rate Over Time ({freq} bins)')
    plt.xlabel('Time')
    plt.ylabel('Cumulative Data Transferred (bytes)')
    plt.grid(True)
    plt.show()

def validate_data(df, column_name):
    if column_name not in df.columns:
        logging.warning(f"'{column_name}' column is missing from the DataFrame.")
        return False
    if df[column_name].isnull().all():
        logging.warning(f"All entries in '{column_name}' column are null.")
        return False
    return True

def plot_protocol_breakdown(df):
    if not validate_data(df, 'protocol'):
        return
    protocol_counts = df['protocol'].value_counts()
    if protocol_counts.nunique() <= 0:
        logging.info("Not enough protocol diversity for meaningful breakdown visualization.")
        return

    plt.figure(figsize=(8, 8))
    plt.pie(protocol_counts, labels=protocol_counts.index, autopct='%1.1f%%', startangle=140)
    plt.title('Protocol Usage Breakdown')
    plt.show()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        logger.error("Please provide the path to the PCAP file.")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    port_scan_threshold = 100  
    if len(sys.argv) >= 3:
        try:
            port_scan_threshold = int(sys.argv[2])
        except ValueError:
            logger.error("Invalid port_scan_threshold value. Using the default value.")
    
    main(pcap_file, port_scan_threshold)


