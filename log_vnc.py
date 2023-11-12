import dpkt
import csv

def log_flow_fields(filename):
    with open(filename, 'r') as pcap_file:
        pcap = dpkt.pcap.Reader(pcap_file)
        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            if eth.type == dpkt.ethernet.ETH_TYPE_IP:
                ip = dpkt.ip.IP(eth.data)
                if ip.p == dpkt.ip.IP_PROTO_TCP:
                    tcp = dpkt.tcp.TCP(ip.data)
                    with open('flow_log.csv', 'a', newline='') as csvfile:
                        flow_writer = csv.DictWriter(csvfile, fieldnames=['flow_duration', 'Header_Length', 'Protocol_Type', 'Duration', 'Rate', 'Srate', 'ack_flag_number', 'syn_count', 'urg_count', 'rst_count', 'UDP', 'ICMP', 'tot_sum', 'Min', 'Max', 'AVG', 'Std', 'Tot_size', 'IAT', 'Number', 'Magnitue', 'Radius', 'Covariance', 'Variance', 'Weight'])
                        flow_writer.writerow({
                            'flow_duration': ts,
                            'Header_Length': len(eth.data) + len(ip.data) + len(tcp.data),
                            'Protocol_Type': ip.p,
                            'Duration': tcp.dport,
                            'Rate': tcp.sport,
                            'Srate': ip.ttl,
                            'ack_flag_number': tcp.flags,
                            'syn_count': len(tcp.options),
                            'urg_count': tcp.seq,
                            'rst_count': tcp.ack,
                            'UDP': 0,
                            'ICMP': 0,
                            'tot_sum': ip.sum,
                            'Min': tcp.window,
                            'Max': tcp.urg,
                            'AVG': tcp.opt,
                            'Std': tcp.mss,
                            'Tot_size': len(buf),
                            'IAT': len(ip.opt),
                            'Number': len(tcp.opt),
                            'Magnitue': len(tcp.opt),
                            'Radius': len(tcp.opt),
                            'Covariance': len(tcp.opt),
                            'Variance': len(tcp.opt),
                            'Weight': len(tcp.opt),
                        })

if __name__ == '__main__':
    filename = 'sample.pcap'
    log_flow_fields(filename)