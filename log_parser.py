import csv
from collections import defaultdict

#Protocol numbers mapped to name by IANA
protocol_mapping = {
    "0": "HOPOPT",
    "1": "icmp",
    "2": "IGMP",
    "3": "GGP",
    "4": "IPv4",
    "5": "ST",
    "6": "tcp",
    "7": "CBT",
    "8": "EGP",
    "9": "IGP",
    "10": "BBN-RCC-MON",
    "11": "NVP-II",
    "12": "PUP",
    "13": "ARGUS",
    "14": "EMCON",
    "15": "XNET",
    "16": "CHAOS",
    "17": "udp",
    "18": "mux",
    "19": "DCN-MEAS",
    "20": "HMP",
    "21": "PRM",
    "22": "XNS-IDP",
    "23": "TRUNK-1",
    "24": "TRUNK-2",
    "25": "LEAF-1",
    "26": "LEAF-2",
    "27": "RDP",
    "28": "IRTP",
    "29": "ISO-TP4",
    "30": "NETBLT",
    "31": "MFE-NSP",
    "32": "MERIT-INP",
    "33": "DCCP",
    "34": "3PC",
    "35": "IDPR",
    "36": "XTP",
    "37": "DDP",
    "38": "IDPR-CMTP",
    "39": "TP++",
    "40": "IL",
    "41": "IPv6",
    "42": "SDRP",
    "43": "IPv6-Route",
    "44": "IPv6-Frag",
    "45": "IDRP",
    "46": "RSVP",
    "47": "GRE",
    "48": "DSR",
    "49": "BNA",
    "50": "ESP",
    "51": "AH",
    "52": "I-NLSP",
    "53": "SWIPE",
    "54": "NARP",
    "55": "MOBILE",
    "56": "TLSP",
    "57": "SKIP",
    "58": "IPv6-ICMP",
    "59": "IPv6-NoNxt",
    "60": "IPv6-Opts",
    "61": "host internal protocol",
    "62": "CFTP",
    "63": "local network",
    "64": "SAT-EXPAK",
    "65": "KRYPTOLAN",
    "66": "RVD",
    "67": "IPPC",
    "68": "distributed file system",
    "69": "SAT-MON",
    "70": "VISA",
    "71": "IPCV",
    "72": "CPNX",
    "73": "CPHB",
    "74": "WSN",
    "75": "PVP",
    "76": "BR-SAT-MON",
    "77": "SUN-ND",
    "78": "WB-MON",
    "79": "WB-EXPAK",
    "80": "ISO-IP",
    "81": "VMTP",
    "82": "SECURE-VMTP",
    "83": "VINES",
    "84": "TTP",
    "85": "NSFNET-IGP",
    "86": "DGP",
    "87": "TCF",
    "88": "EIGRP",
    "89": "OSPFIGP",
    "90": "Sprite-RPC",
    "91": "LARP",
    "92": "MTP",
    "93": "AX.25",
    "94": "IPIP",
    "95": "MICP",
    "96": "SCC-SP",
    "97": "ETHERIP",
    "98": "ENCAP",
    "99": "private encryption scheme",
    "100": "GMTP",
    "101": "IFMP",
    "102": "PNNI",
    "103": "PIM",
    "104": "ARIS",
    "105": "SCPS",
    "106": "QNX",
    "107": "A/N",
    "108": "IPComp",
    "109": "SNP",
    "110": "Compaq-Peer",
    "111": "IPX-in-IP",
    "112": "VRRP",
    "113": "PGM",
    "114": "zero-hop protocol",
    "115": "L2TP",
    "116": "DDX",
    "117": "IATP",
    "118": "STP",
    "119": "SRP",
    "120": "UTI",
    "121": "SMP",
    "122": "SM",
    "123": "PTP",
    "124": "ISIS over IPv4",
    "125": "FIRE",
    "126": "CRTP",
    "127": "CRUDP",
    "128": "SSCOPMCE",
    "129": "IPLT",
    "130": "SPS",
    "131": "PIPE",
    "132": "SCTP",
    "133": "FC",
    "134": "RSVP-E2E-IGNORE",
    "135": "Mobility Header",
    "136": "UDPLite",
    "137": "MPLS-in-IP",
    "138": "manet",
    "139": "HIP",
    "140": "Shim6",
    "141": "WESP",
    "142": "ROHC",
    "143": "Ethernet",
    "144": "AGGFRAG",
    "145": "NSH",
}

def protocol_num_to_name(protocol_num):
    #mapping protocol num to name 
    return protocol_mapping.get(protocol_num, "unknown")

def parse_lookup_table(lookup_file):
    #Parse lookup table 
    #mapping port & protocol to tag
    tag_lookup = {}
    try:
        with open(lookup_file, mode='r') as file:
            reader = csv.reader(file)
            next(reader)  #Skip the header row
            for row in reader:
                if len(row) == 3:
                    dstport, protocol, tag = row
                    key = f"{dstport.lower()},{protocol.lower()}"
                    tag_lookup[key] = tag
                else:
                    print(f"Warning: Skipping invalid row in lookup table: {row}")
    except FileNotFoundError:
        print(f"Error: The file {lookup_file} was not found.")
        return {}
    except Exception as e:
        print(f"Error reading {lookup_file}: {e}")
        return {}
    return tag_lookup

def process_flow_logs(flow_file, tag_lookup):
    #Process log file 
    #counting the tag count & port/protocol count
    #return the counts
    tag_counts = defaultdict(int)
    port_protocol_counts = defaultdict(int)
    untagged_count = 0

    try:
        with open(flow_file, mode='r') as file:
            for line in file:
                fields = line.strip().split()
                if len(fields) >= 8:
                    dstport = fields[5]
                    protocol_num = fields[7]

                    protocol = protocol_num_to_name(protocol_num)
                    key = f"{dstport.lower()},{protocol.lower()}"

                    port_protocol_counts[key] += 1

                    if key in tag_lookup:
                        tag_counts[tag_lookup[key]] += 1
                    else:
                        untagged_count += 1
                else:
                    print(f"Warning: Skipping invalid log")
    except FileNotFoundError:
        print(f"Error: The file {flow_file} was not found.")
    except Exception as e:
        print(f"Error processing {flow_file}: {e}")

    return tag_counts, port_protocol_counts, untagged_count

def write_output(output_file, tag_counts, port_protocol_counts, untagged_count):
    #Generate output file
    #Prints the tag count 
    #Prints the port/protocol count
    try:
        with open(output_file, mode='w', newline='') as file:
            writer = csv.writer(file)

            #Print Tag Counts
            writer.writerow(["Tag", "Count"])
            for tag, count in tag_counts.items():
                writer.writerow([tag, count])
            writer.writerow(["Untagged", untagged_count])

            #Print Port/Protocol Counts
            writer.writerow([])
            writer.writerow(["Port", "Protocol", "Count"])
            for key, count in port_protocol_counts.items():
                dstport, protocol = key.split(',')
                writer.writerow([dstport, protocol, count])
    except Exception as e:
        print(f"Error writing to {output_file}: {e}")

if __name__ == "__main__":
    lookup_file = "lookup.csv"
    flow_file = "logs.txt"
    output_file = "output.csv"

    tag_lookup = parse_lookup_table(lookup_file)
    if tag_lookup:
        tag_counts, port_protocol_counts, untagged_count = process_flow_logs(flow_file, tag_lookup)
        write_output(output_file, tag_counts, port_protocol_counts, untagged_count)
    else:
        print("Error: No valid tag mappings were loaded.")
