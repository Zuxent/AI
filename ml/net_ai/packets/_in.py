
## Program calls
from utilities.logging import *
from config.config import *
from packets.decode import *



def tshark(pcap, pcap_path):
    logp("Running tshark...")
    start_time = time.time()
    analyzer = SimpleRawPCAP(pcap_path)
    analyzer.parse()  # Required to populate data before analysis
    user = "developer"
    results = analyzer.analyze_all()
    #log_to_discord(user ,results, analyzer.entropy)
    #logp("Total unique source IPs:", len(analyzer.src_ip_counts))
    bad_ip_count = analyzer.suspected_ips_count
    ip_count = len(analyzer.src_ip_counts)
    bad_ip_percentage = (bad_ip_count / ip_count) * 100 if ip_count > 0 else 0
    logp(f"Bad IP Percentage: {bad_ip_percentage:.2f}%")
    logp(f"{ip_count} total IPs")
    logp(f"{bad_ip_count} bad IPs")


    #analyzer.post_analysis()
    #print(f"{analyzer.entropy} entropy")
    total_time = round(time.time() - start_time, 3)
    logp(f"✅ Time to Analysis → {total_time}s")
    return results