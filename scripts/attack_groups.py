#!/usr/bin/env python3
"""Attack category grouping definitions for result extraction.
   Follows eTRACE/scripts/attack_groups.py design.
"""
import re
from typing import Optional

# Group definitions for different datasets
GROUPS_IDS2017: dict[str, list[str]] = {
    "DoS_DDoS": ["DDoS", "DoS_GoldenEye", "DoS_Hulk", "DoS_Slowhttptest", "DoS_slowloris"],
    "BruteForce": ["Brute_Force", "FTP_Patator", "SSH_Patator"],
    "Web_Scan": ["PortScan", "Port_Scan", "XSS"],
    "Bot": ["Bot", "Botnet"],
}

GROUPS_CICIOT2025: dict[str, list[str]] = {
    "BruteForce": [
        "bruteforce_dictionary-ssh",
        "bruteforce_dictionary-telnet",
    ],
    "DoS_DDoS": [
        "dos_syn-flood", "dos_tcp-flood", "dos_udp-flood", "dos_http-flood",
        "dos_icmp-flood", "dos_slowloris", "dos_connect-flood", "dos_push-ack-flood",
        "dos_ack-frag-flood", "dos_icmp-frag-flood", "dos_mqtt-publish-flood",
        "dos_rst-fin-flood", "dos_synonymousip-flood", "dos_udp-frag-flood",
        "ddos_syn-flood", "ddos_tcp-flood", "ddos_udp-flood", "ddos_http-flood",
        "ddos_icmp-flood", "ddos_slowloris", "ddos_connect-flood", "ddos_push-ack-flood",
        "ddos_ack-frag-flood", "ddos_icmp-frag-flood", "ddos_mqtt-publish-flood",
        "ddos_rst-fin-flood", "ddos_synonymousip-flood", "ddos_udp-frag-flood",
    ],
    "Malware": [
        "malware_mirai-syn-flood",
        "malware_mirai-udp-flood",
    ],
    "MITM": [
        "mitm_arp-spoofing", "mitm_impersonation", "mitm_ip-spoofing",
    ],
    "Recon_Scan": [
        "recon_host-disc-arp-ping", "recon_host-disc-tcp-ack-ping", "recon_host-disc-tcp-syn-ping",
        "recon_host-disc-tcp-syn-stealth", "recon_host-disc-udp-ping", "recon_os-scan",
        "recon_ping-sweep", "recon_port-scan", "recon_vuln-scan",
    ],
    "Web_Attack": [
        "web_backdoor-upload", "web_command-injection",
        "web_sql-injection-blind", "web_sql-injection", "web_xss",
    ],
}

GROUPS_UNSW: dict[str, list[str]] = {
    "DoS_DDoS": ["DoS"],
    "Recon_Scan": ["Reconnaissance", "Analysis", "Fuzzers"],
    "Exploit_Malware": ["Exploits", "Backdoor", "Shellcode", "Worms"],
    "Generic": ["Generic"],
}

GROUPS_HYPERVISION: dict[str, list[str]] = {
    "BruteForce": [
        "telnetpwdla", "telnetpwdmd", "telnetpwdsm",
        "sshpwdla", "sshpwdmd", "sshpwdsm",
    ],
    "DoS_DDoS": [
        "charrdos", "cldaprdos", "dnsrdos", "memcachedrdos", "ntprdos", "riprdos",
        "ssdprdos", "synsdos", "udpsdos", "icmpsdos", "crossfirela", "crossfiremd",
        "crossfiresm", "rstsdos", "lrtcpdos02", "lrtcpdos05", "lrtcpdos10", "ackport"
    ],
    "Malware": [
        "agentinject", "adload", "bitcoinminer", "coinminer", "dridex", "emotet",
        "koler", "magic", "mazarbot", "mobidash", "paraminject", "plankton",
        "ransombo", "sality", "snojan", "svpeng", "thbot", "trickbot",
        "trojanminer", "wannalocker", "webcompanion", "zsone", "spam1", "spam50",
        "spam100", "ccleaner", "persistence", "oracle", "penetho", "trickster",
    ],
    "Recon_Scan": [
        "dns_lrscan", "http_lrscan", "icmp_lrscan", "ipidaddr", "ipidport",
        "netbios_lrscan", "rdp_lrscan", "sslscan", "httpscan", "httpsscan", "icmpscan",
        "dnsscan", "ntpscan", "scrapy", "sshscan", "telnet_lrscan", "vlc_lrscan",
        "ssh_lrscan", "snmp_lrscan", "smtp_lrscan",
    ],
    "Web_Attack": ["xss", "codeinject", "webshell", "sqlscan", "csrf", "csfr"],
}

GROUPS_CIC_APT_IOT: dict[str, list[str]] = {
    "APT": [
        "cleanup", "collection", "command_and_control", "credential_access",
        "discovery", "exfiltration", "lateral_movement", "persistence",
    ],
}

GROUPS_DOHBRW: dict[str, list[str]] = {
    "Tunneling": ["dns2tcp", "dnscat2", "iodine"],
}


def _norm_token(s: str) -> str:
    """Normalize token for matching."""
    return re.sub(r"[^A-Za-z0-9_]+", "_", s).strip("_").lower()


def match_group(dataset: str, token: str) -> Optional[str]:
    """Match an attack file token to its category group.

    Args:
        dataset: Dataset name (e.g., "ids2017", "unsw", "hypervision", "ciciot2025")
        token: Attack file token (normalized from filename like "Bot", "DoS_Hulk")

    Returns:
        Category name (e.g., "DoS_DDoS", "BruteForce") or None if no match
    """
    # Normalize dataset name
    dataset_lower = dataset.lower()
    
    if "ids2017" in dataset_lower or dataset == "ids2017":
        groups = GROUPS_IDS2017
    elif "ciciot" in dataset_lower or dataset == "ciciot2025":
        groups = GROUPS_CICIOT2025
    elif "unsw" in dataset_lower or dataset == "unsw":
        groups = GROUPS_UNSW
    elif "hypervision" in dataset_lower or dataset == "hypervision":
        groups = GROUPS_HYPERVISION
    elif "cic_apt" in dataset_lower or dataset == "cic_apt_iot":
        groups = GROUPS_CIC_APT_IOT
    elif "dohbrw" in dataset_lower or dataset == "dohbrw":
        groups = GROUPS_DOHBRW
    else:
        return None

    tok = _norm_token(token)
    for gname, keys in groups.items():
        for k in keys:
            k2 = _norm_token(k)
            # Contains matching: e.g., "lrtcpdos02" matches "dos" / "rdos"
            if k2 in tok:
                return gname
    return None
