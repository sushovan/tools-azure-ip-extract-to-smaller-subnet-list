#!/usr/bin/env python3
"""
Extract IP ranges from Azure Service Tags JSON file and format for WireGuard AllowedIPs
"""

# Author: Sushovan (https://github.com/sushovan)
# Date: 2025-07-16
# Purpose: Extract Azure IP ranges for WireGuard configuration
#
# Project: Azure-IPs-Set
# License: MIT

import json
import sys
from typing import List, Set
import ipaddress
import os
import requests

JSON_URL = "https://download.microsoft.com/download/7/1/d/71d86715-5596-4529-9b13-da13a5de5b63/ServiceTags_Public_20250707.json"
JSON_FILENAME = "tmp/ServiceTags_Public.json"
OUTPUT_FILENAME_FOR_LIST = "tmp/azure_ips.txt"

def extract_ip_ranges(json_file_path: str) -> List[str]:
    """Extract all IP ranges from Azure Service Tags JSON file"""
    try:
        with open(json_file_path, 'r') as f:
            data = json.load(f)
        
        ip_ranges = set()
        
        # Extract from all service tags
        for service in data.get('values', []):
            service_name = service.get('name', 'Unknown')
            address_prefixes = service.get('properties', {}).get('addressPrefixes', [])
            
            for prefix in address_prefixes:
                # Only include IPv4 addresses (WireGuard supports IPv6 too, but most setups use IPv4)
                try:
                    network = ipaddress.ip_network(prefix, strict=False)
                    if network.version == 4:  # IPv4 only
                        ip_ranges.add(prefix)
                except ValueError:
                    # Skip invalid IP ranges
                    continue
        
        return sorted(list(ip_ranges))
    
    except FileNotFoundError:
        print(f"Error: File '{json_file_path}' not found.")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in file '{json_file_path}'.")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

def consolidate_ranges(ip_ranges: List[str]) -> List[str]:
    """
    Consolidate overlapping and adjacent IP ranges to reduce the list size.
    This is a lossless consolidation.
    """
    networks = [ipaddress.ip_network(ip) for ip in ip_ranges]
    # Collapse overlapping and adjacent networks
    collapsed = ipaddress.collapse_addresses(networks)
    return [str(net) for net in collapsed]

def summarize_ranges(ip_ranges: List[str], max_prefix_diff: int = 2) -> List[str]:
    """
    Summarize a list of IP ranges into a smaller, more general list of supernets.
    This is a lossy process, as it may include IPs not in the original list.

    :param ip_ranges: A list of IP CIDR strings to summarize.
    :param max_prefix_diff: The maximum allowed difference in prefix length
                              to merge two networks. e.g., a value of 2 allows
                              merging a /24 network into a /22 supernet.
    :return: A list of summarized IP CIDR strings.
    """
    if not ip_ranges:
        return []

    networks = sorted([ipaddress.ip_network(ip) for ip in ip_ranges])
    summarized_nets = []

    i = 0
    while i < len(networks):
        current_net = networks[i]
        group = [current_net]

        # Look ahead to find networks that can be grouped together
        j = i + 1
        while j < len(networks):
            next_net = networks[j]

            # Try to create a supernet that covers the current group and the next network
            group_start = group[0].network_address
            group_end = group[-1].broadcast_address
            next_end = next_net.broadcast_address

            # Find the supernet that covers from group start to next network end
            try:
                candidate_supernet = list(ipaddress.summarize_address_range(group_start, next_end))[0]

                # Only merge if:
                # 1. The supernet is not too much bigger than the original networks
                # 2. The gap between networks is reasonable
                gap_size = int(next_net.network_address) - int(group[-1].broadcast_address) - 1
                supernet_size = candidate_supernet.num_addresses
                original_size = sum(net.num_addresses for net in group) + next_net.num_addresses

                # Conservative merging: only merge if supernet is at most 4x the original size
                # and the gap is not too large
                if (candidate_supernet.prefixlen >= current_net.prefixlen - max_prefix_diff and
                    supernet_size <= original_size * 4 and
                    gap_size <= next_net.num_addresses):
                    group.append(next_net)
                    j += 1
                else:
                    break
            except:
                break

        # Create the supernet for this group
        if len(group) == 1:
            summarized_nets.append(group[0])
        else:
            group_start = group[0].network_address
            group_end = group[-1].broadcast_address
            supernet = list(ipaddress.summarize_address_range(group_start, group_end))[0]
            summarized_nets.append(supernet)

        i = j

    return [str(net) for net in summarized_nets]

def format_for_wireguard(ip_ranges: List[str], max_line_length: int = 80) -> str:
    """Format IP ranges for WireGuard AllowedIPs"""
    if not ip_ranges:
        return "AllowedIPs = "
    
    # Join all ranges with commas
    all_ranges = ", ".join(ip_ranges)
    
    # If the line is too long, break it into multiple lines
    if len(all_ranges) + len("AllowedIPs = ") <= max_line_length:
        return f"AllowedIPs = {all_ranges}"
    
    # Multi-line format
    result = "AllowedIPs = "
    current_line = "AllowedIPs = "
    
    for i, ip_range in enumerate(ip_ranges):
        if i == 0:
            current_line += ip_range
        else:
            test_line = current_line + ", " + ip_range
            if len(test_line) <= max_line_length:
                current_line = test_line
            else:
                result += current_line + ", \\\n             "
                current_line = "             " + ip_range
    
    result += current_line
    return result

def ensure_json_file(json_path: str = JSON_FILENAME, url: str = JSON_URL) -> str:
    """Download the JSON file if it does not exist locally. Handles SSL errors gracefully."""
    if not os.path.exists(json_path):
        print(f"Downloading Azure Service Tags JSON from {url} ...")
        try:
            # First attempt with SSL verification
            response = requests.get(url, stream=True)
            response.raise_for_status()
            with open(json_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
        except requests.exceptions.SSLError:
            print("Warning: SSL certificate verification failed. Retrying without certificate verification (not recommended for production)...")
            # Second attempt without SSL verification
            response = requests.get(url, stream=True, verify=False)
            response.raise_for_status()
            with open(json_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
        except requests.exceptions.RequestException as e:
            print(f"Download failed: {e}")
            sys.exit(1)

        print(f"Downloaded to {json_path}")
    else:
        print(f"Using existing JSON file: {json_path}")
    return json_path

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Extract and consolidate Azure IP ranges for WireGuard AllowedIPs.")
    parser.add_argument("-j", "--json_file", help="Path to Azure Service Tags JSON file", default=JSON_FILENAME)
    parser.add_argument("-o", "--output", help="Output file for AllowedIPs list", default=OUTPUT_FILENAME_FOR_LIST)
    args = parser.parse_args()

    json_file = ensure_json_file(args.json_file)
    ip_ranges = extract_ip_ranges(json_file)

    print(f"Found {len(ip_ranges)} unique IP ranges.")
    
    # Option 1: Use all ranges (may be very long)
    print("\n" + "="*80)
    print("OPTION 1: All IP ranges (may be very long for WireGuard)")
    print("="*80)
    wireguard_config = format_for_wireguard(ip_ranges)
    print(wireguard_config)
    
    # Option 2: Try to consolidate ranges
    print("\n" + "="*80)
    print("OPTION 2: Attempting to consolidate overlapping ranges (lossless)")
    print("="*80)
    consolidated_ranges = consolidate_ranges(ip_ranges)
    print(f"Consolidated to {len(consolidated_ranges)} ranges.")
    wireguard_config_consolidated = format_for_wireguard(consolidated_ranges)
    print(wireguard_config_consolidated)

    # Option 3: A more aggressive, lossy summarization
    print("\n" + "="*80)
    print("OPTION 3: Aggressive summarization (lossy)")
    print("="*80)
    summarized_ranges = summarize_ranges(consolidated_ranges, 4)
    print(f"Summarized to {len(summarized_ranges)} ranges.")
    wireguard_config_summarized = format_for_wireguard(summarized_ranges)
    print(wireguard_config_summarized)

    # Option 4: Show some major Azure IP blocks that might be more practical
    print("\n" + "="*80)
    print("OPTION 4: Major Azure IP blocks (most practical approach)")
    print("="*80)
    print("Consider using these major Azure IP ranges instead:")
    option4_blocks = [
        ipaddress.ip_network("13.0.0.0/8"),
        ipaddress.ip_network("20.0.0.0/8"),
        ipaddress.ip_network("40.0.0.0/8"),
        ipaddress.ip_network("51.0.0.0/8"),
        ipaddress.ip_network("52.0.0.0/8"),
        ipaddress.ip_network("104.0.0.0/8"),
    ]
    print("AllowedIPs = " + ", ".join(str(b) for b in option4_blocks))
    print("\nNote: This covers most Azure services but may include some non-Azure IPs.")
    print("For maximum precision, use Option 1 or 2 above.")

    # Check which Azure IPs are excluded by Option 4
    excluded_ranges = []
    for ipr in ip_ranges:
        net = ipaddress.ip_network(ipr, strict=False)
        if not any(net.subnet_of(block) for block in option4_blocks):
            excluded_ranges.append(ipr)

    print(f"\nNumber of Azure IP ranges NOT covered by Option 4: {len(excluded_ranges)}")
    if excluded_ranges:
        print("Sample of excluded ranges:")
        for r in excluded_ranges[:20]:
            print(r)
        if len(excluded_ranges) > 20:
            print("...")

    # Save to file
    with open(args.output, 'w') as f:
        f.write("# Azure Service Tags IP Ranges for WireGuard AllowedIPs\n")
        f.write(f"# Generated from {args.json_file}\n")
        f.write(f"# Total ranges: {len(ip_ranges)}\n")
        f.write(f"# Consolidated ranges (lossless): {len(consolidated_ranges)}\n")
        f.write(f"# Summarized ranges (lossy): {len(summarized_ranges)}\n\n")
        f.write("# Option 1: All ranges\n")
        f.write(wireguard_config + "\n\n")
        f.write("# Option 2: Consolidated ranges (lossless)\n")
        f.write(wireguard_config_consolidated + "\n\n")
        f.write("# Option 3: Aggressive summarization (lossy)\n")
        f.write(wireguard_config_summarized + "\n\n")
        f.write("# Option 4: Major Azure blocks (practical approach)\n")
        f.write("AllowedIPs = " + ", ".join(str(b) for b in option4_blocks) + "\n\n")
        f.write(f"# {len(excluded_ranges)} Azure IP ranges NOT covered by Option 4:\n")
        for r in excluded_ranges:
            f.write(r + "\n")

    print(f"\n\nResults saved to: {args.output}")

if __name__ == "__main__":
    main()
