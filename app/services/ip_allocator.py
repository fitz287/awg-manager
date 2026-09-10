import ipaddress
from typing import List, Optional, Tuple

class IPAllocator:
    @staticmethod
    def get_interface_prefix(interface_address: str) -> str:
        """
        Extracts the first two octets of an IPv4 address string (e.g. '10.12.0.1/16' -> '10.12').
        """
        ip_str = interface_address.split('/')[0].strip()
        parts = ip_str.split('.')
        if len(parts) >= 2:
            return f"{parts[0]}.{parts[1]}"
        return "10.12"

    @staticmethod
    def allocate_user_subnet(existing_indices: List[int], interface_address: str) -> Tuple[int, str]:
        """
        Allocates the next available /24 subnet for a new user on the given interface.
        Example: returns (1, "10.12.1.0/24") for index 1.
        """
        prefix = IPAllocator.get_interface_prefix(interface_address)
        used_set = set(existing_indices)
        
        # Octet 0 is reserved for the server interface itself (e.g. 10.12.0.1)
        for idx in range(1, 255):
            if idx not in used_set:
                subnet_str = f"{prefix}.{idx}.0/24"
                return idx, subnet_str

        raise ValueError("No available subnets left in this interface pool (limit 254 users).")

    @staticmethod
    def allocate_device_ip(user_subnet: str, existing_device_ips: List[str]) -> str:
        """
        Allocates the next available /32 IP address inside the user's /24 subnet.
        Example: For '10.12.1.0/24', allocates '10.12.1.2', then '10.12.1.3', etc.
        (x.x.x.1 is reserved as the gateway/server).
        """
        network = ipaddress.ip_network(user_subnet, strict=False)
        used_ips = {str(ip.split('/')[0].strip()) for ip in existing_device_ips}
        
        # Skip network address (.0) and gateway (.1)
        hosts = list(network.hosts())
        for host in hosts[1:]:  # start from .2 onwards
            host_str = str(host)
            if host_str not in used_ips:
                return host_str

        raise ValueError(f"No available IP addresses left in user subnet {user_subnet} (limit 253 devices).")
