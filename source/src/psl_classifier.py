"""PSL classifier for IP/domain detection and walkable classification."""

import ipaddress
import logging
import re
from typing import List, Optional, Tuple

import tldextract

logger = logging.getLogger(__name__)

# Default: expand CIDRs up to /20 (4096 IPs max per CIDR)
# Smaller prefix = larger network = more IPs
DEFAULT_MIN_CIDR_PREFIX = 20


class PSLClassifier:
    """Classifier for IP vs domain detection and PSL-based walkable classification."""
    
    def __init__(self):
        # Initialize tldextract with caching
        self.tld_extract = tldextract.TLDExtract(
            cache_dir=None,  # Use default cache location
            fallback_to_snapshot=True
        )
        
        # Precompiled regex patterns for IP detection
        self._ipv4_pattern = re.compile(
            r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        )
        
        # More comprehensive IPv6 pattern
        self._ipv6_pattern = re.compile(
            r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|'  # Full format
            r'^::1$|'  # Localhost
            r'^::$|'  # All zeros
            r'^(?:[0-9a-fA-F]{1,4}:)*::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}$'  # Compressed format
        )
    
    def classify_entry(self, entry: str) -> Tuple[str, bool]:
        """
        Classify an entry as IP or domain and determine if it's walkable.
        
        Args:
            entry: The entry to classify (should be normalized/lowercase)
        
        Returns:
            Tuple of (entry_type, is_walkable)
            entry_type: "ip" or "domain"
            is_walkable: True if domain is registrable domain (eTLD+1), False otherwise
        """
        if self.is_ip_address(entry):
            return "ip", False  # IPs are never walkable in our context
        else:
            is_walkable = self.is_walkable_domain(entry)
            return "domain", is_walkable
    
    def is_ip_address(self, entry: str) -> bool:
        """
        Check if entry is a valid IP address (IPv4 or IPv6).
        
        Args:
            entry: Entry to check
        
        Returns:
            True if valid IP address, False otherwise
        """
        # Quick regex check first (faster than ipaddress module)
        if not (self._ipv4_pattern.match(entry) or self._ipv6_pattern.match(entry)):
            return False
        
        # Validate with ipaddress module for accuracy
        try:
            ipaddress.ip_address(entry)
            return True
        except ValueError:
            return False
    
    def is_cidr_notation(self, entry: str) -> bool:
        """
        Check if entry is a valid CIDR notation (e.g., 192.168.1.0/24).
        
        Args:
            entry: Entry to check
        
        Returns:
            True if valid CIDR notation, False otherwise
        """
        if '/' not in entry:
            return False
        
        try:
            network = ipaddress.ip_network(entry, strict=False)
            return True
        except ValueError:
            return False
    
    def expand_cidr(self, cidr: str, min_prefix: int = DEFAULT_MIN_CIDR_PREFIX) -> List[str]:
        """
        Expand a CIDR notation to individual IP addresses.
        
        Args:
            cidr: CIDR notation (e.g., "192.168.1.0/24")
            min_prefix: Minimum prefix length to expand (default /20 = 4096 IPs max)
                       Larger networks (smaller prefix) will be skipped
        
        Returns:
            List of IP addresses as strings, or empty list if too large/invalid
        """
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            
            # Skip networks larger than min_prefix (too many IPs)
            if network.prefixlen < min_prefix:
                logger.debug(f"Skipping large CIDR {cidr} (prefix /{network.prefixlen} < /{min_prefix})")
                return []
            
            # Expand to individual IPs
            return [str(ip) for ip in network.hosts()]
            
        except ValueError as e:
            logger.warning(f"Invalid CIDR notation '{cidr}': {e}")
            return []
    
    def get_cidr_size(self, cidr: str) -> int:
        """
        Get the number of hosts in a CIDR block.
        
        Args:
            cidr: CIDR notation
        
        Returns:
            Number of usable hosts, or 0 if invalid
        """
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            return network.num_addresses - 2 if network.num_addresses > 2 else network.num_addresses
        except ValueError:
            return 0
    
    def is_valid_domain(self, domain: str) -> bool:
        """
        Validate domain format and length.
        
        Args:
            domain: Domain to validate
        
        Returns:
            True if valid domain format, False otherwise
        """
        # Check length (DNS limit)
        if not domain or len(domain) > 253:
            return False
        
        # Check for invalid characters
        # Valid domain characters: a-z, 0-9, -, .
        if not re.match(r'^[a-z0-9.-]+$', domain):
            return False
        
        # Check label lengths (each part between dots should be <= 63 chars)
        labels = domain.split('.')
        for label in labels:
            if not label or len(label) > 63:
                return False
            # Labels can't start or end with hyphen
            if label.startswith('-') or label.endswith('-'):
                return False
        
        # Must have at least one dot for a valid domain
        if '.' not in domain:
            return False
        
        return True
    
    def get_registrable_domain(self, domain: str) -> Optional[str]:
        """
        Extract the registrable domain (eTLD+1) from a domain.
        
        Args:
            domain: Domain to extract from
        
        Returns:
            Registrable domain or None if extraction fails
        """
        try:
            extracted = self.tld_extract(domain)
            if extracted.domain and extracted.suffix:
                return f"{extracted.domain}.{extracted.suffix}"
            return None
        except Exception as e:
            logger.warning(f"Failed to extract registrable domain from '{domain}': {e}")
            return None
    
    def is_walkable_domain(self, domain: str) -> bool:
        """
        Determine if a domain is "walkable" (i.e., it's a registrable domain).
        
        A walkable domain is one where subdomain matching should be allowed.
        This happens when the domain is exactly the registrable domain (eTLD+1).
        
        Examples:
        - "kortin.click" → walkable (is registrable domain)
        - "foo.kortin.click" → not walkable (is subdomain)
        - "github.io" → walkable (is registrable domain for github.io)
        - "user.github.io" → not walkable (is subdomain)
        
        Args:
            domain: Domain to check
        
        Returns:
            True if domain is walkable (registrable domain), False otherwise
        """
        if not self.is_valid_domain(domain):
            return False
        
        registrable_domain = self.get_registrable_domain(domain)
        if not registrable_domain:
            return False
        
        # Domain is walkable if it equals its registrable domain
        return domain == registrable_domain
    
    def get_parent_domain_for_lookup(self, domain: str) -> Optional[str]:
        """
        Get the parent domain to check for walkable matching.
        
        This is used during lookup to find the registrable domain
        that should be checked against walkable domains.
        
        Args:
            domain: Domain to get parent for
        
        Returns:
            Registrable domain to check, or None if domain is already registrable
        """
        if not self.is_valid_domain(domain):
            return None
        
        registrable_domain = self.get_registrable_domain(domain)
        if not registrable_domain:
            return None
        
        # If domain is already the registrable domain, no parent to check
        if domain == registrable_domain:
            return None
        
        # Return the registrable domain to check for walkable match
        return registrable_domain
    
    def normalize_entry(self, entry: str) -> str:
        """
        Normalize an entry for consistent storage and lookup.
        
        Args:
            entry: Raw entry from feed
        
        Returns:
            Normalized entry (lowercase, stripped)
        """
        return entry.strip().lower()
    
    def is_valid_entry(self, entry: str, max_length: int = 253) -> bool:
        """
        Check if entry is valid for processing.
        
        Args:
            entry: Entry to validate
            max_length: Maximum allowed length
        
        Returns:
            True if entry is valid, False otherwise
        """
        if not entry or len(entry) > max_length:
            return False
        
        # Skip comments and blank lines
        if entry.startswith('#') or not entry.strip():
            return False
        
        normalized = self.normalize_entry(entry)
        
        # Must be valid IP, CIDR, or domain
        return self.is_ip_address(normalized) or self.is_cidr_notation(normalized) or self.is_valid_domain(normalized)


# Global classifier instance
psl_classifier = PSLClassifier()
