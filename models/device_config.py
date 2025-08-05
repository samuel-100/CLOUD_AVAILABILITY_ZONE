"""
Device configuration data models for NAPALM integration

Provides dataclasses for device configuration, credentials, and validation
for spine-leaf datacenter topology with IGP, BGP, VXLAN, EVPN support.
"""

from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List
import ipaddress
import re


@dataclass
class DeviceCredentials:
    """Device authentication credentials with connection parameters"""
    username: str
    password: str
    timeout: int = 30
    optional_args: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate credentials after initialization"""
        if not self.username or not self.password:
            raise ValueError("Username and password are required")
        
        if self.timeout <= 0:
            raise ValueError("Timeout must be positive")


@dataclass
class DeviceConfig:
    """Device configuration model for spine-leaf datacenter topology"""
    name: str
    host: str
    role: str  # 'spine' or 'leaf'
    driver: str  # NAPALM driver type (ios, nxos, etc.)
    credentials: DeviceCredentials
    data_ip: Optional[str] = None
    router_id: Optional[str] = None
    uplinks: Optional[List[str]] = None
    bgp_asn: Optional[int] = None
    vxlan_config: Optional[Dict[str, Any]] = None
    
    def __post_init__(self):
        """Validate device configuration after initialization"""
        self._validate_name()
        self._validate_host()
        self._validate_role()
        self._validate_driver()
        self._validate_ips()
        self._validate_bgp_asn()
    
    def _validate_name(self):
        """Validate device name format"""
        if not self.name:
            raise ValueError("Device name is required")
        
        # Device name should be alphanumeric with hyphens/underscores
        if not re.match(r'^[a-zA-Z0-9_-]+$', self.name):
            raise ValueError("Device name must be alphanumeric with hyphens/underscores only")
    
    def _validate_host(self):
        """Validate host IP address"""
        if not self.host:
            raise ValueError("Host IP address is required")
        
        try:
            ipaddress.ip_address(self.host)
        except ValueError:
            raise ValueError(f"Invalid host IP address: {self.host}")
    
    def _validate_role(self):
        """Validate device role"""
        valid_roles = ['spine', 'leaf']
        if self.role not in valid_roles:
            raise ValueError(f"Role must be one of {valid_roles}, got: {self.role}")
    
    def _validate_driver(self):
        """Validate NAPALM driver type"""
        valid_drivers = ['ios', 'nxos', 'eos', 'junos']
        if self.driver not in valid_drivers:
            raise ValueError(f"Driver must be one of {valid_drivers}, got: {self.driver}")
    
    def _validate_ips(self):
        """Validate IP addresses (data_ip, router_id)"""
        if self.data_ip:
            try:
                ipaddress.ip_address(self.data_ip)
            except ValueError:
                raise ValueError(f"Invalid data plane IP address: {self.data_ip}")
        
        if self.router_id:
            try:
                ipaddress.ip_address(self.router_id)
            except ValueError:
                raise ValueError(f"Invalid router ID: {self.router_id}")
    
    def _validate_bgp_asn(self):
        """Validate BGP ASN if provided"""
        if self.bgp_asn is not None:
            if not isinstance(self.bgp_asn, int) or self.bgp_asn <= 0 or self.bgp_asn > 4294967295:
                raise ValueError("BGP ASN must be a positive integer between 1 and 4294967295")
    
    @property
    def is_spine(self) -> bool:
        """Check if device is a spine switch"""
        return self.role == 'spine'
    
    @property
    def is_leaf(self) -> bool:
        """Check if device is a leaf switch"""
        return self.role == 'leaf'
    
    @property
    def connection_ip(self) -> str:
        """Get the IP address to use for connections (data_ip if available, else host)"""
        return self.data_ip if self.data_ip else self.host
    
    def to_napalm_params(self) -> Dict[str, Any]:
        """Convert to NAPALM connection parameters"""
        return {
            'hostname': self.connection_ip,
            'username': self.credentials.username,
            'password': self.credentials.password,
            'timeout': self.credentials.timeout,
            'optional_args': self.credentials.optional_args
        }


@dataclass
class DeviceFacts:
    """Device operational facts collected via NAPALM"""
    hostname: str
    fqdn: str
    vendor: str
    model: str
    serial_number: str
    os_version: str
    uptime: int
    interface_list: List[str]
    
    def __post_init__(self):
        """Validate device facts"""
        if not self.hostname:
            raise ValueError("Hostname is required")


@dataclass
class InterfaceData:
    """Interface operational data"""
    name: str
    is_enabled: bool
    is_up: bool
    mac_address: str
    mtu: int
    speed: int
    description: str
    last_flapped: float
    
    def __post_init__(self):
        """Validate interface data"""
        if not self.name:
            raise ValueError("Interface name is required")
        
        if self.mtu <= 0:
            raise ValueError("MTU must be positive")
        
        if self.speed < 0:
            raise ValueError("Speed cannot be negative")


def create_device_config(name: str, host: str, role: str, driver: str,
                        username: str, password: str, **kwargs) -> DeviceConfig:
    """
    Factory function to create DeviceConfig with validation
    
    Args:
        name: Device name
        host: Management IP address
        role: Device role (spine/leaf)
        driver: NAPALM driver type
        username: SSH username
        password: SSH password
        **kwargs: Additional configuration parameters
        
    Returns:
        DeviceConfig instance
    """
    credentials = DeviceCredentials(
        username=username,
        password=password,
        timeout=kwargs.get('timeout', 30),
        optional_args=kwargs.get('optional_args', {})
    )
    
    return DeviceConfig(
        name=name,
        host=host,
        role=role,
        driver=driver,
        credentials=credentials,
        data_ip=kwargs.get('data_ip'),
        router_id=kwargs.get('router_id'),
        uplinks=kwargs.get('uplinks'),
        bgp_asn=kwargs.get('bgp_asn'),
        vxlan_config=kwargs.get('vxlan_config')
    )