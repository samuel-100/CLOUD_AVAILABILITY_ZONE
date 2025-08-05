#!/usr/bin/env python3
"""
Network Context Engine - Intelligent State Management

Implements intelligent network state tracking, real-time device monitoring,
historical data collection, trend analysis, and proactive network management
for network automation.
"""

import os
import sys
import json
import yaml
import logging
import asyncio
import time
import sqlite3
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import statistics
import pickle
from pathlib import Path
from collections import defaultdict, deque
import concurrent.futures

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

# Import network services
from services.network_status_tool import get_network_status
from services.device_details_tool import get_device_details
from services.network_topology_tool import get_network_topology

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# File paths
CONTEXT_DATA_DIR = '/opt/network-automation/CLOUD_AVAILABILITY_ZONE/logs/context_engine'
HISTORICAL_DB = '/opt/network-automation/CLOUD_AVAILABILITY_ZONE/logs/context_engine/network_history.db'
STATE_CACHE_DIR = '/opt/network-automation/CLOUD_AVAILABILITY_ZONE/logs/context_engine/state_cache'

# Device-specific command mappings
DEVICE_COMMANDS = {
    'nxos': {  # SPINE devices
        'cpu': 'show system resources',
        'memory': 'show system resources',
        'interfaces': 'show interface brief',
        'ospf': 'show ip ospf neighbors',
        'bgp': 'show bgp summary',
        'vxlan': 'show nve peers',
        'version': 'show version',
        'environment': 'show environment temperature'
    },
    'ios': {   # LEAF devices
        'cpu': 'show processes cpu',
        'memory': 'show memory summary',
        'interfaces': 'show ip interface brief',
        'ospf': 'show ip ospf neighbor',
        'bgp': 'show ip bgp summary',
        'vxlan': None,  # Not typically available in IOS
        'version': 'show version',
        'environment': 'show environment'
    }
}

# Ensure directories exist
for dir_path in [CONTEXT_DATA_DIR, STATE_CACHE_DIR]:
    Path(dir_path).mkdir(parents=True, exist_ok=True)

class DeviceState(Enum):
    """Device operational states"""
    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    UNREACHABLE = "unreachable"
    UNKNOWN = "unknown"

class MetricTrend(Enum):
    """Metric trend directions"""
    STABLE = "stable"
    INCREASING = "increasing"
    DECREASING = "decreasing"
    VOLATILE = "volatile"

class AlertSeverity(Enum):
    """Alert severity levels"""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    EMERGENCY = "emergency"

@dataclass
class DeviceMetrics:
    """Device performance metrics"""
    device_name: str
    timestamp: str
    cpu_utilization: float
    memory_utilization: float
    interface_utilization: Dict[str, float]
    packet_loss: float
    latency: float
    uptime: int
    error_count: int
    temperature: Optional[float] = None
    power_consumption: Optional[float] = None

@dataclass
class NetworkSnapshot:
    """Point-in-time network state snapshot"""
    snapshot_id: str
    timestamp: str
    device_states: Dict[str, DeviceState]
    device_metrics: Dict[str, DeviceMetrics]
    topology_changes: List[str]
    protocol_states: Dict[str, Dict[str, Any]]
    active_alarms: List[str]
    performance_summary: Dict[str, float]

@dataclass
class TrendAnalysis:
    """Trend analysis for network metrics"""
    metric_name: str
    device_name: str
    trend_direction: MetricTrend
    trend_strength: float  # 0.0 to 1.0
    prediction: float
    confidence: float
    analysis_period: str
    data_points: int
    last_updated: str

@dataclass
class NetworkAlert:
    """Network monitoring alert"""
    alert_id: str
    severity: AlertSeverity
    source_device: str
    alert_type: str
    description: str
    threshold_value: float
    current_value: float
    first_occurrence: str
    last_occurrence: str
    occurrence_count: int
    acknowledged: bool = False
    resolved: bool = False
    resolution_notes: str = ""

@dataclass
class StateChange:
    """Network state change record"""
    change_id: str
    timestamp: str
    device_name: str
    change_type: str  # config, state, metric, topology
    before_value: Any
    after_value: Any
    impact_score: float  # 0.0 to 1.0
    related_changes: List[str]
    correlation_id: Optional[str] = None

class NetworkContextEngine:
    """Intelligent network state management and monitoring"""
    
    def __init__(self, monitoring_interval: int = 60):
        self.monitoring_interval = monitoring_interval
        self.current_state = {}
        self.historical_snapshots = deque(maxlen=1000)  # Keep last 1000 snapshots
        self.trend_cache = {}
        self.active_alerts = {}
        self.state_changes = deque(maxlen=5000)  # Keep last 5000 changes
        self.monitoring_thread = None
        self.running = False
        
        # Initialize database
        self._init_database()
        
        # Load cached state
        self._load_cached_state()
        
        # Performance baselines
        self.performance_baselines = self._calculate_baselines()
        
        logger.info("NetworkContextEngine initialized")
    
    def _init_database(self):
        """Initialize SQLite database for historical data"""
        try:
            with sqlite3.connect(HISTORICAL_DB) as conn:
                cursor = conn.cursor()
                
                # Create tables
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS snapshots (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        snapshot_id TEXT UNIQUE,
                        timestamp TEXT,
                        data TEXT
                    )
                ''')
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS device_metrics (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        device_name TEXT,
                        timestamp TEXT,
                        metric_name TEXT,
                        metric_value REAL
                    )
                ''')
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS state_changes (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        change_id TEXT UNIQUE,
                        timestamp TEXT,
                        device_name TEXT,
                        change_type TEXT,
                        data TEXT
                    )
                ''')
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        alert_id TEXT UNIQUE,
                        timestamp TEXT,
                        severity TEXT,
                        source_device TEXT,
                        alert_type TEXT,
                        description TEXT,
                        resolved INTEGER DEFAULT 0
                    )
                ''')
                
                # Create indices for performance
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_snapshots_timestamp ON snapshots(timestamp)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_metrics_device_timestamp ON device_metrics(device_name, timestamp)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_changes_timestamp ON state_changes(timestamp)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)')
                
                conn.commit()
                logger.info("Database initialized successfully")
                
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
    
    def _load_cached_state(self):
        """Load cached network state from disk"""
        try:
            cache_file = Path(STATE_CACHE_DIR) / "current_state.pickle"
            if cache_file.exists():
                with open(cache_file, 'rb') as f:
                    cached_data = pickle.load(f)
                    self.current_state = cached_data.get('current_state', {})
                    self.trend_cache = cached_data.get('trend_cache', {})
                    self.performance_baselines = cached_data.get('performance_baselines', {})
                logger.info("Cached state loaded successfully")
        except Exception as e:
            logger.warning(f"Could not load cached state: {e}")
    
    def _save_cached_state(self):
        """Save current state to disk cache"""
        try:
            cache_file = Path(STATE_CACHE_DIR) / "current_state.pickle"
            cache_data = {
                'current_state': self.current_state,
                'trend_cache': self.trend_cache,
                'performance_baselines': self.performance_baselines,
                'last_updated': datetime.now().isoformat()
            }
            with open(cache_file, 'wb') as f:
                pickle.dump(cache_data, f)
        except Exception as e:
            logger.error(f"Failed to save cached state: {e}")
    
    def _calculate_baselines(self) -> Dict[str, Dict[str, float]]:
        """Calculate performance baselines from historical data"""
        baselines = defaultdict(lambda: defaultdict(float))
        
        try:
            with sqlite3.connect(HISTORICAL_DB) as conn:
                cursor = conn.cursor()
                
                # Get last 7 days of metrics for baseline calculation
                week_ago = (datetime.now() - timedelta(days=7)).isoformat()
                
                cursor.execute('''
                    SELECT device_name, metric_name, AVG(metric_value), COUNT(*)
                    FROM device_metrics 
                    WHERE timestamp > ?
                    GROUP BY device_name, metric_name
                    HAVING COUNT(*) >= 10
                ''', (week_ago,))
                
                for device_name, metric_name, avg_value, count in cursor.fetchall():
                    baselines[device_name][metric_name] = avg_value
                
                logger.info(f"Calculated baselines for {len(baselines)} devices")
                
        except Exception as e:
            logger.warning(f"Could not calculate baselines: {e}")
        
        return dict(baselines)
    
    def collect_network_snapshot(self) -> NetworkSnapshot:
        """Collect comprehensive network state snapshot"""
        snapshot_id = f"SNAP-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        timestamp = datetime.now().isoformat()
        
        try:
            # Get network status
            network_status = get_network_status()
            
            # Get topology
            topology = get_network_topology()
            
            # Collect device states and metrics
            device_states = {}
            device_metrics = {}
            protocol_states = {}
            
            if 'devices' in network_status:
                for device_info in network_status['devices']:
                    device_name = device_info['name']
                    
                    # Determine device state
                    if device_info.get('status') == 'reachable':
                        device_states[device_name] = DeviceState.HEALTHY
                        
                        # Get detailed metrics
                        try:
                            device_details = get_device_details(device_name)
                            metrics = self._extract_device_metrics(device_name, device_details)
                            device_metrics[device_name] = metrics
                            
                            # Extract protocol states
                            protocol_states[device_name] = self._extract_protocol_states(device_details)
                            
                        except Exception as e:
                            logger.warning(f"Failed to get details for {device_name}: {e}")
                            device_states[device_name] = DeviceState.WARNING
                    else:
                        device_states[device_name] = DeviceState.UNREACHABLE
            
            # Calculate performance summary
            performance_summary = self._calculate_performance_summary(device_metrics)
            
            # Create snapshot
            snapshot = NetworkSnapshot(
                snapshot_id=snapshot_id,
                timestamp=timestamp,
                device_states=device_states,
                device_metrics=device_metrics,
                topology_changes=[],  # TODO: Implement topology change detection
                protocol_states=protocol_states,
                active_alarms=[],  # TODO: Implement alarm collection
                performance_summary=performance_summary
            )
            
            # Store snapshot
            self._store_snapshot(snapshot)
            
            # Update current state
            self.current_state = {
                'last_snapshot': snapshot,
                'last_updated': timestamp
            }
            
            return snapshot
            
        except Exception as e:
            logger.error(f"Failed to collect network snapshot: {e}")
            # Return empty snapshot
            return NetworkSnapshot(
                snapshot_id=snapshot_id,
                timestamp=timestamp,
                device_states={},
                device_metrics={},
                topology_changes=[],
                protocol_states={},
                active_alarms=[],
                performance_summary={}
            )
    
    def _extract_device_metrics(self, device_name: str, device_details: Dict) -> DeviceMetrics:
        """Extract performance metrics from device details"""
        
        # Determine device type for command parsing
        is_spine = 'SPINE' in device_name.upper()
        is_leaf = 'LEAF' in device_name.upper()
        
        # Parse CPU utilization based on device type
        cpu_util = 0.0
        cpu_info = device_details.get('cpu_info', '')
        
        if is_spine:  # NX-OS format
            # NX-OS CPU parsing from 'show system resources'
            # Format: "CPU states: 1.0% user, 0.0% kernel, 99.0% idle"
            if cpu_info and ('CPU states' in cpu_info or 'cpu' in cpu_info.lower()):
                import re
                # Look for user CPU percentage in "CPU states" line
                cpu_match = re.search(r'(\d+\.?\d*)%\s+user', cpu_info, re.IGNORECASE)
                if cpu_match:
                    cpu_util = float(cpu_match.group(1))
                else:
                    # Fallback: look for any percentage
                    cpu_match = re.search(r'(\d+\.?\d*)%', cpu_info)
                    if cpu_match:
                        cpu_util = float(cpu_match.group(1))
        elif is_leaf:  # IOS format
            # IOS CPU parsing from 'show processes cpu'
            # Format: "CPU utilization for five seconds: 1%/0%; one minute: 1%; five minutes: 1%"
            if cpu_info and 'CPU utilization' in cpu_info:
                import re
                # Look for "five seconds" percentage
                cpu_match = re.search(r'five seconds:\s*(\d+)%', cpu_info, re.IGNORECASE)
                if cpu_match:
                    cpu_util = float(cpu_match.group(1))
                else:
                    # Fallback: look for first percentage
                    cpu_match = re.search(r'(\d+)%', cpu_info)
                    if cpu_match:
                        cpu_util = float(cpu_match.group(1))
        
        # Parse memory utilization based on device type
        memory_util = 0.0
        memory_info = device_details.get('memory_info', '')
        
        if is_spine:  # NX-OS memory format
            # NX-OS: "show system resources"
            # Format: "Memory usage: 4194304K total, 2097152K used, 2097152K free"
            if memory_info and ('Memory usage' in memory_info or 'memory' in memory_info.lower()):
                import re
                # Look for "Memory usage: XK total, YK used" pattern
                memory_match = re.search(r'Memory usage:\s*(\d+)K\s+total,\s*(\d+)K\s+used', memory_info, re.IGNORECASE)
                if memory_match:
                    total_mem = float(memory_match.group(1))
                    used_mem = float(memory_match.group(2))
                    if total_mem > 0:
                        memory_util = (used_mem / total_mem) * 100
                else:
                    # Look for percentage directly
                    percent_match = re.search(r'(\d+\.?\d*)%', memory_info)
                    if percent_match:
                        memory_util = float(percent_match.group(1))
        elif is_leaf:  # IOS memory format
            # IOS: "show memory summary" or "show memory"
            # Various formats possible, try to parse intelligently
            if memory_info and ('memory' in memory_info.lower() or 'processor' in memory_info.lower()):
                import re
                # Try to find percentage first
                percent_match = re.search(r'(\d+\.?\d*)%', memory_info)
                if percent_match:
                    memory_util = float(percent_match.group(1))
                else:
                    # Try to parse table format: "Processor XXXXX YYYYY ZZZZZ"
                    table_match = re.search(r'Processor\s+(\d+)\s+(\d+)\s+(\d+)', memory_info)
                    if table_match:
                        total_mem = float(table_match.group(1))
                        used_mem = float(table_match.group(2))
                        if total_mem > 0:
                            memory_util = (used_mem / total_mem) * 100
                    else:
                        # Default for IOS if no specific format found
                        memory_util = 50.0
        
        # Parse interface utilization based on device type
        interface_util = {}
        interfaces = device_details.get('interfaces', [])
        
        if is_spine:  # NX-OS interface format
            # NX-OS: "show interface brief" output
            # Different format and column headers than IOS
            for interface in interfaces:
                if isinstance(interface, dict):
                    intf_name = interface.get('interface', '')
                    # NX-OS specific interface utilization parsing
                    # Could parse from interface counters if available
                    status = interface.get('status', '').lower()
                    protocol = interface.get('protocol', '').lower()
                    
                    # Basic utilization placeholder - would need detailed interface stats
                    if 'up' in status and 'up' in protocol:
                        interface_util[intf_name] = 5.0  # Low utilization for active interfaces
                    else:
                        interface_util[intf_name] = 0.0
        elif is_leaf:  # IOS interface format
            # IOS: "show ip interface brief" output
            # Standard IOS format
            for interface in interfaces:
                if isinstance(interface, dict):
                    intf_name = interface.get('interface', '')
                    # IOS specific interface utilization parsing
                    status = interface.get('status', '').lower()
                    protocol = interface.get('protocol', '').lower()
                    
                    # Basic utilization placeholder - would need detailed interface stats
                    if 'up' in status and 'up' in protocol:
                        interface_util[intf_name] = 3.0  # Low utilization for active interfaces
                    else:
                        interface_util[intf_name] = 0.0
        
        # Calculate uptime from device info based on device type
        uptime = 0
        version_info = device_details.get('version_info', '')
        
        if is_spine:  # NX-OS uptime format
            # NX-OS: "show version" - "System uptime: 1 day(s), 2 hour(s), 34 minute(s), 56 second(s)"
            # Also: "Kernel uptime is X days, Y hours, Z minutes"
            if 'uptime' in version_info.lower():
                import re
                uptime_seconds = 0
                
                # Parse NX-OS format with parentheses
                days_match = re.search(r'(\d+)\s+day\(s\)', version_info, re.IGNORECASE)
                if not days_match:
                    # Try without parentheses
                    days_match = re.search(r'(\d+)\s+days?', version_info, re.IGNORECASE)
                if days_match:
                    uptime_seconds += int(days_match.group(1)) * 86400
                
                hours_match = re.search(r'(\d+)\s+hour\(s\)', version_info, re.IGNORECASE)
                if not hours_match:
                    hours_match = re.search(r'(\d+)\s+hours?', version_info, re.IGNORECASE)
                if hours_match:
                    uptime_seconds += int(hours_match.group(1)) * 3600
                
                minutes_match = re.search(r'(\d+)\s+minute\(s\)', version_info, re.IGNORECASE)
                if not minutes_match:
                    minutes_match = re.search(r'(\d+)\s+minutes?', version_info, re.IGNORECASE)
                if minutes_match:
                    uptime_seconds += int(minutes_match.group(1)) * 60
                
                uptime = uptime_seconds if uptime_seconds > 0 else 86400
        elif is_leaf:  # IOS uptime format
            # IOS: "show version" - "Router uptime is 1 day, 2 hours, 34 minutes"
            # Also: "System uptime: 1 day, 2 hours, 34 minutes"
            if 'uptime' in version_info.lower():
                import re
                uptime_seconds = 0
                
                # Parse standard IOS format
                days_match = re.search(r'(\d+)\s+days?', version_info, re.IGNORECASE)
                if days_match:
                    uptime_seconds += int(days_match.group(1)) * 86400
                
                hours_match = re.search(r'(\d+)\s+hours?', version_info, re.IGNORECASE)
                if hours_match:
                    uptime_seconds += int(hours_match.group(1)) * 3600
                
                minutes_match = re.search(r'(\d+)\s+minutes?', version_info, re.IGNORECASE)
                if minutes_match:
                    uptime_seconds += int(minutes_match.group(1)) * 60
                
                uptime = uptime_seconds if uptime_seconds > 0 else 86400
        else:
            # Default uptime for unknown device types
            uptime = 86400
        
        return DeviceMetrics(
            device_name=device_name,
            timestamp=datetime.now().isoformat(),
            cpu_utilization=cpu_util,
            memory_utilization=memory_util,
            interface_utilization=interface_util,
            packet_loss=0.0,  # Would need SNMP or enhanced monitoring
            latency=0.0,      # Would need network testing
            uptime=uptime,
            error_count=0     # Would need log analysis
        )
    
    def _extract_protocol_states(self, device_details: Dict) -> Dict[str, Any]:
        """Extract routing protocol states based on device type"""
        protocol_states = {}
        
        # Determine device type
        device_name = device_details.get('device_name', '')
        is_spine = 'SPINE' in device_name.upper()
        is_leaf = 'LEAF' in device_name.upper()
        
        # OSPF state extraction
        ospf_neighbors = device_details.get('ospf_neighbors', [])
        if ospf_neighbors:
            if is_spine:  # NX-OS OSPF
                # NX-OS: "show ip ospf neighbors" 
                # States: FULL, FULL/DR, FULL/BDR, FULL/DROTHER, INIT, 2WAY, etc.
                ospf_up = len([n for n in ospf_neighbors if isinstance(n, dict) and 
                              (n.get('state', '').upper().startswith('FULL'))])
            elif is_leaf:  # IOS OSPF
                # IOS: "show ip ospf neighbor"
                # States: FULL, FULL/DR, FULL/BDR, FULL/DROTHER, INIT, 2WAY, etc.
                ospf_up = len([n for n in ospf_neighbors if isinstance(n, dict) and 
                              (n.get('state', '').upper().startswith('FULL'))])
            else:
                # Generic OSPF parsing
                ospf_up = len([n for n in ospf_neighbors if isinstance(n, dict) and 
                              n.get('state', '').upper() == 'FULL'])
            
            ospf_total = len(ospf_neighbors)
            protocol_states['ospf'] = {
                'neighbors_up': ospf_up,
                'neighbors_total': ospf_total,
                'state': 'healthy' if ospf_up == ospf_total else 'degraded',
                'device_type': 'nxos' if is_spine else 'ios' if is_leaf else 'unknown',
                'command_used': DEVICE_COMMANDS.get('nxos' if is_spine else 'ios', {}).get('ospf', 'unknown')
            }
        
        # BGP state extraction
        bgp_summary = device_details.get('bgp_summary', {})
        if bgp_summary:
            if is_spine:  # NX-OS BGP
                # NX-OS: "show bgp summary" or "show ip bgp summary"
                # More advanced BGP features typically available
                bgp_state = 'active'
                # Could parse established sessions count, peer states, etc.
            elif is_leaf:  # IOS BGP
                # IOS: "show ip bgp summary"
                # Standard BGP implementation
                bgp_state = 'active'
                # Could parse neighbor states, prefixes received, etc.
            else:
                bgp_state = 'active'
            
            protocol_states['bgp'] = {
                'state': bgp_state,
                'device_type': 'nxos' if is_spine else 'ios' if is_leaf else 'unknown',
                'command_used': DEVICE_COMMANDS.get('nxos' if is_spine else 'ios', {}).get('bgp', 'unknown')
            }
        
        # VXLAN state (primarily for SPINE devices with NX-OS)
        if is_spine:
            vxlan_info = device_details.get('vxlan_info', '')
            if vxlan_info:
                # NX-OS: "show nve peers" or "show vxlan"
                # VXLAN is primarily an NX-OS feature in datacenter deployments
                protocol_states['vxlan'] = {
                    'state': 'active' if vxlan_info else 'inactive',
                    'device_type': 'nxos',
                    'command_used': DEVICE_COMMANDS['nxos']['vxlan']
                }
        elif is_leaf:
            # Most IOS devices don't support VXLAN, but note the absence
            protocol_states['vxlan'] = {
                'state': 'not_supported',
                'device_type': 'ios',
                'command_used': 'N/A - VXLAN not typically supported in IOS'
            }
        
        return protocol_states
    
    def _calculate_performance_summary(self, device_metrics: Dict[str, DeviceMetrics]) -> Dict[str, float]:
        """Calculate network-wide performance summary"""
        if not device_metrics:
            return {}
        
        cpu_values = [m.cpu_utilization for m in device_metrics.values()]
        memory_values = [m.memory_utilization for m in device_metrics.values()]
        
        return {
            'avg_cpu_utilization': statistics.mean(cpu_values) if cpu_values else 0.0,
            'max_cpu_utilization': max(cpu_values) if cpu_values else 0.0,
            'avg_memory_utilization': statistics.mean(memory_values) if memory_values else 0.0,
            'max_memory_utilization': max(memory_values) if memory_values else 0.0,
            'device_count': len(device_metrics),
            'healthy_devices': len([m for m in device_metrics.values() if m.cpu_utilization < 80])
        }
    
    def _store_snapshot(self, snapshot: NetworkSnapshot):
        """Store snapshot in database and memory"""
        try:
            # Add to memory cache
            self.historical_snapshots.append(snapshot)
            
            # Store in database
            with sqlite3.connect(HISTORICAL_DB) as conn:
                cursor = conn.cursor()
                
                # Store snapshot
                cursor.execute('''
                    INSERT OR REPLACE INTO snapshots (snapshot_id, timestamp, data)
                    VALUES (?, ?, ?)
                ''', (snapshot.snapshot_id, snapshot.timestamp, json.dumps(asdict(snapshot), default=str)))
                
                # Store individual metrics
                for device_name, metrics in snapshot.device_metrics.items():
                    metrics_dict = asdict(metrics)
                    for metric_name, value in metrics_dict.items():
                        if isinstance(value, (int, float)) and metric_name != 'timestamp':
                            cursor.execute('''
                                INSERT INTO device_metrics (device_name, timestamp, metric_name, metric_value)
                                VALUES (?, ?, ?, ?)
                            ''', (device_name, snapshot.timestamp, metric_name, value))
                
                conn.commit()
                
        except Exception as e:
            logger.error(f"Failed to store snapshot: {e}")
    
    def analyze_trends(self, device_name: str = None, metric_name: str = None, 
                      hours: int = 24) -> List[TrendAnalysis]:
        """Analyze trends in network metrics"""
        trends = []
        
        try:
            with sqlite3.connect(HISTORICAL_DB) as conn:
                cursor = conn.cursor()
                
                # Build query
                since_time = (datetime.now() - timedelta(hours=hours)).isoformat()
                
                if device_name and metric_name:
                    query = '''
                        SELECT device_name, metric_name, timestamp, metric_value
                        FROM device_metrics 
                        WHERE device_name = ? AND metric_name = ? AND timestamp > ?
                        ORDER BY timestamp
                    '''
                    params = (device_name, metric_name, since_time)
                elif device_name:
                    query = '''
                        SELECT device_name, metric_name, timestamp, metric_value
                        FROM device_metrics 
                        WHERE device_name = ? AND timestamp > ?
                        ORDER BY device_name, metric_name, timestamp
                    '''
                    params = (device_name, since_time)
                else:
                    query = '''
                        SELECT device_name, metric_name, timestamp, metric_value
                        FROM device_metrics 
                        WHERE timestamp > ?
                        ORDER BY device_name, metric_name, timestamp
                    '''
                    params = (since_time,)
                
                cursor.execute(query, params)
                results = cursor.fetchall()
                
                # Group by device and metric
                grouped_data = defaultdict(list)
                for dev_name, met_name, timestamp, value in results:
                    grouped_data[(dev_name, met_name)].append((timestamp, value))
                
                # Analyze trends for each metric
                for (dev_name, met_name), data_points in grouped_data.items():
                    if len(data_points) >= 5:  # Minimum points for trend analysis
                        trend = self._calculate_trend(dev_name, met_name, data_points, hours)
                        if trend:
                            trends.append(trend)
                            
                            # Cache trend
                            cache_key = f"{dev_name}_{met_name}"
                            self.trend_cache[cache_key] = trend
                
        except Exception as e:
            logger.error(f"Failed to analyze trends: {e}")
        
        return trends
    
    def _calculate_trend(self, device_name: str, metric_name: str, 
                        data_points: List[Tuple[str, float]], hours: int) -> Optional[TrendAnalysis]:
        """Calculate trend for a specific metric"""
        try:
            if len(data_points) < 5:
                return None
            
            # Convert to numerical values for analysis
            values = [point[1] for point in data_points]
            n = len(values)
            
            # Calculate linear regression slope
            x_values = list(range(n))
            x_mean = statistics.mean(x_values)
            y_mean = statistics.mean(values)
            
            numerator = sum((x - x_mean) * (y - y_mean) for x, y in zip(x_values, values))
            denominator = sum((x - x_mean) ** 2 for x in x_values)
            
            if denominator == 0:
                slope = 0
            else:
                slope = numerator / denominator
            
            # Determine trend direction
            if abs(slope) < 0.001:  # Very small slope = stable
                trend_direction = MetricTrend.STABLE
                trend_strength = 0.0
            elif slope > 0:
                trend_direction = MetricTrend.INCREASING
                trend_strength = min(abs(slope) * 10, 1.0)  # Normalize to 0-1
            else:
                trend_direction = MetricTrend.DECREASING  
                trend_strength = min(abs(slope) * 10, 1.0)
            
            # Calculate volatility
            if len(values) > 2:
                value_changes = [abs(values[i] - values[i-1]) for i in range(1, len(values))]
                volatility = statistics.mean(value_changes) if value_changes else 0
                if volatility > statistics.mean(values) * 0.1:  # High volatility threshold
                    trend_direction = MetricTrend.VOLATILE
            
            # Simple prediction (next value based on trend)
            prediction = values[-1] + slope
            
            # Confidence based on data consistency
            confidence = max(0.3, 1.0 - (statistics.stdev(values) / max(y_mean, 1)))
            
            return TrendAnalysis(
                metric_name=metric_name,
                device_name=device_name,
                trend_direction=trend_direction,
                trend_strength=trend_strength,
                prediction=prediction,
                confidence=confidence,
                analysis_period=f"{hours} hours",
                data_points=len(data_points),
                last_updated=datetime.now().isoformat()
            )
            
        except Exception as e:
            logger.error(f"Failed to calculate trend for {device_name}/{metric_name}: {e}")
            return None
    
    def detect_anomalies(self, threshold_multiplier: float = 2.0) -> List[NetworkAlert]:
        """Detect anomalies in current metrics compared to baselines"""
        alerts = []
        
        try:
            current_snapshot = self.current_state.get('last_snapshot')
            if not current_snapshot or not isinstance(current_snapshot, NetworkSnapshot):
                return alerts
            
            for device_name, metrics in current_snapshot.device_metrics.items():
                device_baselines = self.performance_baselines.get(device_name, {})
                
                if not device_baselines:
                    continue
                
                # Check CPU utilization
                if 'cpu_utilization' in device_baselines:
                    baseline_cpu = device_baselines['cpu_utilization']
                    current_cpu = metrics.cpu_utilization
                    
                    if current_cpu > baseline_cpu * threshold_multiplier:
                        alert = NetworkAlert(
                            alert_id=f"ANOM-{device_name}-CPU-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                            severity=AlertSeverity.WARNING if current_cpu < 85 else AlertSeverity.CRITICAL,
                            source_device=device_name,
                            alert_type="cpu_anomaly",
                            description=f"CPU utilization anomaly detected on {device_name}",
                            threshold_value=baseline_cpu * threshold_multiplier,
                            current_value=current_cpu,
                            first_occurrence=datetime.now().isoformat(),
                            last_occurrence=datetime.now().isoformat(),
                            occurrence_count=1
                        )
                        alerts.append(alert)
                
                # Check memory utilization
                if 'memory_utilization' in device_baselines:
                    baseline_memory = device_baselines['memory_utilization']
                    current_memory = metrics.memory_utilization
                    
                    if current_memory > baseline_memory * threshold_multiplier:
                        alert = NetworkAlert(
                            alert_id=f"ANOM-{device_name}-MEM-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                            severity=AlertSeverity.WARNING if current_memory < 90 else AlertSeverity.CRITICAL,
                            source_device=device_name,
                            alert_type="memory_anomaly",
                            description=f"Memory utilization anomaly detected on {device_name}",
                            threshold_value=baseline_memory * threshold_multiplier,
                            current_value=current_memory,
                            first_occurrence=datetime.now().isoformat(),
                            last_occurrence=datetime.now().isoformat(),
                            occurrence_count=1
                        )
                        alerts.append(alert)
            
            # Store alerts
            for alert in alerts:
                self.active_alerts[alert.alert_id] = alert
                self._store_alert(alert)
            
        except Exception as e:
            logger.error(f"Failed to detect anomalies: {e}")
        
        return alerts
    
    def _store_alert(self, alert: NetworkAlert):
        """Store alert in database"""
        try:
            with sqlite3.connect(HISTORICAL_DB) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT OR REPLACE INTO alerts 
                    (alert_id, timestamp, severity, source_device, alert_type, description, resolved)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    alert.alert_id, alert.first_occurrence, alert.severity.value,
                    alert.source_device, alert.alert_type, alert.description,
                    1 if alert.resolved else 0
                ))
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to store alert: {e}")
    
    def start_monitoring(self):
        """Start continuous network monitoring"""
        if self.running:
            logger.warning("Monitoring already running")
            return
        
        self.running = True
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitoring_thread.start()
        logger.info(f"Network monitoring started (interval: {self.monitoring_interval}s)")
    
    def stop_monitoring(self):
        """Stop continuous network monitoring"""
        self.running = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
        logger.info("Network monitoring stopped")
    
    def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                # Collect snapshot
                snapshot = self.collect_network_snapshot()
                
                # Analyze trends every 5 snapshots
                if len(self.historical_snapshots) % 5 == 0:
                    self.analyze_trends(hours=6)  # Analyze last 6 hours
                
                # Detect anomalies
                self.detect_anomalies()
                
                # Save cached state
                self._save_cached_state()
                
                # Sleep until next collection
                time.sleep(self.monitoring_interval)
                
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(30)  # Wait 30 seconds before retrying

# MCP Tool Functions
def get_network_context() -> Dict[str, Any]:
    """
    Get comprehensive network context and current state
    
    Returns:
        Dict containing current network context and state information
    """
    try:
        engine = NetworkContextEngine()
        
        # Get current snapshot
        current_snapshot = engine.collect_network_snapshot()
        
        # Get recent trends
        trends = engine.analyze_trends(hours=24)
        
        # Detect anomalies
        anomalies = engine.detect_anomalies()
        
        # Get historical summary
        historical_count = len(engine.historical_snapshots)
        
        # Convert enums to strings for JSON serialization
        def convert_enums(obj):
            if isinstance(obj, dict):
                return {k: convert_enums(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_enums(item) for item in obj]
            elif isinstance(obj, (DeviceState, MetricTrend, AlertSeverity)):
                return obj.value
            else:
                return obj
        
        result = {
            'success': True,
            'network_context': {
                'current_snapshot': convert_enums(asdict(current_snapshot)),
                'trend_analysis': convert_enums([asdict(trend) for trend in trends]),
                'anomaly_alerts': convert_enums([asdict(alert) for alert in anomalies]),
                'historical_snapshots_count': historical_count,
                'monitoring_active': engine.running,
                'last_updated': datetime.now().isoformat()
            },
            'message': f"Network context collected - {len(current_snapshot.device_states)} devices monitored"
        }
        
        return result
        
    except Exception as e:
        logger.error(f"MCP get_network_context failed: {e}")
        return {
            'success': False,
            'error': str(e),
            'message': f"Failed to get network context: {str(e)}"
        }

def start_network_monitoring(monitoring_interval: int = 60) -> Dict[str, Any]:
    """
    Start continuous network monitoring
    
    Args:
        monitoring_interval: Monitoring interval in seconds
        
    Returns:
        Dict containing monitoring start result
    """
    try:
        engine = NetworkContextEngine(monitoring_interval)
        engine.start_monitoring()
        
        return {
            'success': True,
            'monitoring': {
                'status': 'started',
                'interval_seconds': monitoring_interval,
                'started_at': datetime.now().isoformat()
            },
            'message': f"Network monitoring started with {monitoring_interval}s interval"
        }
        
    except Exception as e:
        logger.error(f"MCP start_network_monitoring failed: {e}")
        return {
            'success': False,
            'error': str(e),
            'message': f"Failed to start network monitoring: {str(e)}"
        }

def get_network_trends(device_name: str = "", metric_name: str = "", hours: int = 24) -> Dict[str, Any]:
    """
    Get network performance trends and analysis
    
    Args:
        device_name: Specific device to analyze (optional)
        metric_name: Specific metric to analyze (optional)
        hours: Analysis time window in hours
        
    Returns:
        Dict containing trend analysis results
    """
    try:
        engine = NetworkContextEngine()
        
        # Analyze trends
        trends = engine.analyze_trends(
            device_name=device_name if device_name else None,
            metric_name=metric_name if metric_name else None,
            hours=hours
        )
        
        # Convert enums to strings
        def convert_enums(obj):
            if isinstance(obj, dict):
                return {k: convert_enums(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_enums(item) for item in obj]
            elif isinstance(obj, MetricTrend):
                return obj.value
            else:
                return obj
        
        return {
            'success': True,
            'trends': {
                'analysis_results': convert_enums([asdict(trend) for trend in trends]),
                'analysis_period': f"{hours} hours",
                'device_filter': device_name if device_name else "all devices",
                'metric_filter': metric_name if metric_name else "all metrics",
                'trends_count': len(trends)
            },
            'message': f"Analyzed {len(trends)} trends over {hours} hours"
        }
        
    except Exception as e:
        logger.error(f"MCP get_network_trends failed: {e}")
        return {
            'success': False,
            'error': str(e),
            'message': f"Failed to get network trends: {str(e)}"
        }

if __name__ == "__main__":
    # Test the network context engine
    engine = NetworkContextEngine(monitoring_interval=30)
    
    # Collect initial snapshot
    snapshot = engine.collect_network_snapshot()
    print(f"Snapshot collected: {snapshot.snapshot_id}")
    print(f"Devices monitored: {len(snapshot.device_states)}")
    
    # Test trend analysis
    trends = engine.analyze_trends(hours=1)
    print(f"Trends analyzed: {len(trends)}")
    
    # Test anomaly detection
    anomalies = engine.detect_anomalies()
    print(f"Anomalies detected: {len(anomalies)}")
    
    print("NetworkContextEngine test completed")
