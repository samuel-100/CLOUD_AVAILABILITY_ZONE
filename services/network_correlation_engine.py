#!/usr/bin/env python3
"""
Network Correlation and Analysis Engine

Implements change correlation, impact analysis, pattern recognition,
and performance optimization recommendations for proactive network management.
"""

import os
import sys
import json
import yaml
import logging
import sqlite3
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, asdict
from enum import Enum
import statistics
import pickle
from pathlib import Path
from collections import defaultdict, deque
import hashlib
import re

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

# Import network services and context engine
from services.network_context_engine import (
    NetworkContextEngine, StateChange, NetworkAlert, DeviceState, 
    MetricTrend, AlertSeverity, HISTORICAL_DB
)

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ChangeImpact(Enum):
    """Change impact severity levels"""
    MINIMAL = "minimal"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class PatternType(Enum):
    """Pattern recognition types"""
    CYCLIC = "cyclic"           # Recurring patterns
    DEGRADATION = "degradation" # Performance degradation
    ESCALATION = "escalation"   # Issue escalation
    CORRELATION = "correlation" # Event correlation
    ANOMALY = "anomaly"         # Anomalous behavior

class ChangeCategory(Enum):
    """Categories of network changes"""
    CONFIGURATION = "configuration"
    TOPOLOGY = "topology"
    PROTOCOL = "protocol"
    PERFORMANCE = "performance"
    SECURITY = "security"
    CAPACITY = "capacity"

@dataclass
class ChangeCorrelation:
    """Change correlation analysis result"""
    correlation_id: str
    primary_change: StateChange
    related_changes: List[StateChange]
    correlation_strength: float  # 0.0 to 1.0
    time_window: int  # seconds
    impact_analysis: str
    root_cause_probability: float
    affected_devices: List[str]
    affected_services: List[str]
    timestamp: str

@dataclass
class ImpactAnalysis:
    """Network change impact analysis"""
    analysis_id: str
    change_event: StateChange
    impact_level: ChangeImpact
    affected_components: List[str]
    service_disruption: bool
    estimated_users_affected: int
    business_impact_score: float  # 0.0 to 1.0
    mitigation_recommendations: List[str]
    rollback_required: bool
    monitoring_recommendations: List[str]
    timestamp: str

@dataclass
class NetworkPattern:
    """Detected network pattern"""
    pattern_id: str
    pattern_type: PatternType
    description: str
    confidence: float  # 0.0 to 1.0
    frequency: str  # daily, weekly, monthly, etc.
    affected_devices: List[str]
    metrics_involved: List[str]
    pattern_data: Dict[str, Any]
    prediction: str
    recommended_actions: List[str]
    first_detected: str
    last_updated: str

@dataclass
class PerformanceOptimization:
    """Performance optimization recommendation"""
    optimization_id: str
    target_device: str
    optimization_type: str  # cpu, memory, bandwidth, latency
    current_metrics: Dict[str, float]
    target_metrics: Dict[str, float]
    improvement_potential: float  # percentage improvement
    implementation_steps: List[str]
    estimated_effort: str
    risk_assessment: str
    expected_benefits: List[str]
    prerequisites: List[str]
    timestamp: str

@dataclass
class ProactiveRecommendation:
    """Proactive network management recommendation"""
    recommendation_id: str
    category: ChangeCategory
    priority: str  # low, medium, high, critical
    title: str
    description: str
    rationale: str
    evidence: List[str]
    implementation_steps: List[str]
    expected_outcome: str
    risk_factors: List[str]
    timeline: str
    success_metrics: List[str]
    created_at: str

class NetworkCorrelationEngine:
    """Advanced network correlation and analysis engine"""
    
    def __init__(self):
        self.context_engine = NetworkContextEngine()
        self.correlation_cache = deque(maxlen=1000)
        self.pattern_cache = {}
        self.optimization_cache = deque(maxlen=500)
        self.correlation_rules = self._load_correlation_rules()
        
        logger.info("NetworkCorrelationEngine initialized")
    
    def _load_correlation_rules(self) -> Dict[str, Any]:
        """Load correlation analysis rules"""
        return {
            'time_windows': {
                'immediate': 300,    # 5 minutes
                'short_term': 1800,  # 30 minutes
                'medium_term': 7200, # 2 hours
                'long_term': 86400   # 24 hours
            },
            'correlation_thresholds': {
                'strong': 0.8,
                'moderate': 0.6,
                'weak': 0.4
            },
            'impact_weights': {
                'spine_device': 0.9,
                'leaf_device': 0.7,
                'protocol_change': 0.8,
                'interface_change': 0.6,
                'config_change': 0.7
            }
        }
    
    def analyze_change_correlation(self, time_window_hours: int = 2) -> List[ChangeCorrelation]:
        """Analyze correlations between network changes"""
        correlations = []
        
        try:
            # Get recent state changes from database
            since_time = (datetime.now() - timedelta(hours=time_window_hours)).isoformat()
            
            with sqlite3.connect(HISTORICAL_DB) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT change_id, timestamp, device_name, change_type, data
                    FROM state_changes 
                    WHERE timestamp > ?
                    ORDER BY timestamp DESC
                ''', (since_time,))
                
                change_records = cursor.fetchall()
            
            # Convert to StateChange objects
            state_changes = []
            for record in change_records:
                try:
                    change_data = json.loads(record[4])
                    state_change = StateChange(
                        change_id=record[0],
                        timestamp=record[1],
                        device_name=record[2],
                        change_type=record[3],
                        before_value=change_data.get('before_value'),
                        after_value=change_data.get('after_value'),
                        impact_score=change_data.get('impact_score', 0.5),
                        related_changes=change_data.get('related_changes', [])
                    )
                    state_changes.append(state_change)
                except Exception as e:
                    logger.warning(f"Failed to parse state change record: {e}")
                    continue
            
            # Analyze correlations
            for i, primary_change in enumerate(state_changes):
                related_changes = []
                correlation_scores = []
                
                # Look for related changes within time windows
                for j, other_change in enumerate(state_changes):
                    if i == j:  # Skip self
                        continue
                    
                    correlation_score = self._calculate_correlation(primary_change, other_change)
                    if correlation_score > self.correlation_rules['correlation_thresholds']['weak']:
                        related_changes.append(other_change)
                        correlation_scores.append(correlation_score)
                
                # Create correlation if significant relationships found
                if related_changes:
                    avg_correlation = statistics.mean(correlation_scores)
                    
                    # Analyze impact
                    impact_analysis = self._analyze_change_impact_correlation(primary_change, related_changes)
                    
                    # Determine affected devices and services
                    affected_devices = list(set([primary_change.device_name] + 
                                               [c.device_name for c in related_changes]))
                    affected_services = self._identify_affected_services(affected_devices, primary_change.change_type)
                    
                    correlation = ChangeCorrelation(
                        correlation_id=f"CORR-{datetime.now().strftime('%Y%m%d%H%M%S')}-{i}",
                        primary_change=primary_change,
                        related_changes=related_changes,
                        correlation_strength=avg_correlation,
                        time_window=time_window_hours * 3600,
                        impact_analysis=impact_analysis,
                        root_cause_probability=self._calculate_root_cause_probability(primary_change, related_changes),
                        affected_devices=affected_devices,
                        affected_services=affected_services,
                        timestamp=datetime.now().isoformat()
                    )
                    
                    correlations.append(correlation)
                    self.correlation_cache.append(correlation)
            
            logger.info(f"Analyzed {len(correlations)} change correlations")
            
        except Exception as e:
            logger.error(f"Failed to analyze change correlation: {e}")
        
        return correlations
    
    def _calculate_correlation(self, change1: StateChange, change2: StateChange) -> float:
        """Calculate correlation strength between two changes"""
        score = 0.0
        
        # Time proximity (within time windows)
        time1 = datetime.fromisoformat(change1.timestamp.replace('Z', '+00:00'))
        time2 = datetime.fromisoformat(change2.timestamp.replace('Z', '+00:00'))
        time_diff = abs((time1 - time2).total_seconds())
        
        # Score based on time proximity
        for window_name, window_seconds in self.correlation_rules['time_windows'].items():
            if time_diff <= window_seconds:
                if window_name == 'immediate':
                    score += 0.4
                elif window_name == 'short_term':
                    score += 0.3
                elif window_name == 'medium_term':
                    score += 0.2
                elif window_name == 'long_term':
                    score += 0.1
                break
        
        # Device relationship scoring
        if change1.device_name == change2.device_name:
            score += 0.3  # Same device
        elif self._are_devices_connected(change1.device_name, change2.device_name):
            score += 0.2  # Connected devices
        
        # Change type relationship
        if change1.change_type == change2.change_type:
            score += 0.2  # Same change type
        elif self._are_change_types_related(change1.change_type, change2.change_type):
            score += 0.1  # Related change types
        
        # Impact score similarity
        impact_diff = abs(change1.impact_score - change2.impact_score)
        if impact_diff < 0.2:
            score += 0.1
        
        return min(score, 1.0)
    
    def _are_devices_connected(self, device1: str, device2: str) -> bool:
        """Check if two devices are directly connected"""
        try:
            # This would need topology information
            # For now, assume spine-leaf relationships
            if ('SPINE' in device1 and 'LEAF' in device2) or ('LEAF' in device1 and 'SPINE' in device2):
                return True
            return False
        except Exception:
            return False
    
    def _are_change_types_related(self, type1: str, type2: str) -> bool:
        """Check if change types are related"""
        related_types = {
            'config': ['protocol', 'interface'],
            'protocol': ['config', 'topology'],
            'interface': ['config', 'topology'],
            'topology': ['protocol', 'interface'],
            'metric': ['performance', 'state'],
            'performance': ['metric', 'state']
        }
        
        return type2 in related_types.get(type1, [])
    
    def _analyze_change_impact_correlation(self, primary: StateChange, related: List[StateChange]) -> str:
        """Analyze the impact of correlated changes"""
        impact_factors = []
        
        # Device criticality
        if 'SPINE' in primary.device_name:
            impact_factors.append("Critical spine device affected")
        
        # Change volume
        if len(related) > 3:
            impact_factors.append("Multiple related changes detected")
        
        # Change types
        change_types = set([primary.change_type] + [c.change_type for c in related])
        if 'protocol' in change_types:
            impact_factors.append("Protocol changes may affect routing")
        if 'topology' in change_types:
            impact_factors.append("Topology changes may affect connectivity")
        
        if not impact_factors:
            return "Minimal network impact expected"
        
        return "; ".join(impact_factors)
    
    def _calculate_root_cause_probability(self, primary: StateChange, related: List[StateChange]) -> float:
        """Calculate probability that primary change is root cause"""
        score = 0.5  # Base probability
        
        # Earlier timestamp increases root cause probability
        primary_time = datetime.fromisoformat(primary.timestamp.replace('Z', '+00:00'))
        earlier_count = 0
        
        for change in related:
            change_time = datetime.fromisoformat(change.timestamp.replace('Z', '+00:00'))
            if primary_time <= change_time:
                earlier_count += 1
        
        if earlier_count > len(related) / 2:
            score += 0.3
        
        # Higher impact score increases probability
        avg_related_impact = statistics.mean([c.impact_score for c in related])
        if primary.impact_score > avg_related_impact:
            score += 0.2
        
        return min(score, 1.0)
    
    def _identify_affected_services(self, devices: List[str], change_type: str) -> List[str]:
        """Identify network services affected by changes"""
        services = []
        
        # Based on device roles
        spine_devices = [d for d in devices if 'SPINE' in d]
        leaf_devices = [d for d in devices if 'LEAF' in d]
        
        if spine_devices:
            services.extend(['routing', 'inter_pod_connectivity'])
        
        if leaf_devices:
            services.extend(['access_layer', 'host_connectivity'])
        
        # Based on change type
        if change_type in ['protocol', 'routing']:
            services.append('routing_protocols')
        elif change_type == 'interface':
            services.append('network_connectivity')
        elif change_type == 'config':
            services.append('device_configuration')
        
        return list(set(services))
    
    def detect_network_patterns(self, analysis_days: int = 7) -> List[NetworkPattern]:
        """Detect recurring patterns in network behavior"""
        patterns = []
        
        try:
            # Get historical data for pattern analysis
            since_time = (datetime.now() - timedelta(days=analysis_days)).isoformat()
            
            with sqlite3.connect(HISTORICAL_DB) as conn:
                cursor = conn.cursor()
                
                # Get device metrics for pattern analysis
                cursor.execute('''
                    SELECT device_name, metric_name, timestamp, metric_value
                    FROM device_metrics 
                    WHERE timestamp > ?
                    ORDER BY device_name, metric_name, timestamp
                ''', (since_time,))
                
                metrics_data = cursor.fetchall()
            
            # Group data by device and metric
            grouped_metrics = defaultdict(lambda: defaultdict(list))
            for device, metric, timestamp, value in metrics_data:
                grouped_metrics[device][metric].append((timestamp, value))
            
            # Analyze patterns for each metric
            for device_name, device_metrics in grouped_metrics.items():
                for metric_name, time_series in device_metrics.items():
                    if len(time_series) < 20:  # Need sufficient data points
                        continue
                    
                    # Detect different pattern types
                    cyclic_pattern = self._detect_cyclic_pattern(device_name, metric_name, time_series)
                    if cyclic_pattern:
                        patterns.append(cyclic_pattern)
                    
                    degradation_pattern = self._detect_degradation_pattern(device_name, metric_name, time_series)
                    if degradation_pattern:
                        patterns.append(degradation_pattern)
                    
                    anomaly_pattern = self._detect_anomaly_pattern(device_name, metric_name, time_series)
                    if anomaly_pattern:
                        patterns.append(anomaly_pattern)
            
            # Store patterns in cache
            for pattern in patterns:
                self.pattern_cache[pattern.pattern_id] = pattern
            
            logger.info(f"Detected {len(patterns)} network patterns")
            
        except Exception as e:
            logger.error(f"Failed to detect network patterns: {e}")
        
        return patterns
    
    def _detect_cyclic_pattern(self, device: str, metric: str, time_series: List[Tuple[str, float]]) -> Optional[NetworkPattern]:
        """Detect cyclic/recurring patterns in metrics"""
        try:
            if len(time_series) < 24:  # Need at least 24 data points
                return None
            
            values = [point[1] for point in time_series]
            
            # Simple cyclic detection using autocorrelation-like approach
            n = len(values)
            mean_val = statistics.mean(values)
            
            # Check for daily patterns (assuming hourly data)
            if n >= 24:
                daily_correlation = 0
                for i in range(n - 24):
                    if values[i] > mean_val and values[i + 24] > mean_val:
                        daily_correlation += 1
                    elif values[i] <= mean_val and values[i + 24] <= mean_val:
                        daily_correlation += 1
                
                daily_confidence = daily_correlation / (n - 24)
                
                if daily_confidence > 0.7:  # Strong daily pattern
                    pattern_id = f"CYCLIC-{device}-{metric}-{datetime.now().strftime('%Y%m%d')}"
                    
                    # Calculate peak times
                    peak_hours = []
                    for i in range(24):
                        if i < len(values) and values[i] > mean_val * 1.2:
                            peak_hours.append(i)
                    
                    return NetworkPattern(
                        pattern_id=pattern_id,
                        pattern_type=PatternType.CYCLIC,
                        description=f"Daily cyclic pattern detected in {metric} on {device}",
                        confidence=daily_confidence,
                        frequency="daily",
                        affected_devices=[device],
                        metrics_involved=[metric],
                        pattern_data={
                            "cycle_period": "24_hours",
                            "peak_hours": peak_hours,
                            "baseline_value": mean_val
                        },
                        prediction=f"Pattern expected to repeat daily with peaks around hours {peak_hours}",
                        recommended_actions=[
                            "Schedule maintenance during low-usage hours",
                            "Prepare for increased load during peak hours"
                        ],
                        first_detected=datetime.now().isoformat(),
                        last_updated=datetime.now().isoformat()
                    )
            
        except Exception as e:
            logger.warning(f"Failed to detect cyclic pattern for {device}/{metric}: {e}")
        
        return None
    
    def _detect_degradation_pattern(self, device: str, metric: str, time_series: List[Tuple[str, float]]) -> Optional[NetworkPattern]:
        """Detect performance degradation patterns"""
        try:
            if len(time_series) < 10:
                return None
            
            values = [point[1] for point in time_series]
            
            # Calculate trend over time
            n = len(values)
            x_vals = list(range(n))
            x_mean = statistics.mean(x_vals)
            y_mean = statistics.mean(values)
            
            numerator = sum((x - x_mean) * (y - y_mean) for x, y in zip(x_vals, values))
            denominator = sum((x - x_mean) ** 2 for x in x_vals)
            
            if denominator == 0:
                return None
            
            slope = numerator / denominator
            
            # Check for degradation (positive slope for latency/cpu, negative for throughput)
            degradation_metrics = ['cpu_utilization', 'memory_utilization', 'latency', 'error_count']
            improvement_metrics = ['uptime', 'packet_loss']  # Lower is better for some
            
            is_degrading = False
            if metric in degradation_metrics and slope > 0.01:  # Increasing bad metrics
                is_degrading = True
            elif metric in improvement_metrics and slope < -0.01:  # Decreasing good metrics
                is_degrading = True
            
            if is_degrading:
                confidence = min(abs(slope) * 10, 1.0)  # Normalize slope to confidence
                
                if confidence > 0.3:  # Significant degradation
                    pattern_id = f"DEGRAD-{device}-{metric}-{datetime.now().strftime('%Y%m%d')}"
                    
                    return NetworkPattern(
                        pattern_id=pattern_id,
                        pattern_type=PatternType.DEGRADATION,
                        description=f"Performance degradation detected in {metric} on {device}",
                        confidence=confidence,
                        frequency="continuous",
                        affected_devices=[device],
                        metrics_involved=[metric],
                        pattern_data={
                            "degradation_rate": slope,
                            "current_value": values[-1],
                            "initial_value": values[0],
                            "trend_period_hours": len(time_series)
                        },
                        prediction=f"Continued degradation expected if trend continues",
                        recommended_actions=[
                            f"Investigate cause of {metric} degradation on {device}",
                            "Consider performance optimization or capacity upgrade",
                            "Implement proactive monitoring"
                        ],
                        first_detected=datetime.now().isoformat(),
                        last_updated=datetime.now().isoformat()
                    )
        
        except Exception as e:
            logger.warning(f"Failed to detect degradation pattern for {device}/{metric}: {e}")
        
        return None
    
    def _detect_anomaly_pattern(self, device: str, metric: str, time_series: List[Tuple[str, float]]) -> Optional[NetworkPattern]:
        """Detect anomalous behavior patterns"""
        try:
            if len(time_series) < 10:
                return None
            
            values = [point[1] for point in time_series]
            mean_val = statistics.mean(values)
            std_dev = statistics.stdev(values) if len(values) > 1 else 0
            
            if std_dev == 0:
                return None
            
            # Detect values outside normal range (2 standard deviations)
            anomalies = []
            for i, (timestamp, value) in enumerate(time_series):
                if abs(value - mean_val) > 2 * std_dev:
                    anomalies.append((i, timestamp, value))
            
            anomaly_ratio = len(anomalies) / len(time_series)
            
            if anomaly_ratio > 0.1:  # More than 10% anomalous values
                pattern_id = f"ANOM-{device}-{metric}-{datetime.now().strftime('%Y%m%d')}"
                
                return NetworkPattern(
                    pattern_id=pattern_id,
                    pattern_type=PatternType.ANOMALY,
                    description=f"Anomalous behavior pattern detected in {metric} on {device}",
                    confidence=min(anomaly_ratio * 2, 1.0),
                    frequency="irregular",
                    affected_devices=[device],
                    metrics_involved=[metric],
                    pattern_data={
                        "anomaly_count": len(anomalies),
                        "anomaly_ratio": anomaly_ratio,
                        "baseline_mean": mean_val,
                        "baseline_stddev": std_dev,
                        "recent_anomalies": anomalies[-3:]  # Last 3 anomalies
                    },
                    prediction="Continued anomalous behavior may indicate underlying issues",
                    recommended_actions=[
                        f"Investigate root cause of anomalies in {metric} on {device}",
                        "Review recent configuration changes",
                        "Check for hardware or software issues"
                    ],
                    first_detected=datetime.now().isoformat(),
                    last_updated=datetime.now().isoformat()
                )
        
        except Exception as e:
            logger.warning(f"Failed to detect anomaly pattern for {device}/{metric}: {e}")
        
        return None
    
    def generate_performance_optimizations(self) -> List[PerformanceOptimization]:
        """Generate performance optimization recommendations"""
        optimizations = []
        
        try:
            # Get current network snapshot
            current_snapshot = self.context_engine.collect_network_snapshot()
            
            for device_name, metrics in current_snapshot.device_metrics.items():
                # CPU optimization
                if metrics.cpu_utilization > 70:
                    cpu_opt = self._generate_cpu_optimization(device_name, metrics)
                    if cpu_opt:
                        optimizations.append(cpu_opt)
                
                # Memory optimization
                if metrics.memory_utilization > 80:
                    mem_opt = self._generate_memory_optimization(device_name, metrics)
                    if mem_opt:
                        optimizations.append(mem_opt)
                
                # Interface optimization
                high_util_interfaces = {k: v for k, v in metrics.interface_utilization.items() if v > 80}
                if high_util_interfaces:
                    intf_opt = self._generate_interface_optimization(device_name, metrics, high_util_interfaces)
                    if intf_opt:
                        optimizations.append(intf_opt)
            
            # Store optimizations
            for opt in optimizations:
                self.optimization_cache.append(opt)
            
            logger.info(f"Generated {len(optimizations)} performance optimization recommendations")
            
        except Exception as e:
            logger.error(f"Failed to generate performance optimizations: {e}")
        
        return optimizations
    
    def _generate_cpu_optimization(self, device: str, metrics) -> Optional[PerformanceOptimization]:
        """Generate CPU optimization recommendation"""
        optimization_id = f"CPU-OPT-{device}-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        current_cpu = metrics.cpu_utilization
        target_cpu = 50.0  # Target 50% utilization
        
        # Device-specific optimization recommendations
        is_spine = 'SPINE' in device.upper()
        is_leaf = 'LEAF' in device.upper()
        
        implementation_steps = [
            "Review process list and identify high CPU consumers",
            "Optimize routing protocol configurations"
        ]
        
        if is_spine:  # NX-OS specific optimizations
            implementation_steps.extend([
                "NX-OS: Use 'show system resources' to identify CPU bottlenecks",
                "NX-OS: Optimize BGP route reflector configuration",
                "NX-OS: Tune OSPF SPF timers with 'ip ospf spf-time'", 
                "NX-OS: Review multicast forwarding and VXLAN overhead",
                "NX-OS: Check 'show processes cpu' for high CPU processes",
                "NX-OS: Consider disabling unused features to reduce CPU load"
            ])
        elif is_leaf:  # IOS specific optimizations  
            implementation_steps.extend([
                "IOS: Use 'show processes cpu' to identify high CPU consumers",
                "IOS: Optimize access port configurations",
                "IOS: Review VLAN and STP configurations",
                "IOS: Check for unnecessary features or protocols",
                "IOS: Tune BGP timers if BGP is configured",
                "IOS: Review OSPF area configuration and LSA propagation"
            ])
        
        implementation_steps.append("Consider hardware upgrade if software optimization insufficient")
        
        return PerformanceOptimization(
            optimization_id=optimization_id,
            target_device=device,
            optimization_type="cpu",
            current_metrics={"cpu_utilization": current_cpu},
            target_metrics={"cpu_utilization": target_cpu},
            improvement_potential=(current_cpu - target_cpu) / current_cpu * 100,
            implementation_steps=implementation_steps,
            estimated_effort="2-4 hours (device-specific commands)",
            risk_assessment="Medium - requires device-specific configuration changes",
            expected_benefits=[
                "Improved device responsiveness",
                "Better protocol convergence times", 
                "Reduced risk of CPU-related outages",
                f"Device-specific optimization for {'NX-OS' if is_spine else 'IOS' if is_leaf else 'unknown'} platform"
            ],
            prerequisites=[
                "Maintenance window for configuration changes",
                "Backup configuration available",
                "Device-specific monitoring tools to verify improvement",
                f"Familiarity with {'NX-OS' if is_spine else 'IOS' if is_leaf else 'unknown'} command syntax"
            ],
            timestamp=datetime.now().isoformat()
        )
    
    def _generate_memory_optimization(self, device: str, metrics) -> Optional[PerformanceOptimization]:
        """Generate memory optimization recommendation"""
        optimization_id = f"MEM-OPT-{device}-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        current_memory = metrics.memory_utilization
        target_memory = 70.0  # Target 70% utilization
        
        # Device-specific memory optimization
        is_spine = 'SPINE' in device.upper()
        is_leaf = 'LEAF' in device.upper()
        
        implementation_steps = [
            "Review routing table size and optimize prefixes",
            "Tune protocol buffers and queue sizes"
        ]
        
        if is_spine:  # NX-OS specific memory optimizations
            implementation_steps.extend([
                "NX-OS: Use 'show system resources' to analyze memory usage",
                "NX-OS: Review BGP route reflector memory consumption",
                "NX-OS: Check VXLAN tunnel and NVE peer memory usage",
                "NX-OS: Optimize multicast forwarding tables if applicable",
                "NX-OS: Use 'show processes memory' for detailed analysis",
                "NX-OS: Clear unnecessary log files with 'clear logging logfile'",
                "NX-OS: Review and optimize feature usage to reduce memory footprint"
            ])
        elif is_leaf:  # IOS specific memory optimizations
            implementation_steps.extend([
                "IOS: Use 'show memory summary' to analyze memory pools",
                "IOS: Review access-list and prefix-list memory usage",
                "IOS: Optimize VLAN database and STP memory consumption", 
                "IOS: Check interface buffer allocation",
                "IOS: Use 'show processes memory sorted' for analysis",
                "IOS: Clear logs with 'clear logging' command",
                "IOS: Review and disable unused services to free memory"
            ])
        
        implementation_steps.extend([
            "Clear unnecessary log files and temporary data",
            "Consider memory upgrade if optimization insufficient"
        ])
        
        return PerformanceOptimization(
            optimization_id=optimization_id,
            target_device=device,
            optimization_type="memory",
            current_metrics={"memory_utilization": current_memory},
            target_metrics={"memory_utilization": target_memory},
            improvement_potential=(current_memory - target_memory) / current_memory * 100,
            implementation_steps=implementation_steps,
            estimated_effort="1-3 hours (platform-specific analysis)",
            risk_assessment="Low to Medium - device-specific memory optimization",
            expected_benefits=[
                "Improved system stability",
                "Better performance under load",
                "Reduced risk of memory-related crashes",
                f"Optimized for {'NX-OS' if is_spine else 'IOS' if is_leaf else 'unknown'} memory management"
            ],
            prerequisites=[
                "System monitoring during optimization",
                "Understanding of current memory usage patterns",
                f"Knowledge of {'NX-OS' if is_spine else 'IOS' if is_leaf else 'unknown'} memory architecture"
            ],
            timestamp=datetime.now().isoformat()
        )
    
    def _generate_interface_optimization(self, device: str, metrics, high_util_interfaces: Dict[str, float]) -> Optional[PerformanceOptimization]:
        """Generate interface utilization optimization"""
        optimization_id = f"INTF-OPT-{device}-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        avg_utilization = statistics.mean(high_util_interfaces.values())
        target_utilization = 60.0  # Target 60% utilization
        
        # Device-specific interface optimization
        is_spine = 'SPINE' in device.upper()
        is_leaf = 'LEAF' in device.upper()
        
        implementation_steps = [
            f"Analyze traffic patterns on high-utilization interfaces: {list(high_util_interfaces.keys())}",
        ]
        
        if is_spine:  # NX-OS specific interface optimizations
            implementation_steps.extend([
                "NX-OS: Use 'show interface brief' for interface status overview",
                "NX-OS: Check interface counters with 'show interface counters'",
                "NX-OS: Analyze VXLAN tunnel interface utilization",
                "NX-OS: Review BGP peering interface bandwidth requirements",
                "NX-OS: Use 'show interface ethernet X/Y' for detailed statistics",
                "NX-OS: Consider port-channel aggregation for high-traffic spine links",
                "NX-OS: Optimize buffer allocation with 'interface buffer-boost'",
                "NX-OS: Review QoS policies applied to spine interfaces",
                "NX-OS: Check for interface errors with 'show interface counters errors'"
            ])
        elif is_leaf:  # IOS specific interface optimizations
            implementation_steps.extend([
                "IOS: Use 'show ip interface brief' for interface overview",
                "IOS: Check interface statistics with 'show interfaces'",
                "IOS: Analyze access port vs trunk port utilization patterns",
                "IOS: Review VLAN interface performance and segmentation",
                "IOS: Use 'show interfaces gigabitEthernet X/Y' for detailed analysis",
                "IOS: Consider EtherChannel for link aggregation",
                "IOS: Optimize interface buffers and queuing mechanisms",
                "IOS: Review storm-control and rate-limiting configurations",
                "IOS: Check interface error statistics with 'show interfaces counters'"
            ])
        
        implementation_steps.extend([
            "Consider link aggregation or higher bandwidth interfaces",
            "Implement traffic engineering or load balancing strategies", 
            "Review QoS policies for traffic prioritization and shaping",
            "Monitor interface performance after optimization"
        ])
        
        return PerformanceOptimization(
            optimization_id=optimization_id,
            target_device=device,
            optimization_type="bandwidth",
            current_metrics={"avg_interface_utilization": avg_utilization},
            target_metrics={"avg_interface_utilization": target_utilization},
            improvement_potential=(avg_utilization - target_utilization) / avg_utilization * 100,
            implementation_steps=implementation_steps,
            estimated_effort="4-8 hours (platform-specific interface work)",
            risk_assessment="Medium to High - may require hardware changes and device-specific configuration",
            expected_benefits=[
                "Improved network performance",
                "Reduced congestion and packet loss",
                "Better user experience",
                f"Optimized for {'NX-OS' if is_spine else 'IOS' if is_leaf else 'unknown'} interface management"
            ],
            prerequisites=[
                "Traffic analysis tools",
                "Understanding of current traffic patterns",
                "Possible hardware procurement",
                f"Knowledge of {'NX-OS' if is_spine else 'IOS' if is_leaf else 'unknown'} interface configuration"
            ],
            timestamp=datetime.now().isoformat()
        )
    
    def generate_proactive_recommendations(self) -> List[ProactiveRecommendation]:
        """Generate proactive network management recommendations"""
        recommendations = []
        
        try:
            # Analyze recent correlations and patterns
            correlations = self.analyze_change_correlation(time_window_hours=24)
            patterns = self.detect_network_patterns(analysis_days=7)
            optimizations = self.generate_performance_optimizations()
            
            # Generate recommendations based on analysis
            if correlations:
                rec = self._recommend_correlation_monitoring(correlations)
                if rec:
                    recommendations.append(rec)
            
            if patterns:
                degradation_patterns = [p for p in patterns if p.pattern_type == PatternType.DEGRADATION]
                if degradation_patterns:
                    rec = self._recommend_degradation_response(degradation_patterns)
                    if rec:
                        recommendations.append(rec)
                
                cyclic_patterns = [p for p in patterns if p.pattern_type == PatternType.CYCLIC]
                if cyclic_patterns:
                    rec = self._recommend_capacity_planning(cyclic_patterns)
                    if rec:
                        recommendations.append(rec)
            
            if optimizations:
                rec = self._recommend_performance_improvements(optimizations)
                if rec:
                    recommendations.append(rec)
            
            logger.info(f"Generated {len(recommendations)} proactive recommendations")
            
        except Exception as e:
            logger.error(f"Failed to generate proactive recommendations: {e}")
        
        return recommendations
    
    def _recommend_correlation_monitoring(self, correlations: List[ChangeCorrelation]) -> Optional[ProactiveRecommendation]:
        """Recommend enhanced monitoring based on correlations"""
        if not correlations:
            return None
        
        high_impact_correlations = [c for c in correlations if c.correlation_strength > 0.7]
        if not high_impact_correlations:
            return None
        
        affected_devices = set()
        for corr in high_impact_correlations:
            affected_devices.update(corr.affected_devices)
        
        return ProactiveRecommendation(
            recommendation_id=f"CORR-MON-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            category=ChangeCategory.PERFORMANCE,
            priority="high",
            title="Enhanced Correlation Monitoring",
            description="Implement enhanced monitoring for highly correlated network changes",
            rationale=f"Detected {len(high_impact_correlations)} high-impact change correlations affecting {len(affected_devices)} devices",
            evidence=[f"Correlation strength: {c.correlation_strength:.2f} for {c.primary_change.device_name}" for c in high_impact_correlations[:3]],
            implementation_steps=[
                "Set up automated correlation detection",
                "Implement real-time alerting for correlated changes",
                "Create correlation dashboards for operations team",
                "Establish correlation response procedures"
            ],
            expected_outcome="Faster incident detection and resolution through correlation awareness",
            risk_factors=["Potential alert fatigue if not properly tuned"],
            timeline="1-2 weeks",
            success_metrics=[
                "Reduced mean time to detection (MTTD)",
                "Improved incident correlation accuracy",
                "Faster root cause identification"
            ],
            created_at=datetime.now().isoformat()
        )
    
    def _recommend_degradation_response(self, patterns: List[NetworkPattern]) -> Optional[ProactiveRecommendation]:
        """Recommend response to degradation patterns"""
        if not patterns:
            return None
        
        critical_devices = []
        for pattern in patterns:
            critical_devices.extend(pattern.affected_devices)
        
        return ProactiveRecommendation(
            recommendation_id=f"DEGRAD-RESP-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            category=ChangeCategory.PERFORMANCE,
            priority="critical",
            title="Address Performance Degradation",
            description="Take immediate action to address detected performance degradation patterns",
            rationale=f"Detected degradation patterns on {len(set(critical_devices))} devices",
            evidence=[f"Degradation in {p.metrics_involved} on {p.affected_devices}" for p in patterns[:3]],
            implementation_steps=[
                "Investigate root cause of performance degradation",
                "Implement immediate mitigation measures",
                "Schedule proactive maintenance",
                "Update monitoring thresholds based on trends"
            ],
            expected_outcome="Prevention of service degradation and potential outages",
            risk_factors=["Performance may continue degrading without intervention"],
            timeline="Immediate (1-3 days)",
            success_metrics=[
                "Performance metrics return to baseline",
                "No service disruptions occur",
                "Trend analysis shows improvement"
            ],
            created_at=datetime.now().isoformat()
        )
    
    def _recommend_capacity_planning(self, patterns: List[NetworkPattern]) -> Optional[ProactiveRecommendation]:
        """Recommend capacity planning based on cyclic patterns"""
        if not patterns:
            return None
        
        return ProactiveRecommendation(
            recommendation_id=f"CAP-PLAN-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            category=ChangeCategory.CAPACITY,
            priority="medium",
            title="Capacity Planning Based on Usage Patterns",
            description="Optimize capacity planning using detected cyclic usage patterns",
            rationale=f"Detected {len(patterns)} cyclic patterns indicating predictable usage",
            evidence=[f"Daily pattern in {p.metrics_involved} on {p.affected_devices}" for p in patterns[:3]],
            implementation_steps=[
                "Analyze peak usage periods from pattern data",
                "Plan capacity upgrades for peak periods",
                "Implement predictive scaling",
                "Schedule maintenance during low-usage periods"
            ],
            expected_outcome="Improved resource utilization and user experience",
            risk_factors=["Pattern changes may require plan adjustments"],
            timeline="2-4 weeks",
            success_metrics=[
                "Reduced peak period congestion",
                "Improved capacity utilization efficiency",
                "Better maintenance scheduling"
            ],
            created_at=datetime.now().isoformat()
        )
    
    def _recommend_performance_improvements(self, optimizations: List[PerformanceOptimization]) -> Optional[ProactiveRecommendation]:
        """Recommend performance improvements"""
        if not optimizations:
            return None
        
        high_impact_opts = [opt for opt in optimizations if opt.improvement_potential > 20]
        if not high_impact_opts:
            return None
        
        return ProactiveRecommendation(
            recommendation_id=f"PERF-IMP-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            category=ChangeCategory.PERFORMANCE,
            priority="high",
            title="Implement Performance Optimizations",
            description="Execute identified performance optimization opportunities",
            rationale=f"Identified {len(high_impact_opts)} high-impact optimization opportunities",
            evidence=[f"{opt.improvement_potential:.1f}% improvement potential in {opt.optimization_type} on {opt.target_device}" for opt in high_impact_opts[:3]],
            implementation_steps=[
                "Prioritize optimizations by impact and effort",
                "Schedule implementation during maintenance windows",
                "Implement monitoring to verify improvements",
                "Document optimization results for future reference"
            ],
            expected_outcome="Significant performance improvements across the network",
            risk_factors=["Configuration changes may introduce temporary instability"],
            timeline="2-6 weeks depending on scope",
            success_metrics=[
                "Measurable performance improvements",
                "Reduced resource utilization",
                "Improved system stability"
            ],
            created_at=datetime.now().isoformat()
        )

# MCP Tool Functions
def analyze_network_correlation(time_window_hours: int = 2) -> Dict[str, Any]:
    """
    Analyze correlations between network changes and events
    
    Args:
        time_window_hours: Time window for correlation analysis
        
    Returns:
        Dict containing correlation analysis results
    """
    try:
        engine = NetworkCorrelationEngine()
        correlations = engine.analyze_change_correlation(time_window_hours)
        
        # Convert enums and objects for JSON serialization
        def convert_objects(obj):
            if isinstance(obj, dict):
                return {k: convert_objects(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_objects(item) for item in obj]
            elif hasattr(obj, '__dict__'):
                return convert_objects(asdict(obj))
            elif isinstance(obj, (ChangeImpact, PatternType, ChangeCategory)):
                return obj.value
            else:
                return obj
        
        return {
            'success': True,
            'correlation_analysis': {
                'correlations': convert_objects(correlations),
                'time_window_hours': time_window_hours,
                'correlations_count': len(correlations),
                'high_strength_correlations': len([c for c in correlations if c.correlation_strength > 0.7]),
                'analysis_timestamp': datetime.now().isoformat()
            },
            'message': f"Analyzed {len(correlations)} change correlations in {time_window_hours} hour window"
        }
        
    except Exception as e:
        logger.error(f"MCP analyze_network_correlation failed: {e}")
        return {
            'success': False,
            'error': str(e),
            'message': f"Failed to analyze network correlation: {str(e)}"
        }

def detect_network_patterns(analysis_days: int = 7) -> Dict[str, Any]:
    """
    Detect patterns in network behavior and performance
    
    Args:
        analysis_days: Number of days to analyze for patterns
        
    Returns:
        Dict containing detected patterns
    """
    try:
        engine = NetworkCorrelationEngine()
        patterns = engine.detect_network_patterns(analysis_days)
        
        # Convert objects for JSON serialization
        def convert_objects(obj):
            if isinstance(obj, dict):
                return {k: convert_objects(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_objects(item) for item in obj]
            elif hasattr(obj, '__dict__'):
                return convert_objects(asdict(obj))
            elif isinstance(obj, (PatternType,)):
                return obj.value
            else:
                return obj
        
        # Categorize patterns by type
        pattern_summary = defaultdict(int)
        for pattern in patterns:
            pattern_summary[pattern.pattern_type.value] += 1
        
        return {
            'success': True,
            'pattern_detection': {
                'patterns': convert_objects(patterns),
                'analysis_days': analysis_days,
                'total_patterns': len(patterns),
                'pattern_summary': dict(pattern_summary),
                'analysis_timestamp': datetime.now().isoformat()
            },
            'message': f"Detected {len(patterns)} patterns over {analysis_days} days"
        }
        
    except Exception as e:
        logger.error(f"MCP detect_network_patterns failed: {e}")
        return {
            'success': False,
            'error': str(e),
            'message': f"Failed to detect network patterns: {str(e)}"
        }

def get_performance_optimizations() -> Dict[str, Any]:
    """
    Get performance optimization recommendations
    
    Returns:
        Dict containing optimization recommendations
    """
    try:
        engine = NetworkCorrelationEngine()
        optimizations = engine.generate_performance_optimizations()
        
        # Convert objects for JSON serialization
        def convert_objects(obj):
            if isinstance(obj, dict):
                return {k: convert_objects(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_objects(item) for item in obj]
            elif hasattr(obj, '__dict__'):
                return convert_objects(asdict(obj))
            else:
                return obj
        
        # Categorize by optimization type
        opt_summary = defaultdict(int)
        for opt in optimizations:
            opt_summary[opt.optimization_type] += 1
        
        return {
            'success': True,
            'performance_optimizations': {
                'optimizations': convert_objects(optimizations),
                'total_optimizations': len(optimizations),
                'optimization_summary': dict(opt_summary),
                'analysis_timestamp': datetime.now().isoformat()
            },
            'message': f"Generated {len(optimizations)} performance optimization recommendations"
        }
        
    except Exception as e:
        logger.error(f"MCP get_performance_optimizations failed: {e}")
        return {
            'success': False,
            'error': str(e),
            'message': f"Failed to get performance optimizations: {str(e)}"
        }

def get_proactive_recommendations() -> Dict[str, Any]:
    """
    Get proactive network management recommendations
    
    Returns:
        Dict containing proactive recommendations
    """
    try:
        engine = NetworkCorrelationEngine()
        recommendations = engine.generate_proactive_recommendations()
        
        # Convert objects for JSON serialization
        def convert_objects(obj):
            if isinstance(obj, dict):
                return {k: convert_objects(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_objects(item) for item in obj]
            elif hasattr(obj, '__dict__'):
                return convert_objects(asdict(obj))
            elif isinstance(obj, (ChangeCategory,)):
                return obj.value
            else:
                return obj
        
        # Categorize by priority and category
        priority_summary = defaultdict(int)
        category_summary = defaultdict(int)
        for rec in recommendations:
            priority_summary[rec.priority] += 1
            category_summary[rec.category.value] += 1
        
        return {
            'success': True,
            'proactive_recommendations': {
                'recommendations': convert_objects(recommendations),
                'total_recommendations': len(recommendations),
                'priority_summary': dict(priority_summary),
                'category_summary': dict(category_summary),
                'analysis_timestamp': datetime.now().isoformat()
            },
            'message': f"Generated {len(recommendations)} proactive recommendations"
        }
        
    except Exception as e:
        logger.error(f"MCP get_proactive_recommendations failed: {e}")
        return {
            'success': False,
            'error': str(e),
            'message': f"Failed to get proactive recommendations: {str(e)}"
        }

if __name__ == "__main__":
    # Test the correlation engine
    engine = NetworkCorrelationEngine()
    
    # Test correlation analysis
    correlations = engine.analyze_change_correlation(time_window_hours=2)
    print(f"Correlations found: {len(correlations)}")
    
    # Test pattern detection
    patterns = engine.detect_network_patterns(analysis_days=1)
    print(f"Patterns detected: {len(patterns)}")
    
    # Test optimization recommendations
    optimizations = engine.generate_performance_optimizations()
    print(f"Optimizations generated: {len(optimizations)}")
    
    # Test proactive recommendations
    recommendations = engine.generate_proactive_recommendations()
    print(f"Proactive recommendations: {len(recommendations)}")
    
    print("NetworkCorrelationEngine test completed")
