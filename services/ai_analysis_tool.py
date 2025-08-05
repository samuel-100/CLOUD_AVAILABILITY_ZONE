#!/usr/bin/env python3
"""
AI-Powered Network Analysis Tool

Implements intelligent network issue analysis with AI-powered diagnostics,
root cause analysis, and actionable recommendations for network automation.
"""

import os
import sys
import json
import yaml
import logging
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
import re

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

# Import network services
from services.network_status_tool import get_network_status
from services.device_details_tool import get_device_details
from services.network_topology_tool import get_network_topology

# File paths
TOPOLOGY_FILE = '/opt/network-automation/CLOUD_AVAILABILITY_ZONE/network_topology.yaml'
DEVICES_FILE = '/opt/network-automation/CLOUD_AVAILABILITY_ZONE/devices.yaml'
LOGS_DIR = '/opt/network-automation/CLOUD_AVAILABILITY_ZONE/logs'

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class NetworkSymptom:
    """Network issue symptom definition"""
    type: str  # connectivity, performance, protocol, configuration
    device: Optional[str] = None
    interface: Optional[str] = None
    protocol: Optional[str] = None
    severity: str = "medium"  # low, medium, high, critical
    description: str = ""
    timestamp: str = ""
    data: Dict[str, Any] = None

@dataclass
class RootCauseAnalysis:
    """Root cause analysis result"""
    primary_cause: str
    contributing_factors: List[str]
    confidence_score: float  # 0.0 to 1.0
    evidence: List[str]
    affected_devices: List[str]
    impact_assessment: str

@dataclass
class ActionableRecommendation:
    """Actionable recommendation for issue resolution"""
    action_type: str  # immediate, preventive, monitoring
    priority: str  # low, medium, high, critical
    description: str
    commands: List[str]
    verification_steps: List[str]
    estimated_time: str
    risk_level: str  # low, medium, high
    rollback_plan: str = ""

@dataclass
class NetworkIssueAnalysis:
    """Complete network issue analysis response"""
    issue_id: str
    summary: str
    symptoms: List[NetworkSymptom]
    root_cause: RootCauseAnalysis
    recommendations: List[ActionableRecommendation]
    timeline: List[Dict[str, Any]]
    related_changes: List[str]
    monitoring_suggestions: List[str]
    timestamp: str

class NetworkIssueAnalyzer:
    """AI-powered network issue analyzer"""
    
    def __init__(self):
        self.topology_data = self._load_topology()
        self.device_credentials = self._load_device_credentials()
        self.analysis_history = []
        
    def _load_topology(self) -> Dict[str, Any]:
        """Load network topology configuration"""
        try:
            with open(TOPOLOGY_FILE) as f:
                data = yaml.safe_load(f)
                return data.get('topology', {})
        except Exception as e:
            logger.error(f"Failed to load topology: {e}")
            return {}
    
    def _load_device_credentials(self) -> Dict[str, Any]:
        """Load device credentials"""
        try:
            with open(DEVICES_FILE) as f:
                devices_config = yaml.safe_load(f)
                return {
                    device['name']: {
                        'username': device['username'],
                        'password': device['password'],
                        'mgmt_ip': device['mgmt_ip']
                    }
                    for device in devices_config['devices']
                }
        except Exception as e:
            logger.warning(f"Could not load device credentials: {e}")
            return {}
    
    def _collect_network_state(self) -> Dict[str, Any]:
        """Collect current network state for analysis"""
        try:
            # Get network status
            network_status = get_network_status()
            
            # Get topology information
            topology_info = get_network_topology()
            
            # Get device details for each device
            device_details = {}
            if 'devices' in network_status:
                for device in network_status['devices']:
                    if device.get('status') == 'reachable':
                        details = get_device_details(device['name'])
                        device_details[device['name']] = details
            
            return {
                'network_status': network_status,
                'topology_info': topology_info,
                'device_details': device_details,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"Failed to collect network state: {e}")
            return {}
    
    def _analyze_connectivity_issues(self, network_state: Dict[str, Any]) -> List[NetworkSymptom]:
        """Analyze connectivity-related issues"""
        symptoms = []
        
        if 'network_status' not in network_state:
            return symptoms
        
        network_status = network_state['network_status']
        
        # Check device reachability
        if 'devices' in network_status:
            for device in network_status['devices']:
                if device.get('status') != 'reachable':
                    symptoms.append(NetworkSymptom(
                        type="connectivity",
                        device=device['name'],
                        severity="high",
                        description=f"Device {device['name']} is not reachable",
                        timestamp=datetime.now().isoformat(),
                        data={'mgmt_ip': device.get('mgmt_ip'), 'ping_status': device.get('status')}
                    ))
        
        # Check interface status from device details
        device_details = network_state.get('device_details', {})
        for device_name, details in device_details.items():
            if 'interfaces' in details:
                for interface in details['interfaces']:
                    if interface.get('admin_status') == 'up' and interface.get('oper_status') == 'down':
                        symptoms.append(NetworkSymptom(
                            type="connectivity",
                            device=device_name,
                            interface=interface['name'],
                            severity="medium",
                            description=f"Interface {interface['name']} on {device_name} is admin up but operationally down",
                            timestamp=datetime.now().isoformat(),
                            data=interface
                        ))
        
        return symptoms
    
    def _analyze_protocol_issues(self, network_state: Dict[str, Any]) -> List[NetworkSymptom]:
        """Analyze protocol-related issues"""
        symptoms = []
        
        network_status = network_state.get('network_status', {})
        device_details = network_state.get('device_details', {})
        
        # Check OSPF neighbor issues
        for device_name, details in device_details.items():
            if 'ospf_neighbors' in details:
                for neighbor in details['ospf_neighbors']:
                    if neighbor.get('state') != 'Full':
                        symptoms.append(NetworkSymptom(
                            type="protocol",
                            device=device_name,
                            protocol="ospf",
                            severity="high",
                            description=f"OSPF neighbor {neighbor.get('neighbor_id')} on {device_name} is in {neighbor.get('state')} state",
                            timestamp=datetime.now().isoformat(),
                            data=neighbor
                        ))
        
        # Check BGP session issues
        for device_name, details in device_details.items():
            if 'bgp_neighbors' in details:
                for neighbor in details['bgp_neighbors']:
                    if neighbor.get('state') != 'Established':
                        symptoms.append(NetworkSymptom(
                            type="protocol",
                            device=device_name,
                            protocol="bgp",
                            severity="high",
                            description=f"BGP neighbor {neighbor.get('neighbor')} on {device_name} is in {neighbor.get('state')} state",
                            timestamp=datetime.now().isoformat(),
                            data=neighbor
                        ))
        
        return symptoms
    
    def _analyze_performance_issues(self, network_state: Dict[str, Any]) -> List[NetworkSymptom]:
        """Analyze performance-related issues"""
        symptoms = []
        
        device_details = network_state.get('device_details', {})
        
        # Check interface utilization and errors
        for device_name, details in device_details.items():
            if 'interfaces' in details:
                for interface in details['interfaces']:
                    # Check for high error rates
                    input_errors = interface.get('input_errors', 0)
                    output_errors = interface.get('output_errors', 0)
                    
                    if isinstance(input_errors, (int, float)) and input_errors > 100:
                        symptoms.append(NetworkSymptom(
                            type="performance",
                            device=device_name,
                            interface=interface['name'],
                            severity="medium",
                            description=f"High input errors ({input_errors}) on interface {interface['name']} of {device_name}",
                            timestamp=datetime.now().isoformat(),
                            data={'input_errors': input_errors, 'interface_data': interface}
                        ))
                    
                    if isinstance(output_errors, (int, float)) and output_errors > 100:
                        symptoms.append(NetworkSymptom(
                            type="performance",
                            device=device_name,
                            interface=interface['name'],
                            severity="medium",
                            description=f"High output errors ({output_errors}) on interface {interface['name']} of {device_name}",
                            timestamp=datetime.now().isoformat(),
                            data={'output_errors': output_errors, 'interface_data': interface}
                        ))
        
        return symptoms
    
    def _correlate_symptoms(self, symptoms: List[NetworkSymptom]) -> RootCauseAnalysis:
        """Correlate symptoms to identify root cause"""
        
        if not symptoms:
            return RootCauseAnalysis(
                primary_cause="No issues detected",
                contributing_factors=[],
                confidence_score=1.0,
                evidence=["All network monitoring checks passed"],
                affected_devices=[],
                impact_assessment="Network is operating normally"
            )
        
        # Group symptoms by type and device
        connectivity_issues = [s for s in symptoms if s.type == "connectivity"]
        protocol_issues = [s for s in symptoms if s.type == "protocol"]
        performance_issues = [s for s in symptoms if s.type == "performance"]
        
        affected_devices = list(set([s.device for s in symptoms if s.device]))
        
        # Analyze patterns
        if len(connectivity_issues) > len(protocol_issues):
            # Connectivity is primary issue
            primary_cause = "Network connectivity failure"
            contributing_factors = ["Device unreachable", "Interface down", "Physical layer issues"]
            confidence_score = 0.8
            evidence = [s.description for s in connectivity_issues[:3]]
            impact_assessment = f"High impact - {len(affected_devices)} devices affected"
            
        elif len(protocol_issues) > 0:
            # Protocol issues detected
            protocols = list(set([s.protocol for s in protocol_issues if s.protocol]))
            primary_cause = f"Protocol convergence issues ({', '.join(protocols)})"
            contributing_factors = ["Configuration mismatch", "Routing protocol instability", "Network topology changes"]
            confidence_score = 0.75
            evidence = [s.description for s in protocol_issues[:3]]
            impact_assessment = f"Medium to high impact - routing protocols affected on {len(affected_devices)} devices"
            
        elif len(performance_issues) > 0:
            # Performance issues
            primary_cause = "Network performance degradation"
            contributing_factors = ["High error rates", "Interface congestion", "Hardware issues"]
            confidence_score = 0.7
            evidence = [s.description for s in performance_issues[:3]]
            impact_assessment = f"Medium impact - performance issues on {len(affected_devices)} devices"
            
        else:
            # Mixed or unknown issues
            primary_cause = "Multiple network issues detected"
            contributing_factors = ["Mixed connectivity and protocol issues", "Potential cascading failures"]
            confidence_score = 0.6
            evidence = [s.description for s in symptoms[:3]]
            impact_assessment = f"Variable impact - {len(affected_devices)} devices affected"
        
        return RootCauseAnalysis(
            primary_cause=primary_cause,
            contributing_factors=contributing_factors,
            confidence_score=confidence_score,
            evidence=evidence,
            affected_devices=affected_devices,
            impact_assessment=impact_assessment
        )
    
    def _generate_recommendations(self, symptoms: List[NetworkSymptom], root_cause: RootCauseAnalysis) -> List[ActionableRecommendation]:
        """Generate actionable recommendations"""
        recommendations = []
        
        if not symptoms:
            return [ActionableRecommendation(
                action_type="monitoring",
                priority="low",
                description="Continue regular network monitoring",
                commands=["python services/postcheck.py"],
                verification_steps=["Check all devices are reachable", "Verify protocol states"],
                estimated_time="5 minutes",
                risk_level="low"
            )]
        
        # Connectivity issue recommendations
        connectivity_issues = [s for s in symptoms if s.type == "connectivity"]
        if connectivity_issues:
            for issue in connectivity_issues[:2]:  # Limit to top 2
                recommendations.append(ActionableRecommendation(
                    action_type="immediate",
                    priority="high",
                    description=f"Restore connectivity to {issue.device}",
                    commands=[
                        f"ping {issue.data.get('mgmt_ip', 'device')} -c 5",
                        f"ssh admin@{issue.data.get('mgmt_ip', 'device')} 'show version'",
                        "python services/test_connectivity.py"
                    ],
                    verification_steps=[
                        "Verify device is pingable",
                        "Confirm SSH access is working",
                        "Check device status in monitoring"
                    ],
                    estimated_time="10-15 minutes",
                    risk_level="low",
                    rollback_plan="No configuration changes required for basic connectivity tests"
                ))
        
        # Protocol issue recommendations
        protocol_issues = [s for s in symptoms if s.type == "protocol"]
        if protocol_issues:
            ospf_issues = [s for s in protocol_issues if s.protocol == "ospf"]
            bgp_issues = [s for s in protocol_issues if s.protocol == "bgp"]
            
            if ospf_issues:
                recommendations.append(ActionableRecommendation(
                    action_type="immediate",
                    priority="high",
                    description="Troubleshoot OSPF neighbor relationships",
                    commands=[
                        "show ip ospf neighbor",
                        "show ip ospf interface brief",
                        "show ip ospf database",
                        "clear ip ospf process"
                    ],
                    verification_steps=[
                        "Check OSPF neighbor states are Full",
                        "Verify OSPF database consistency",
                        "Confirm routing table convergence"
                    ],
                    estimated_time="15-20 minutes",
                    risk_level="medium",
                    rollback_plan="OSPF process restart is non-disruptive in stable topology"
                ))
            
            if bgp_issues:
                recommendations.append(ActionableRecommendation(
                    action_type="immediate",
                    priority="high",
                    description="Troubleshoot BGP session establishment",
                    commands=[
                        "show ip bgp summary",
                        "show ip bgp neighbors",
                        "show ip route bgp",
                        "clear ip bgp * soft"
                    ],
                    verification_steps=[
                        "Check BGP session states are Established",
                        "Verify BGP route advertisements",
                        "Confirm end-to-end reachability"
                    ],
                    estimated_time="15-25 minutes",
                    risk_level="medium",
                    rollback_plan="Soft BGP reset preserves configuration and session history"
                ))
        
        # Performance issue recommendations
        performance_issues = [s for s in symptoms if s.type == "performance"]
        if performance_issues:
            recommendations.append(ActionableRecommendation(
                action_type="immediate",
                priority="medium",
                description="Investigate interface errors and performance",
                commands=[
                    "show interfaces",
                    "show interfaces counters errors",
                    "show interfaces description",
                    "show interface utilization"
                ],
                verification_steps=[
                    "Check interface error counters",
                    "Monitor interface utilization",
                    "Verify physical layer status"
                ],
                estimated_time="10-15 minutes",
                risk_level="low",
                rollback_plan="Read-only commands, no configuration impact"
            ))
        
        # General monitoring recommendation
        recommendations.append(ActionableRecommendation(
            action_type="monitoring",
            priority="medium",
            description="Establish continuous monitoring for early detection",
            commands=[
                "python services/postcheck.py --continuous",
                "python services/workflow_monitoring.py --enable-alerts"
            ],
            verification_steps=[
                "Confirm monitoring scripts are running",
                "Verify alert notifications are working",
                "Check log file rotation is configured"
            ],
            estimated_time="5-10 minutes",
            risk_level="low"
        ))
        
        return recommendations
    
    def _create_timeline(self, symptoms: List[NetworkSymptom]) -> List[Dict[str, Any]]:
        """Create timeline of events"""
        timeline = []
        
        # Sort symptoms by timestamp
        sorted_symptoms = sorted(symptoms, key=lambda s: s.timestamp)
        
        for symptom in sorted_symptoms:
            timeline.append({
                'timestamp': symptom.timestamp,
                'event_type': 'issue_detected',
                'severity': symptom.severity,
                'description': symptom.description,
                'device': symptom.device,
                'protocol': symptom.protocol
            })
        
        # Add analysis timestamp
        timeline.append({
            'timestamp': datetime.now().isoformat(),
            'event_type': 'analysis_completed',
            'severity': 'info',
            'description': 'AI-powered network analysis completed',
            'device': None,
            'protocol': None
        })
        
        return timeline
    
    def analyze_network_issue(self, issue_description: str = "", focus_devices: List[str] = None) -> NetworkIssueAnalysis:
        """
        Main method to analyze network issues with AI-powered diagnostics
        
        Args:
            issue_description: Optional description of the issue to focus analysis
            focus_devices: Optional list of devices to focus analysis on
            
        Returns:
            NetworkIssueAnalysis: Complete analysis with recommendations
        """
        logger.info(f"Starting network issue analysis: {issue_description}")
        
        try:
            # Collect current network state
            network_state = self._collect_network_state()
            
            # Analyze different types of issues
            connectivity_symptoms = self._analyze_connectivity_issues(network_state)
            protocol_symptoms = self._analyze_protocol_issues(network_state)
            performance_symptoms = self._analyze_performance_issues(network_state)
            
            # Combine all symptoms
            all_symptoms = connectivity_symptoms + protocol_symptoms + performance_symptoms
            
            # Filter by focus devices if specified
            if focus_devices:
                all_symptoms = [s for s in all_symptoms if s.device in focus_devices]
            
            # Perform root cause analysis
            root_cause = self._correlate_symptoms(all_symptoms)
            
            # Generate actionable recommendations
            recommendations = self._generate_recommendations(all_symptoms, root_cause)
            
            # Create timeline
            timeline = self._create_timeline(all_symptoms)
            
            # Generate issue ID
            issue_id = f"NA-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
            
            # Create summary
            if all_symptoms:
                summary = f"Network analysis detected {len(all_symptoms)} issues: {root_cause.primary_cause}"
            else:
                summary = "Network analysis completed - no issues detected"
            
            # Create analysis result
            analysis = NetworkIssueAnalysis(
                issue_id=issue_id,
                summary=summary,
                symptoms=all_symptoms,
                root_cause=root_cause,
                recommendations=recommendations,
                timeline=timeline,
                related_changes=[],  # TODO: Implement change correlation
                monitoring_suggestions=[
                    "Enable continuous OSPF and BGP monitoring",
                    "Set up interface error rate alerting",
                    "Implement automated network health checks",
                    "Configure threshold-based alerting for key metrics"
                ],
                timestamp=datetime.now().isoformat()
            )
            
            # Store analysis in history
            self.analysis_history.append(analysis)
            
            logger.info(f"Network analysis completed: {summary}")
            return analysis
            
        except Exception as e:
            logger.error(f"Network analysis failed: {e}")
            # Return minimal analysis on error
            return NetworkIssueAnalysis(
                issue_id=f"NA-ERROR-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
                summary=f"Analysis failed: {str(e)}",
                symptoms=[],
                root_cause=RootCauseAnalysis(
                    primary_cause="Analysis system error",
                    contributing_factors=[str(e)],
                    confidence_score=0.0,
                    evidence=[],
                    affected_devices=[],
                    impact_assessment="Unable to assess due to analysis failure"
                ),
                recommendations=[ActionableRecommendation(
                    action_type="immediate",
                    priority="high",
                    description="Check network analysis system",
                    commands=["python services/network_status_tool.py"],
                    verification_steps=["Verify analysis tools are working"],
                    estimated_time="5 minutes",
                    risk_level="low"
                )],
                timeline=[],
                related_changes=[],
                monitoring_suggestions=[],
                timestamp=datetime.now().isoformat()
            )

# MCP Tool Functions
def analyze_network_issue(issue_description: str = "", focus_devices: str = "") -> Dict[str, Any]:
    """
    AI-powered network issue analysis tool for MCP integration
    
    Args:
        issue_description: Description of the network issue to analyze
        focus_devices: Comma-separated list of devices to focus analysis on
        
    Returns:
        Dict containing comprehensive network analysis results
    """
    try:
        # Parse focus devices
        focus_device_list = []
        if focus_devices:
            focus_device_list = [device.strip() for device in focus_devices.split(',')]
        
        # Create analyzer and run analysis
        analyzer = NetworkIssueAnalyzer()
        analysis = analyzer.analyze_network_issue(issue_description, focus_device_list)
        
        # Convert to dictionary for MCP response
        result = asdict(analysis)
        
        return {
            'success': True,
            'analysis': result,
            'message': f"Network analysis completed: {analysis.summary}"
        }
        
    except Exception as e:
        logger.error(f"MCP analyze_network_issue failed: {e}")
        return {
            'success': False,
            'error': str(e),
            'message': f"Network analysis failed: {str(e)}"
        }

if __name__ == "__main__":
    # Test the analyzer
    analyzer = NetworkIssueAnalyzer()
    analysis = analyzer.analyze_network_issue("Testing network analysis system")
    print(json.dumps(asdict(analysis), indent=2))
