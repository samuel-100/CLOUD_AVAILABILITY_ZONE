#!/usr/bin/env python3
"""
Enhanced Error Handling and Recovery Service

Provides comprehensive error classification, retry logic, rollback capabilities,
and recovery mechanisms for network automation operations.
"""

import os
import sys
import json
import time
import logging
import traceback
import asyncio
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, asdict
from typing import Dict, List, Any, Optional, Callable, Union
from functools import wraps
import sqlite3
import yaml

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ErrorSeverity(Enum):
    """Error severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ErrorCategory(Enum):
    """Error categories for classification"""
    NETWORK = "network"
    AUTHENTICATION = "authentication"
    CONFIGURATION = "configuration"
    DEVICE = "device"
    PROTOCOL = "protocol"
    TIMEOUT = "timeout"
    PERMISSION = "permission"
    VALIDATION = "validation"
    RESOURCE = "resource"
    UNKNOWN = "unknown"

class RecoveryAction(Enum):
    """Available recovery actions"""
    RETRY = "retry"
    ROLLBACK = "rollback"
    SKIP = "skip"
    ESCALATE = "escalate"
    ABORT = "abort"
    MANUAL = "manual"

@dataclass
class ErrorContext:
    """Context information for error analysis"""
    operation: str
    device: Optional[str] = None
    user: Optional[str] = None
    timestamp: Optional[datetime] = None
    session_id: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

@dataclass
class ErrorInfo:
    """Comprehensive error information"""
    error_id: str
    category: ErrorCategory
    severity: ErrorSeverity
    message: str
    context: ErrorContext
    exception_type: str
    traceback_info: str
    timestamp: datetime
    recovery_action: Optional[RecoveryAction] = None
    retry_count: int = 0
    resolved: bool = False

@dataclass
class RetryPolicy:
    """Retry policy configuration"""
    max_retries: int = 3
    base_delay: float = 1.0
    max_delay: float = 60.0
    exponential_backoff: bool = True
    jitter: bool = True
    retryable_errors: List[ErrorCategory] = None

@dataclass
class RollbackStep:
    """Individual rollback step"""
    step_id: str
    description: str
    action: Callable
    args: tuple = ()
    kwargs: dict = None
    priority: int = 1

class ErrorHandlingService:
    """Enhanced error handling and recovery service"""
    
    def __init__(self, config_file: str = "config/error_handling.yaml"):
        """Initialize the error handling service"""
        self.config_file = config_file
        self.db_file = "logs/error_handling.db"
        self.error_patterns = {}
        self.retry_policies = {}
        self.rollback_stack = []
        self.recovery_strategies = {}
        
        # Initialize components
        self._setup_database()
        self._load_configuration()
        self._setup_error_patterns()
        
        logger.info("Error handling service initialized")
    
    def _setup_database(self):
        """Set up SQLite database for error tracking"""
        os.makedirs(os.path.dirname(self.db_file), exist_ok=True)
        
        with sqlite3.connect(self.db_file) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS errors (
                    error_id TEXT PRIMARY KEY,
                    category TEXT,
                    severity TEXT,
                    message TEXT,
                    context TEXT,
                    exception_type TEXT,
                    traceback_info TEXT,
                    timestamp TEXT,
                    recovery_action TEXT,
                    retry_count INTEGER,
                    resolved BOOLEAN
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS recovery_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    error_id TEXT,
                    action TEXT,
                    result TEXT,
                    timestamp TEXT,
                    FOREIGN KEY (error_id) REFERENCES errors (error_id)
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS rollback_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    operation_id TEXT,
                    step_id TEXT,
                    description TEXT,
                    status TEXT,
                    timestamp TEXT
                )
            """)
    
    def _load_configuration(self):
        """Load error handling configuration"""
        if os.path.exists(self.config_file):
            with open(self.config_file, 'r') as f:
                config = yaml.safe_load(f)
        else:
            config = self._generate_default_config()
            self._save_configuration(config)
        
        # Load retry policies
        for policy_name, policy_data in config.get('retry_policies', {}).items():
            self.retry_policies[policy_name] = RetryPolicy(**policy_data)
        
        # Load recovery strategies
        self.recovery_strategies = config.get('recovery_strategies', {})
        
        logger.info(f"Loaded {len(self.retry_policies)} retry policies")
        logger.info(f"Loaded {len(self.recovery_strategies)} recovery strategies")
    
    def _generate_default_config(self) -> Dict[str, Any]:
        """Generate default error handling configuration"""
        return {
            "retry_policies": {
                "network_operations": {
                    "max_retries": 5,
                    "base_delay": 2.0,
                    "max_delay": 120.0,
                    "exponential_backoff": True,
                    "jitter": True,
                    "retryable_errors": ["network", "timeout", "device"]
                },
                "authentication": {
                    "max_retries": 3,
                    "base_delay": 1.0,
                    "max_delay": 30.0,
                    "exponential_backoff": True,
                    "jitter": False,
                    "retryable_errors": ["authentication", "timeout"]
                },
                "configuration": {
                    "max_retries": 2,
                    "base_delay": 5.0,
                    "max_delay": 60.0,
                    "exponential_backoff": True,
                    "jitter": True,
                    "retryable_errors": ["configuration", "validation"]
                },
                "default": {
                    "max_retries": 3,
                    "base_delay": 1.0,
                    "max_delay": 30.0,
                    "exponential_backoff": True,
                    "jitter": True,
                    "retryable_errors": ["network", "timeout"]
                }
            },
            "recovery_strategies": {
                "device_unreachable": {
                    "actions": ["retry", "try_backup_connection", "escalate"],
                    "timeout": 300
                },
                "authentication_failure": {
                    "actions": ["retry_with_backup_creds", "escalate"],
                    "timeout": 60
                },
                "configuration_error": {
                    "actions": ["rollback", "validate_config", "manual_intervention"],
                    "timeout": 180
                },
                "protocol_error": {
                    "actions": ["retry", "switch_protocol", "escalate"],
                    "timeout": 120
                }
            }
        }
    
    def _save_configuration(self, config: Dict[str, Any]):
        """Save configuration to file"""
        os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
        with open(self.config_file, 'w') as f:
            yaml.dump(config, f, default_flow_style=False)
    
    def _setup_error_patterns(self):
        """Set up error pattern recognition"""
        self.error_patterns = {
            # Network errors
            r"connection.*refused": ErrorCategory.NETWORK,
            r"timeout": ErrorCategory.TIMEOUT,
            r"unreachable": ErrorCategory.NETWORK,
            r"no route to host": ErrorCategory.NETWORK,
            
            # Authentication errors
            r"authentication.*failed": ErrorCategory.AUTHENTICATION,
            r"invalid.*credentials": ErrorCategory.AUTHENTICATION,
            r"access.*denied": ErrorCategory.PERMISSION,
            r"permission.*denied": ErrorCategory.PERMISSION,
            
            # Configuration errors
            r"invalid.*configuration": ErrorCategory.CONFIGURATION,
            r"syntax.*error": ErrorCategory.VALIDATION,
            r"command.*not.*found": ErrorCategory.CONFIGURATION,
            
            # Device errors
            r"device.*not.*found": ErrorCategory.DEVICE,
            r"device.*busy": ErrorCategory.DEVICE,
            r"device.*error": ErrorCategory.DEVICE,
            
            # Protocol errors
            r"protocol.*error": ErrorCategory.PROTOCOL,
            r"ssh.*error": ErrorCategory.PROTOCOL,
            r"snmp.*error": ErrorCategory.PROTOCOL,
        }
    
    def classify_error(self, exception: Exception, context: ErrorContext) -> ErrorInfo:
        """Classify an error and determine its category and severity"""
        import re
        import uuid
        
        error_message = str(exception).lower()
        exception_type = type(exception).__name__
        
        # Determine category
        category = ErrorCategory.UNKNOWN
        for pattern, cat in self.error_patterns.items():
            if re.search(pattern, error_message):
                category = cat
                break
        
        # Determine severity based on category and context
        severity = self._determine_severity(category, exception_type, context)
        
        # Create error info
        error_info = ErrorInfo(
            error_id=str(uuid.uuid4()),
            category=category,
            severity=severity,
            message=str(exception),
            context=context,
            exception_type=exception_type,
            traceback_info=traceback.format_exc(),
            timestamp=datetime.now()
        )
        
        # Store in database
        self._store_error(error_info)
        
        logger.error(f"Error classified: {error_info.error_id} - {category.value} - {severity.value}")
        return error_info
    
    def _determine_severity(self, category: ErrorCategory, exception_type: str, context: ErrorContext) -> ErrorSeverity:
        """Determine error severity based on various factors"""
        # Critical errors
        if category in [ErrorCategory.AUTHENTICATION] and context.operation in ["production_deploy"]:
            return ErrorSeverity.CRITICAL
        
        if exception_type in ["SystemExit", "KeyboardInterrupt"]:
            return ErrorSeverity.CRITICAL
        
        # High severity errors
        if category in [ErrorCategory.CONFIGURATION, ErrorCategory.DEVICE]:
            return ErrorSeverity.HIGH
        
        if context.operation in ["config_push", "firmware_upgrade"]:
            return ErrorSeverity.HIGH
        
        # Medium severity errors
        if category in [ErrorCategory.NETWORK, ErrorCategory.PROTOCOL]:
            return ErrorSeverity.MEDIUM
        
        # Low severity errors (default)
        return ErrorSeverity.LOW
    
    def _store_error(self, error_info: ErrorInfo):
        """Store error information in database"""
        with sqlite3.connect(self.db_file) as conn:
            conn.execute("""
                INSERT INTO errors VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                error_info.error_id,
                error_info.category.value,
                error_info.severity.value,
                error_info.message,
                json.dumps(asdict(error_info.context), default=str),
                error_info.exception_type,
                error_info.traceback_info,
                error_info.timestamp.isoformat(),
                error_info.recovery_action.value if error_info.recovery_action else None,
                error_info.retry_count,
                error_info.resolved
            ))
    
    def get_retry_policy(self, operation_type: str) -> RetryPolicy:
        """Get retry policy for operation type"""
        return self.retry_policies.get(operation_type, self.retry_policies.get("default"))
    
    def should_retry(self, error_info: ErrorInfo, policy: RetryPolicy) -> bool:
        """Determine if an error should be retried"""
        if error_info.retry_count >= policy.max_retries:
            return False
        
        if policy.retryable_errors and error_info.category.value not in policy.retryable_errors:
            return False
        
        if error_info.severity == ErrorSeverity.CRITICAL:
            return False
        
        return True
    
    def calculate_retry_delay(self, retry_count: int, policy: RetryPolicy) -> float:
        """Calculate delay before retry"""
        import random
        
        if policy.exponential_backoff:
            delay = policy.base_delay * (2 ** retry_count)
        else:
            delay = policy.base_delay
        
        delay = min(delay, policy.max_delay)
        
        if policy.jitter:
            delay *= (0.5 + random.random())
        
        return delay
    
    def add_rollback_step(self, step: RollbackStep):
        """Add a step to the rollback stack"""
        self.rollback_stack.append(step)
        logger.debug(f"Added rollback step: {step.step_id}")
    
    def execute_rollback(self, operation_id: str, steps: List[RollbackStep] = None) -> Dict[str, Any]:
        """Execute rollback steps"""
        if steps is None:
            steps = self.rollback_stack
        
        rollback_results = []
        
        # Execute steps in reverse order (LIFO)
        for step in reversed(sorted(steps, key=lambda x: x.priority)):
            try:
                logger.info(f"Executing rollback step: {step.description}")
                
                kwargs = step.kwargs or {}
                result = step.action(*step.args, **kwargs)
                
                rollback_results.append({
                    "step_id": step.step_id,
                    "status": "success",
                    "result": str(result)
                })
                
                # Log to database
                self._log_rollback_step(operation_id, step, "success")
                
            except Exception as e:
                logger.error(f"Rollback step failed: {step.step_id} - {e}")
                
                rollback_results.append({
                    "step_id": step.step_id,
                    "status": "failed",
                    "error": str(e)
                })
                
                # Log to database
                self._log_rollback_step(operation_id, step, f"failed: {e}")
        
        # Clear rollback stack after execution
        self.rollback_stack.clear()
        
        return {
            "operation_id": operation_id,
            "rollback_results": rollback_results,
            "timestamp": datetime.now().isoformat()
        }
    
    def _log_rollback_step(self, operation_id: str, step: RollbackStep, status: str):
        """Log rollback step to database"""
        with sqlite3.connect(self.db_file) as conn:
            conn.execute("""
                INSERT INTO rollback_history (operation_id, step_id, description, status, timestamp)
                VALUES (?, ?, ?, ?, ?)
            """, (operation_id, step.step_id, step.description, status, datetime.now().isoformat()))
    
    def recover_from_error(self, error_info: ErrorInfo) -> Dict[str, Any]:
        """Attempt to recover from an error"""
        strategy_key = f"{error_info.category.value}_error"
        strategy = self.recovery_strategies.get(strategy_key, {})
        
        if not strategy:
            logger.warning(f"No recovery strategy found for {error_info.category.value}")
            return {"success": False, "reason": "no_strategy"}
        
        recovery_actions = strategy.get("actions", [])
        timeout = strategy.get("timeout", 300)
        
        for action in recovery_actions:
            try:
                logger.info(f"Attempting recovery action: {action}")
                
                if action == "retry":
                    return {"success": True, "action": "retry", "delay": 5}
                elif action == "rollback":
                    return {"success": True, "action": "rollback"}
                elif action == "escalate":
                    return {"success": True, "action": "escalate", "urgency": "high"}
                else:
                    logger.warning(f"Unknown recovery action: {action}")
                    
            except Exception as e:
                logger.error(f"Recovery action {action} failed: {e}")
                continue
        
        return {"success": False, "reason": "all_actions_failed"}
    
    def get_error_statistics(self, time_range: timedelta = timedelta(hours=24)) -> Dict[str, Any]:
        """Get error statistics for the specified time range"""
        since = datetime.now() - time_range
        
        with sqlite3.connect(self.db_file) as conn:
            # Total errors
            total_result = conn.execute(
                "SELECT COUNT(*) FROM errors WHERE timestamp > ?",
                (since.isoformat(),)
            ).fetchone()
            
            # Errors by category
            category_result = conn.execute("""
                SELECT category, COUNT(*) 
                FROM errors 
                WHERE timestamp > ? 
                GROUP BY category
            """, (since.isoformat(),)).fetchall()
            
            # Errors by severity
            severity_result = conn.execute("""
                SELECT severity, COUNT(*) 
                FROM errors 
                WHERE timestamp > ? 
                GROUP BY severity
            """, (since.isoformat(),)).fetchall()
            
            # Resolution rate
            resolved_result = conn.execute("""
                SELECT resolved, COUNT(*) 
                FROM errors 
                WHERE timestamp > ? 
                GROUP BY resolved
            """, (since.isoformat(),)).fetchall()
        
        return {
            "time_range": str(time_range),
            "total_errors": total_result[0] if total_result else 0,
            "by_category": dict(category_result),
            "by_severity": dict(severity_result),
            "resolution_rate": dict(resolved_result),
            "timestamp": datetime.now().isoformat()
        }


def error_handler(operation_type: str = "default", context: Dict[str, Any] = None):
    """Decorator for automatic error handling"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            service = ErrorHandlingService()
            
            error_context = ErrorContext(
                operation=func.__name__,
                timestamp=datetime.now(),
                metadata=context or {}
            )
            
            retry_policy = service.get_retry_policy(operation_type)
            
            for attempt in range(retry_policy.max_retries + 1):
                try:
                    return func(*args, **kwargs)
                    
                except Exception as e:
                    error_info = service.classify_error(e, error_context)
                    error_info.retry_count = attempt
                    
                    if attempt < retry_policy.max_retries and service.should_retry(error_info, retry_policy):
                        delay = service.calculate_retry_delay(attempt, retry_policy)
                        logger.info(f"Retrying {func.__name__} in {delay:.2f}s (attempt {attempt + 1})")
                        time.sleep(delay)
                        continue
                    else:
                        # Attempt recovery
                        recovery_result = service.recover_from_error(error_info)
                        if recovery_result.get("success") and recovery_result.get("action") == "retry":
                            continue
                        
                        # Re-raise the exception if all retries failed
                        raise
            
        return wrapper
    return decorator


def rollback_on_error(operation_id: str):
    """Decorator to automatically rollback on error"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            service = ErrorHandlingService()
            
            try:
                return func(*args, **kwargs)
            except Exception as e:
                logger.error(f"Error in {func.__name__}, executing rollback: {e}")
                rollback_result = service.execute_rollback(operation_id)
                logger.info(f"Rollback completed: {rollback_result}")
                raise
        
        return wrapper
    return decorator


# MCP Tools for error handling
def handle_error(error_message: str, operation: str, device: str = None) -> Dict[str, Any]:
    """MCP tool to handle and classify errors"""
    try:
        service = ErrorHandlingService()
        
        # Create a mock exception for classification
        class MockException(Exception):
            pass
        
        exception = MockException(error_message)
        context = ErrorContext(operation=operation, device=device, timestamp=datetime.now())
        
        error_info = service.classify_error(exception, context)
        recovery_result = service.recover_from_error(error_info)
        
        return {
            "success": True,
            "error_id": error_info.error_id,
            "category": error_info.category.value,
            "severity": error_info.severity.value,
            "recovery_action": recovery_result.get("action"),
            "recommendation": recovery_result
        }
        
    except Exception as e:
        return {"success": False, "error": str(e)}


def get_error_statistics() -> Dict[str, Any]:
    """MCP tool to get error statistics"""
    try:
        service = ErrorHandlingService()
        stats = service.get_error_statistics()
        return {"success": True, "statistics": stats}
    except Exception as e:
        return {"success": False, "error": str(e)}


def execute_rollback_operation(operation_id: str) -> Dict[str, Any]:
    """MCP tool to execute rollback for an operation"""
    try:
        service = ErrorHandlingService()
        result = service.execute_rollback(operation_id)
        return {"success": True, "rollback_result": result}
    except Exception as e:
        return {"success": False, "error": str(e)}


if __name__ == "__main__":
    # Test the error handling service
    service = ErrorHandlingService()
    
    print("=== Error Handling Service Test ===")
    
    # Test error classification
    try:
        raise ConnectionError("Connection timeout to device 192.168.100.11")
    except Exception as e:
        context = ErrorContext(operation="device_connect", device="SPINE1")
        error_info = service.classify_error(e, context)
        print(f"Error classified: {error_info.category.value} - {error_info.severity.value}")
    
    # Test retry policy
    policy = service.get_retry_policy("network_operations")
    print(f"Network retry policy: {policy.max_retries} retries, {policy.base_delay}s base delay")
    
    # Test statistics
    stats = service.get_error_statistics()
    print(f"Error statistics: {stats}")
    
    print("Error handling service test completed!")
