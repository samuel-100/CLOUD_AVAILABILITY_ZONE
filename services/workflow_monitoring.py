#!/usr/bin/env python3
"""
Workflow Status and Monitoring System

Implements workflow progress tracking, real-time updates, workflow history,
result caching, and failure recovery capabilities for network automation.
"""

import os
import sys
import json
import yaml
import logging
import asyncio
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, asdict
from enum import Enum
import pickle
import hashlib

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

# File paths
WORKFLOW_CACHE_DIR = '/opt/network-automation/CLOUD_AVAILABILITY_ZONE/logs/workflow_cache'
WORKFLOW_HISTORY_FILE = '/opt/network-automation/CLOUD_AVAILABILITY_ZONE/logs/workflow_history.json'
WORKFLOW_STATUS_FILE = '/opt/network-automation/CLOUD_AVAILABILITY_ZONE/logs/workflow_status.json'

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class WorkflowStatus(Enum):
    """Workflow execution status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    RECOVERING = "recovering"

class WorkflowPriority(Enum):
    """Workflow priority levels"""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class WorkflowStep:
    """Individual workflow step definition"""
    step_id: str
    name: str
    description: str
    command: str
    expected_duration: int  # seconds
    timeout: int  # seconds
    retry_count: int = 3
    status: WorkflowStatus = WorkflowStatus.PENDING
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    output: str = ""
    error_message: str = ""
    retry_attempts: int = 0

@dataclass
class WorkflowDefinition:
    """Complete workflow definition"""
    workflow_id: str
    name: str
    description: str
    category: str  # health_check, deployment, troubleshooting, etc.
    priority: WorkflowPriority
    steps: List[WorkflowStep]
    prerequisites: List[str] = None
    rollback_steps: List[WorkflowStep] = None
    estimated_duration: int = 0  # total estimated seconds
    timeout: int = 3600  # total timeout in seconds
    created_by: str = "system"
    created_at: str = ""

@dataclass
class WorkflowExecution:
    """Workflow execution instance"""
    execution_id: str
    workflow_id: str
    status: WorkflowStatus
    current_step: int = 0
    start_time: str = ""
    end_time: str = ""
    progress_percentage: float = 0.0
    result_summary: str = ""
    error_details: str = ""
    recovery_actions: List[str] = None
    execution_context: Dict[str, Any] = None
    cached_result: bool = False

@dataclass
class WorkflowResult:
    """Workflow execution result"""
    execution_id: str
    workflow_id: str
    status: WorkflowStatus
    success: bool
    start_time: str
    end_time: str
    duration: float  # seconds
    steps_completed: int
    total_steps: int
    result_data: Dict[str, Any]
    error_summary: str = ""
    cache_key: str = ""

class WorkflowCache:
    """Workflow result caching system"""
    
    def __init__(self, cache_dir: str = WORKFLOW_CACHE_DIR):
        self.cache_dir = cache_dir
        os.makedirs(cache_dir, exist_ok=True)
        
    def _generate_cache_key(self, workflow_id: str, context: Dict[str, Any]) -> str:
        """Generate cache key for workflow and context"""
        # Create deterministic hash from workflow ID and context
        content = f"{workflow_id}:{json.dumps(context, sort_keys=True)}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def get_cached_result(self, workflow_id: str, context: Dict[str, Any], 
                         max_age_minutes: int = 30) -> Optional[WorkflowResult]:
        """Get cached workflow result if available and fresh"""
        try:
            cache_key = self._generate_cache_key(workflow_id, context)
            cache_file = os.path.join(self.cache_dir, f"{cache_key}.pkl")
            
            if not os.path.exists(cache_file):
                return None
            
            # Check if cache is still fresh
            cache_age = time.time() - os.path.getmtime(cache_file)
            if cache_age > (max_age_minutes * 60):
                logger.info(f"Cache expired for workflow {workflow_id}")
                os.remove(cache_file)
                return None
            
            # Load cached result
            with open(cache_file, 'rb') as f:
                cached_result = pickle.load(f)
                logger.info(f"Using cached result for workflow {workflow_id}")
                return cached_result
                
        except Exception as e:
            logger.warning(f"Failed to load cache for workflow {workflow_id}: {e}")
            return None
    
    def cache_result(self, workflow_id: str, context: Dict[str, Any], 
                    result: WorkflowResult) -> str:
        """Cache workflow result"""
        try:
            cache_key = self._generate_cache_key(workflow_id, context)
            cache_file = os.path.join(self.cache_dir, f"{cache_key}.pkl")
            
            # Update result with cache key
            result.cache_key = cache_key
            
            # Save to cache
            with open(cache_file, 'wb') as f:
                pickle.dump(result, f)
            
            logger.info(f"Cached result for workflow {workflow_id} with key {cache_key}")
            return cache_key
            
        except Exception as e:
            logger.error(f"Failed to cache result for workflow {workflow_id}: {e}")
            return ""
    
    def clear_cache(self, workflow_id: str = None):
        """Clear cache for specific workflow or all workflows"""
        try:
            if workflow_id:
                # Clear specific workflow cache
                pattern = f"*{workflow_id}*"
                for file in os.listdir(self.cache_dir):
                    if workflow_id in file:
                        os.remove(os.path.join(self.cache_dir, file))
                logger.info(f"Cleared cache for workflow {workflow_id}")
            else:
                # Clear all cache
                for file in os.listdir(self.cache_dir):
                    if file.endswith('.pkl'):
                        os.remove(os.path.join(self.cache_dir, file))
                logger.info("Cleared all workflow cache")
                
        except Exception as e:
            logger.error(f"Failed to clear cache: {e}")

class WorkflowHistory:
    """Workflow execution history management"""
    
    def __init__(self, history_file: str = WORKFLOW_HISTORY_FILE):
        self.history_file = history_file
        self.history = self._load_history()
        
    def _load_history(self) -> List[Dict[str, Any]]:
        """Load workflow history from file"""
        try:
            if os.path.exists(self.history_file):
                with open(self.history_file, 'r') as f:
                    return json.load(f)
            return []
        except Exception as e:
            logger.error(f"Failed to load workflow history: {e}")
            return []
    
    def _save_history(self):
        """Save workflow history to file"""
        try:
            with open(self.history_file, 'w') as f:
                json.dump(self.history, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save workflow history: {e}")
    
    def add_execution(self, execution: WorkflowExecution, result: WorkflowResult):
        """Add workflow execution to history"""
        try:
            history_entry = {
                'execution_id': execution.execution_id,
                'workflow_id': execution.workflow_id,
                'status': result.status.value,
                'success': result.success,
                'start_time': result.start_time,
                'end_time': result.end_time,
                'duration': result.duration,
                'steps_completed': result.steps_completed,
                'total_steps': result.total_steps,
                'result_summary': execution.result_summary,
                'error_summary': result.error_summary,
                'cached_result': execution.cached_result,
                'execution_context': execution.execution_context or {}
            }
            
            self.history.append(history_entry)
            
            # Keep only last 1000 entries
            if len(self.history) > 1000:
                self.history = self.history[-1000:]
            
            self._save_history()
            logger.info(f"Added execution {execution.execution_id} to history")
            
        except Exception as e:
            logger.error(f"Failed to add execution to history: {e}")
    
    def get_workflow_history(self, workflow_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Get execution history for specific workflow"""
        workflow_history = [
            entry for entry in self.history 
            if entry['workflow_id'] == workflow_id
        ]
        return sorted(workflow_history, key=lambda x: x['start_time'], reverse=True)[:limit]
    
    def get_recent_executions(self, hours: int = 24, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent workflow executions"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        cutoff_str = cutoff_time.isoformat()
        
        recent_executions = [
            entry for entry in self.history 
            if entry['start_time'] >= cutoff_str
        ]
        return sorted(recent_executions, key=lambda x: x['start_time'], reverse=True)[:limit]
    
    def get_failure_statistics(self, workflow_id: str = None, days: int = 7) -> Dict[str, Any]:
        """Get failure statistics for workflows"""
        cutoff_time = datetime.now() - timedelta(days=days)
        cutoff_str = cutoff_time.isoformat()
        
        relevant_executions = [
            entry for entry in self.history 
            if entry['start_time'] >= cutoff_str and 
            (workflow_id is None or entry['workflow_id'] == workflow_id)
        ]
        
        total_executions = len(relevant_executions)
        failed_executions = len([e for e in relevant_executions if not e['success']])
        
        return {
            'total_executions': total_executions,
            'failed_executions': failed_executions,
            'success_rate': (total_executions - failed_executions) / total_executions if total_executions > 0 else 0,
            'average_duration': sum(e['duration'] for e in relevant_executions) / total_executions if total_executions > 0 else 0,
            'period_days': days
        }

class WorkflowRecovery:
    """Workflow failure recovery system"""
    
    def __init__(self):
        self.recovery_strategies = {
            'retry': self._retry_strategy,
            'rollback': self._rollback_strategy,
            'skip': self._skip_strategy,
            'manual': self._manual_intervention_strategy
        }
    
    def _retry_strategy(self, execution: WorkflowExecution, step: WorkflowStep) -> bool:
        """Retry failed step"""
        if step.retry_attempts < step.retry_count:
            step.retry_attempts += 1
            step.status = WorkflowStatus.PENDING
            logger.info(f"Retrying step {step.step_id}, attempt {step.retry_attempts}")
            return True
        return False
    
    def _rollback_strategy(self, execution: WorkflowExecution, workflow_def: WorkflowDefinition) -> bool:
        """Execute rollback steps"""
        if workflow_def.rollback_steps:
            logger.info(f"Executing rollback for workflow {workflow_def.workflow_id}")
            # TODO: Implement rollback execution
            return True
        return False
    
    def _skip_strategy(self, execution: WorkflowExecution, step: WorkflowStep) -> bool:
        """Skip failed step and continue"""
        step.status = WorkflowStatus.COMPLETED
        step.error_message = "Step skipped due to failure"
        logger.warning(f"Skipping failed step {step.step_id}")
        return True
    
    def _manual_intervention_strategy(self, execution: WorkflowExecution, step: WorkflowStep) -> bool:
        """Mark for manual intervention"""
        execution.status = WorkflowStatus.FAILED
        execution.error_details = f"Manual intervention required for step {step.step_id}"
        logger.error(f"Manual intervention required for step {step.step_id}")
        return False
    
    def attempt_recovery(self, execution: WorkflowExecution, workflow_def: WorkflowDefinition, 
                        failed_step: WorkflowStep, strategy: str = 'retry') -> bool:
        """Attempt to recover from workflow failure"""
        try:
            execution.status = WorkflowStatus.RECOVERING
            
            if strategy in self.recovery_strategies:
                recovery_func = self.recovery_strategies[strategy]
                success = recovery_func(execution, failed_step)
                
                if success:
                    logger.info(f"Recovery successful using strategy: {strategy}")
                    return True
                else:
                    logger.error(f"Recovery failed using strategy: {strategy}")
                    return False
            else:
                logger.error(f"Unknown recovery strategy: {strategy}")
                return False
                
        except Exception as e:
            logger.error(f"Recovery attempt failed: {e}")
            return False

class WorkflowMonitor:
    """Real-time workflow monitoring and progress tracking"""
    
    def __init__(self):
        self.active_workflows: Dict[str, WorkflowExecution] = {}
        self.status_callbacks: List[Callable] = []
        self.cache = WorkflowCache()
        self.history = WorkflowHistory()
        self.recovery = WorkflowRecovery()
        self._monitoring_thread = None
        self._stop_monitoring = False
        
    def register_status_callback(self, callback: Callable):
        """Register callback for workflow status updates"""
        self.status_callbacks.append(callback)
    
    def _notify_status_change(self, execution: WorkflowExecution):
        """Notify all registered callbacks of status change"""
        for callback in self.status_callbacks:
            try:
                callback(execution)
            except Exception as e:
                logger.error(f"Status callback failed: {e}")
    
    def start_monitoring(self):
        """Start background monitoring thread"""
        if self._monitoring_thread and self._monitoring_thread.is_alive():
            return
        
        self._stop_monitoring = False
        self._monitoring_thread = threading.Thread(target=self._monitoring_loop)
        self._monitoring_thread.daemon = True
        self._monitoring_thread.start()
        logger.info("Workflow monitoring started")
    
    def stop_monitoring(self):
        """Stop background monitoring"""
        self._stop_monitoring = True
        if self._monitoring_thread:
            self._monitoring_thread.join()
        logger.info("Workflow monitoring stopped")
    
    def _monitoring_loop(self):
        """Background monitoring loop"""
        while not self._stop_monitoring:
            try:
                # Check for timeouts
                current_time = datetime.now()
                for execution_id, execution in list(self.active_workflows.items()):
                    if execution.status == WorkflowStatus.RUNNING:
                        start_time = datetime.fromisoformat(execution.start_time.replace('Z', '+00:00'))
                        elapsed = (current_time - start_time).total_seconds()
                        
                        # Check if workflow has timed out
                        workflow_def = self._get_workflow_definition(execution.workflow_id)
                        if workflow_def and elapsed > workflow_def.timeout:
                            logger.warning(f"Workflow {execution_id} timed out")
                            execution.status = WorkflowStatus.FAILED
                            execution.error_details = "Workflow timed out"
                            self._notify_status_change(execution)
                
                time.sleep(5)  # Check every 5 seconds
                
            except Exception as e:
                logger.error(f"Monitoring loop error: {e}")
                time.sleep(10)  # Wait longer on error
    
    def _get_workflow_definition(self, workflow_id: str) -> Optional[WorkflowDefinition]:
        """Get workflow definition by ID"""
        # TODO: Implement workflow definition loading
        return None
    
    def start_workflow(self, workflow_def: WorkflowDefinition, 
                      context: Dict[str, Any] = None) -> WorkflowExecution:
        """Start workflow execution with monitoring"""
        execution_id = f"{workflow_def.workflow_id}-{int(time.time())}"
        
        # Check for cached result
        cached_result = None
        if context:
            cached_result = self.cache.get_cached_result(workflow_def.workflow_id, context)
        
        execution = WorkflowExecution(
            execution_id=execution_id,
            workflow_id=workflow_def.workflow_id,
            status=WorkflowStatus.RUNNING,
            start_time=datetime.now().isoformat(),
            execution_context=context or {},
            cached_result=cached_result is not None
        )
        
        if cached_result:
            # Use cached result
            execution.status = WorkflowStatus.COMPLETED
            execution.end_time = datetime.now().isoformat()
            execution.progress_percentage = 100.0
            execution.result_summary = "Used cached result"
        else:
            # Start fresh execution
            self.active_workflows[execution_id] = execution
            
        self._notify_status_change(execution)
        logger.info(f"Started workflow execution {execution_id}")
        return execution
    
    def update_progress(self, execution_id: str, step_index: int, 
                       step_status: WorkflowStatus, output: str = "", 
                       error: str = ""):
        """Update workflow progress"""
        if execution_id not in self.active_workflows:
            return
        
        execution = self.active_workflows[execution_id]
        execution.current_step = step_index
        
        # Calculate progress percentage
        workflow_def = self._get_workflow_definition(execution.workflow_id)
        if workflow_def:
            total_steps = len(workflow_def.steps)
            execution.progress_percentage = (step_index / total_steps) * 100
        
        self._notify_status_change(execution)
    
    def complete_workflow(self, execution_id: str, success: bool, 
                         result_data: Dict[str, Any] = None, 
                         error_summary: str = ""):
        """Complete workflow execution"""
        if execution_id not in self.active_workflows:
            return
        
        execution = self.active_workflows[execution_id]
        execution.status = WorkflowStatus.COMPLETED if success else WorkflowStatus.FAILED
        execution.end_time = datetime.now().isoformat()
        execution.progress_percentage = 100.0
        execution.error_details = error_summary
        
        # Create result
        start_time = datetime.fromisoformat(execution.start_time.replace('Z', '+00:00'))
        end_time = datetime.fromisoformat(execution.end_time.replace('Z', '+00:00'))
        duration = (end_time - start_time).total_seconds()
        
        result = WorkflowResult(
            execution_id=execution_id,
            workflow_id=execution.workflow_id,
            status=execution.status,
            success=success,
            start_time=execution.start_time,
            end_time=execution.end_time,
            duration=duration,
            steps_completed=execution.current_step,
            total_steps=0,  # TODO: Get from workflow definition
            result_data=result_data or {},
            error_summary=error_summary
        )
        
        # Cache successful results
        if success and execution.execution_context:
            self.cache.cache_result(execution.workflow_id, execution.execution_context, result)
        
        # Add to history
        self.history.add_execution(execution, result)
        
        # Remove from active workflows
        del self.active_workflows[execution_id]
        
        self._notify_status_change(execution)
        logger.info(f"Completed workflow execution {execution_id}: {'SUCCESS' if success else 'FAILED'}")
    
    def get_active_workflows(self) -> List[WorkflowExecution]:
        """Get all currently active workflows"""
        return list(self.active_workflows.values())
    
    def get_workflow_status(self, execution_id: str) -> Optional[WorkflowExecution]:
        """Get status of specific workflow execution"""
        return self.active_workflows.get(execution_id)
    
    def cancel_workflow(self, execution_id: str) -> bool:
        """Cancel running workflow"""
        if execution_id in self.active_workflows:
            execution = self.active_workflows[execution_id]
            execution.status = WorkflowStatus.CANCELLED
            execution.end_time = datetime.now().isoformat()
            
            # Remove from active workflows
            del self.active_workflows[execution_id]
            
            self._notify_status_change(execution)
            logger.info(f"Cancelled workflow execution {execution_id}")
            return True
        return False

# Global workflow monitor instance
workflow_monitor = WorkflowMonitor()

# MCP Tool Functions
def get_workflow_status(execution_id: str = "") -> Dict[str, Any]:
    """
    Get workflow execution status and progress
    
    Args:
        execution_id: Specific execution ID to check (optional)
        
    Returns:
        Dict containing workflow status information
    """
    try:
        if execution_id:
            # Get specific workflow status
            execution = workflow_monitor.get_workflow_status(execution_id)
            if execution:
                return {
                    'success': True,
                    'execution': asdict(execution),
                    'message': f"Workflow {execution_id} status: {execution.status.value}"
                }
            else:
                return {
                    'success': False,
                    'error': 'Execution not found',
                    'message': f"Workflow execution {execution_id} not found"
                }
        else:
            # Get all active workflows
            active_workflows = workflow_monitor.get_active_workflows()
            return {
                'success': True,
                'active_workflows': [asdict(w) for w in active_workflows],
                'count': len(active_workflows),
                'message': f"Found {len(active_workflows)} active workflows"
            }
            
    except Exception as e:
        logger.error(f"Failed to get workflow status: {e}")
        return {
            'success': False,
            'error': str(e),
            'message': f"Failed to get workflow status: {str(e)}"
        }

def get_workflow_history(workflow_id: str = "", limit: int = 50) -> Dict[str, Any]:
    """
    Get workflow execution history
    
    Args:
        workflow_id: Specific workflow ID to get history for (optional)
        limit: Maximum number of history entries to return
        
    Returns:
        Dict containing workflow history
    """
    try:
        history = workflow_monitor.history
        
        if workflow_id:
            # Get history for specific workflow
            workflow_history = history.get_workflow_history(workflow_id, limit)
            return {
                'success': True,
                'workflow_id': workflow_id,
                'history': workflow_history,
                'count': len(workflow_history),
                'message': f"Retrieved {len(workflow_history)} history entries for workflow {workflow_id}"
            }
        else:
            # Get recent executions across all workflows
            recent_executions = history.get_recent_executions(limit=limit)
            return {
                'success': True,
                'recent_executions': recent_executions,
                'count': len(recent_executions),
                'message': f"Retrieved {len(recent_executions)} recent workflow executions"
            }
            
    except Exception as e:
        logger.error(f"Failed to get workflow history: {e}")
        return {
            'success': False,
            'error': str(e),
            'message': f"Failed to get workflow history: {str(e)}"
        }

def clear_workflow_cache(workflow_id: str = "") -> Dict[str, Any]:
    """
    Clear workflow result cache
    
    Args:
        workflow_id: Specific workflow ID to clear cache for (optional)
        
    Returns:
        Dict containing operation result
    """
    try:
        cache = workflow_monitor.cache
        
        if workflow_id:
            cache.clear_cache(workflow_id)
            message = f"Cleared cache for workflow {workflow_id}"
        else:
            cache.clear_cache()
            message = "Cleared all workflow cache"
        
        return {
            'success': True,
            'message': message
        }
        
    except Exception as e:
        logger.error(f"Failed to clear workflow cache: {e}")
        return {
            'success': False,
            'error': str(e),
            'message': f"Failed to clear workflow cache: {str(e)}"
        }

def get_workflow_statistics(workflow_id: str = "", days: int = 7) -> Dict[str, Any]:
    """
    Get workflow execution statistics
    
    Args:
        workflow_id: Specific workflow ID to get statistics for (optional)
        days: Number of days to include in statistics
        
    Returns:
        Dict containing workflow statistics
    """
    try:
        history = workflow_monitor.history
        stats = history.get_failure_statistics(workflow_id, days)
        
        return {
            'success': True,
            'workflow_id': workflow_id or 'all',
            'statistics': stats,
            'message': f"Retrieved statistics for {days} days"
        }
        
    except Exception as e:
        logger.error(f"Failed to get workflow statistics: {e}")
        return {
            'success': False,
            'error': str(e),
            'message': f"Failed to get workflow statistics: {str(e)}"
        }

if __name__ == "__main__":
    # Test the workflow monitor
    workflow_monitor.start_monitoring()
    print("Workflow monitoring system initialized")
    time.sleep(2)
    workflow_monitor.stop_monitoring()
