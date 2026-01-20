"""
Crash Monitor

This module handles detecting and recording crashes.
It wraps target execution and catches various types of failures.

In real fuzzers like AFL, crash detection is done by:
- Monitoring process exit codes
- Checking for signals like SIGSEGV, SIGABRT
- Watching for timeouts

Since we're fuzzing Python code or HTTP endpoints, we focus on:
- Exceptions
- Timeouts
- Memory issues
"""

import time
import traceback
import hashlib
from dataclasses import dataclass
from typing import Callable, Any, Optional
from pathlib import Path

import psutil


@dataclass
class CrashInfo:
    """
    Information about a crash.
    """
    crash_type: str  # "exception", "timeout", "memory", etc.
    error_message: str
    stack_trace: str = ""
    input_data: bytes = b""
    timestamp: float = 0.0
    
    def __post_init__(self):
        if self.timestamp == 0.0:
            self.timestamp = time.time()
    
    @property
    def crash_hash(self) -> str:
        """
        Generate a hash to identify unique crashes.
        
        We hash the crash type and first 3 lines of stack trace.
        This helps deduplicate crashes that have the same root cause.
        """
        # Get first 3 lines of stack trace for deduplication
        trace_lines = self.stack_trace.split('\n')[:3]
        trace_key = '\n'.join(trace_lines)
        
        hash_input = f"{self.crash_type}:{trace_key}"
        return hashlib.md5(hash_input.encode()).hexdigest()[:12]


class CrashMonitor:
    """
    Monitor for crashes and anomalies.
    
    This class wraps the execution of target functions and catches
    various types of failures that might indicate bugs.
    """
    
    def __init__(
        self,
        timeout: float = 5.0,
        max_memory_mb: int = 500,
        crashes_dir: str = "crashes"
    ):
        """
        Initialize crash monitor.
        
        Args:
            timeout: Maximum execution time before considering it a hang
            max_memory_mb: Maximum memory usage before considering it a bug
            crashes_dir: Directory to save crash information
        """
        self.timeout = timeout
        self.max_memory_mb = max_memory_mb
        self.crashes_dir = Path(crashes_dir)
        self.crashes_dir.mkdir(parents=True, exist_ok=True)
        
        # Track seen crashes for deduplication
        self.seen_crashes = set()
    
    def execute_with_monitoring(
        self,
        func: Callable,
        input_data: bytes,
        *args,
        **kwargs
    ) -> tuple[Any, Optional[CrashInfo]]:
        """
        Execute a function with crash monitoring.
        
        Args:
            func: Function to execute
            input_data: The fuzzed input being tested
            *args, **kwargs: Arguments to pass to func
            
        Returns:
            Tuple of (result, crash_info) where crash_info is None if no crash
        """
        crash_info = None
        result = None
        
        start_time = time.time()
        
        try:
            result = func(input_data, *args, **kwargs)
            
            # Check if execution took too long
            elapsed = time.time() - start_time
            if elapsed > self.timeout:
                crash_info = CrashInfo(
                    crash_type="timeout",
                    error_message=f"Execution took {elapsed:.2f}s (limit: {self.timeout}s)",
                    input_data=input_data,
                )
            
        except MemoryError as e:
            crash_info = CrashInfo(
                crash_type="memory",
                error_message=str(e),
                stack_trace=traceback.format_exc(),
                input_data=input_data,
            )
            
        except RecursionError as e:
            crash_info = CrashInfo(
                crash_type="recursion",
                error_message=str(e),
                stack_trace=traceback.format_exc(),
                input_data=input_data,
            )
            
        except Exception as e:
            crash_info = CrashInfo(
                crash_type="exception",
                error_message=f"{type(e).__name__}: {str(e)}",
                stack_trace=traceback.format_exc(),
                input_data=input_data,
            )
        
        # Save crash if it's new
        if crash_info and crash_info.crash_hash not in self.seen_crashes:
            self._save_crash(crash_info)
            self.seen_crashes.add(crash_info.crash_hash)
        
        return result, crash_info
    
    def _save_crash(self, crash: CrashInfo):
        """
        Save crash information to disk.
        """
        base_name = f"crash_{crash.crash_hash}"
        
        # Save the crashing input
        input_file = self.crashes_dir / f"{base_name}.input"
        input_file.write_bytes(crash.input_data)
        
        # Save crash details
        info_file = self.crashes_dir / f"{base_name}.txt"
        info_file.write_text(
            f"Crash Type: {crash.crash_type}\n"
            f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(crash.timestamp))}\n"
            f"Error: {crash.error_message}\n"
            f"\n--- Stack Trace ---\n"
            f"{crash.stack_trace}\n"
            f"\n--- Input (hex) ---\n"
            f"{crash.input_data.hex()}\n"
        )
        
        print(f"\n[CRASH] New crash found: {crash.crash_hash}")
        print(f"        Type: {crash.crash_type}")
        print(f"        Error: {crash.error_message[:80]}")


def check_memory_usage() -> float:
    """
    Get current process memory usage in MB.
    
    Useful for detecting memory leaks or excessive allocation.
    """
    process = psutil.Process()
    return process.memory_info().rss / (1024 * 1024)
