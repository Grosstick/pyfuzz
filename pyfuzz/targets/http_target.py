"""
HTTP Target for API fuzzing

This module lets us fuzz HTTP APIs by sending mutated requests.
It's useful for finding bugs in REST APIs, web applications, etc.

Example usage:
    target = HttpTarget("http://localhost:5000/api/parse")
    result = target.run(b'{"malformed": json}')
"""

import time
import requests
from dataclasses import dataclass
from typing import Dict, Optional
from urllib.parse import urljoin

import sys
sys.path.append('..')
from pyfuzz.core.engine import FuzzResult


@dataclass
class HttpTargetConfig:
    """
    Configuration for HTTP fuzzing target.
    """
    url: str
    method: str = "POST"
    headers: Dict[str, str] = None
    timeout: float = 5.0
    content_type: str = "application/json"
    
    def __post_init__(self):
        if self.headers is None:
            self.headers = {}
        

        if "Content-Type" not in self.headers:
            self.headers["Content-Type"] = self.content_type


class HttpTarget:
    """
    Fuzz an HTTP endpoint.
    
    This sends mutated data to an HTTP endpoint and checks for:
    - Server errors (500, etc.)
    - Timeouts (possible infinite loop or DoS)
    - Connection errors (possible crash)
    - Unusual response patterns
    """
    
    def __init__(self, config: HttpTargetConfig):
        """
        Initialize HTTP target.
        
        Args:
            config: Target configuration
        """
        self.config = config
        self.session = requests.Session()
        

        self.response_sizes = []
    
    def run(self, data: bytes) -> FuzzResult:
        """
        Send fuzzed data to the target.
        
        Args:
            data: Fuzzed input data to send
            
        Returns:
            FuzzResult with crash info if found
        """
        result = FuzzResult(input_data=data)
        start_time = time.time()
        
        try:

            if self.config.method.upper() == "POST":
                response = self.session.post(
                    self.config.url,
                    data=data,
                    headers=self.config.headers,
                    timeout=self.config.timeout,
                )
            elif self.config.method.upper() == "GET":
                response = self.session.get(
                    self.config.url,
                    params={"data": data.decode(errors="ignore")},
                    headers=self.config.headers,
                    timeout=self.config.timeout,
                )
            else:
                response = self.session.request(
                    self.config.method,
                    self.config.url,
                    data=data,
                    headers=self.config.headers,
                    timeout=self.config.timeout,
                )
            
            result.execution_time = time.time() - start_time
            result.response_data = response.content
            

            if response.status_code >= 500:
                result.crashed = True
                result.error_message = f"Server error: HTTP {response.status_code}"
            
            # Pseudo-coverage based on response characteristics
            result.coverage_hash = self._generate_coverage_hash(response)
                
        except requests.exceptions.Timeout:
            result.crashed = True
            result.error_message = "Request timeout (possible hang/DoS)"
            result.execution_time = time.time() - start_time
            
        except requests.exceptions.ConnectionError as e:
            result.crashed = True
            result.error_message = f"Connection error (server crash?): {str(e)[:100]}"
            result.execution_time = time.time() - start_time
            
        except Exception as e:
            result.crashed = True
            result.error_message = f"Unexpected error: {str(e)[:100]}"
            result.execution_time = time.time() - start_time
        
        return result
    
    def _generate_coverage_hash(self, response) -> str:
        """
        Generate a pseudo-coverage hash from the response.
        
        This is a hack since we can't actually instrument the target.
        We use response characteristics as a proxy for coverage.
        
        A real coverage-guided fuzzer would instrument the target
        to track which code paths are executed.
        """
        size_bucket = len(response.content) // 100
        

        error_patterns = [
            b"error",
            b"exception",
            b"traceback",
            b"stack trace",
            b"undefined",
            b"null",
        ]
        
        pattern_flags = ""
        for pattern in error_patterns:
            if pattern in response.content.lower():
                pattern_flags += "1"
            else:
                pattern_flags += "0"
        
        hash_input = f"{response.status_code}_{size_bucket}_{pattern_flags}"
        return hash_input


def create_target_function(url: str, method: str = "POST") -> callable:
    """
    Factory function to create a target function for the fuzzing engine.
    
    Args:
        url: Target URL
        method: HTTP method
        
    Returns:
        Function that can be passed to FuzzingEngine
    """
    config = HttpTargetConfig(url=url, method=method)
    target = HttpTarget(config)
    return target.run
