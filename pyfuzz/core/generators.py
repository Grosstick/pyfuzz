"""
Grammar-based input generation (Work in Progress)

This module will generate inputs from grammar definitions
instead of just mutating existing inputs.

The idea is to define the structure of valid inputs,
then generate random inputs that are syntactically valid.
This helps the fuzzer reach deeper code paths.

Status: Started but not fully integrated yet
"""

# TODO: Finish this and integrate with engine

from typing import Dict, List, Union, Callable
import random


class Grammar:
    """
    Simple grammar representation.
    
    A grammar defines rules for generating structured inputs.
    For example, a JSON grammar would define how to create
    valid JSON objects, arrays, strings, etc.
    """
    
    def __init__(self, rules: Dict[str, List[Union[str, Callable]]]):
        """
        Initialize grammar with production rules.
        
        Args:
            rules: Dict mapping non-terminals to list of possible expansions
        """
        self.rules = rules
        self.start_symbol = "start"
        self.max_depth = 10  # Prevent infinite recursion
    
    def generate(self, symbol: str = None, depth: int = 0) -> str:
        """
        Generate a random string from the grammar.
        
        Args:
            symbol: Starting symbol (default: start)
            depth: Current recursion depth
            
        Returns:
            Generated string
        """
        if symbol is None:
            symbol = self.start_symbol
        
        # Prevent infinite recursion
        if depth > self.max_depth:
            return ""
        
        # If symbol is not in rules, it's a terminal
        if symbol not in self.rules:
            return symbol
        
        # Pick a random expansion
        expansion = random.choice(self.rules[symbol])
        
        # If expansion is a callable, call it
        if callable(expansion):
            return expansion()
        
        # If expansion is a list, generate each part
        if isinstance(expansion, list):
            result = ""
            for part in expansion:
                result += self.generate(part, depth + 1)
            return result
        
        # Otherwise, generate the expansion
        return self.generate(expansion, depth + 1)


# Example: Simple JSON grammar
# TODO: Make this more complete
JSON_GRAMMAR = Grammar({
    "start": ["object", "array"],
    "object": [["{", "members", "}"], ["{}"]],
    "array": [["[", "elements", "]"], ["[]"]],
    "members": [
        ["pair"],
        ["pair", ",", "members"],
    ],
    "pair": [["string", ":", "value"]],
    "elements": [
        ["value"],
        ["value", ",", "elements"],
    ],
    "value": ["string", "number", "object", "array", "true", "false", "null"],
    "string": [lambda: f'"{random_string()}"'],
    "number": [lambda: str(random.randint(-1000, 1000))],
})


def random_string(length: int = None) -> str:
    """Generate a random string."""
    if length is None:
        length = random.randint(1, 10)
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(random.choice(chars) for _ in range(length))


# Quick test
if __name__ == "__main__":
    print("Generating random JSON-like inputs:")
    for i in range(5):
        result = JSON_GRAMMAR.generate()
        print(f"  {i+1}: {result[:60]}...")
