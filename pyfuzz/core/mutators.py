"""
Mutation strategies for fuzzing

This module contains different ways to mutate input data.
The idea is that by making small random changes to valid inputs,
we might accidentally create inputs that trigger bugs.

I learned about these strategies from reading about AFL:
https://lcamtuf.coredump.cx/afl/technical_details.txt
"""

import random
import struct
from typing import List

# Boundary values known to trigger integer-related bugs
INTERESTING_8 = [0, 1, 127, 128, 255]
INTERESTING_16 = [0, 1, 32767, 32768, 65535]
INTERESTING_32 = [0, 1, 2147483647, 2147483648, 4294967295]


class Mutator:
    """
    Base class for input mutation.
    
    A mutator takes some input data and returns a modified version.
    The goal is to explore different inputs that might crash the target.
    """
    
    def __init__(self, seed: int = None):
        """
        Initialize mutator with optional random seed for reproducibility.
        
        Args:
            seed: Random seed for reproducible mutations
        """
        if seed is not None:
            random.seed(seed)
    
    def mutate(self, data: bytes) -> bytes:
        """
        Apply a random mutation to the input data.
        
        Args:
            data: Original input bytes
            
        Returns:
            Mutated version of the input
        """
        if len(data) == 0:
            return data
        

        strategies = [
            self._bit_flip,
            self._byte_flip,
            self._insert_interesting,
            self._delete_bytes,
            self._insert_bytes,
            self._swap_bytes,
        ]
        
        strategy = random.choice(strategies)
        return strategy(data)
    
    def _bit_flip(self, data: bytes) -> bytes:
        """
        Flip a random bit in the data.
        
        This is one of the simplest mutations - just flip one bit.
        Sometimes this is enough to trigger different code paths.
        """
        data = bytearray(data)
        pos = random.randint(0, len(data) - 1)
        bit = random.randint(0, 7)
        data[pos] ^= (1 << bit)
        return bytes(data)
    
    def _byte_flip(self, data: bytes) -> bytes:
        """
        Replace a random byte with a random value.
        """
        data = bytearray(data)
        pos = random.randint(0, len(data) - 1)
        data[pos] = random.randint(0, 255)
        return bytes(data)
    
    def _insert_interesting(self, data: bytes) -> bytes:
        """
        Insert an "interesting" value at a random position.
        
        Interesting values are things like 0, MAX_INT, -1, etc.
        These often cause issues like:
        - Integer overflows
        - Off-by-one errors  
        - Buffer overflows
        """
        data = bytearray(data)
        pos = random.randint(0, len(data) - 1)
        

        choice = random.randint(0, 2)
        
        if choice == 0 and len(data) >= 1:
            data[pos] = random.choice(INTERESTING_8)
        elif choice == 1 and len(data) >= 2:
            val = random.choice(INTERESTING_16)
            if pos + 1 < len(data):
                data[pos:pos+2] = struct.pack('<H', val)
        elif choice == 2 and len(data) >= 4:
            val = random.choice(INTERESTING_32)
            if pos + 3 < len(data):
                data[pos:pos+4] = struct.pack('<I', val)
        
        return bytes(data)
    
    def _delete_bytes(self, data: bytes) -> bytes:
        """
        Delete a random chunk of bytes.
        
        Truncated input can cause parsers to read past buffer boundaries.
        """
        if len(data) <= 1:
            return data
            
        data = bytearray(data)
        pos = random.randint(0, len(data) - 1)
        length = random.randint(1, min(10, len(data) - pos))
        del data[pos:pos + length]
        return bytes(data)
    
    def _insert_bytes(self, data: bytes) -> bytes:
        """
        Insert random bytes at a random position.
        
        Extra input can cause buffer overflows if the target
        doesn't properly validate input length.
        """
        data = bytearray(data)
        pos = random.randint(0, len(data))
        length = random.randint(1, 10)
        new_bytes = bytes([random.randint(0, 255) for _ in range(length)])
        data[pos:pos] = new_bytes
        return bytes(data)
    
    def _swap_bytes(self, data: bytes) -> bytes:
        """
        Swap two random bytes.
        
        This can cause parsing issues when the order of fields matters.
        """
        if len(data) < 2:
            return data
            
        data = bytearray(data)
        pos1 = random.randint(0, len(data) - 1)
        pos2 = random.randint(0, len(data) - 1)
        data[pos1], data[pos2] = data[pos2], data[pos1]
        return bytes(data)


class DictionaryMutator(Mutator):
    """
    Mutator that also uses a dictionary of known interesting strings.
    
    This is useful when fuzzing formats that have keywords,
    like JSON, XML, or SQL. By inserting these tokens, we're more
    likely to trigger interesting parsing behavior.
    """
    
    def __init__(self, dictionary: List[bytes] = None, seed: int = None):
        """
        Args:
            dictionary: List of interesting byte sequences to insert
            seed: Random seed for reproducibility
        """
        super().__init__(seed)
        

        self.dictionary = dictionary or [
            b'{{',
            b'}}',
            b'<script>',
            b'</script>',
            b"'",
            b'"',
            b'\\',
            b'\x00',
            b'\xff',
            b'%s',
            b'%n',
            b'%x',
            b'../../../',
            b'null',
            b'undefined',
            b'-1',
            b'0',
            b'99999999',
        ]
    
    def mutate(self, data: bytes) -> bytes:
        """
        Apply mutation, sometimes using dictionary tokens.
        """

        if random.random() < 0.3:
            return self._insert_dictionary_token(data)
        
        return super().mutate(data)
    
    def _insert_dictionary_token(self, data: bytes) -> bytes:
        """
        Insert a dictionary token at a random position.
        """
        data = bytearray(data)
        token = random.choice(self.dictionary)
        pos = random.randint(0, len(data))
        data[pos:pos] = token
        return bytes(data)



if __name__ == "__main__":
    print("Testing mutator...")
    
    mutator = DictionaryMutator(seed=42)
    original = b'{"name": "test", "value": 123}'
    
    print(f"Original: {original}")
    print("\nMutations:")
    
    for i in range(5):
        mutated = mutator.mutate(original)
        print(f"  {i+1}: {mutated}")
