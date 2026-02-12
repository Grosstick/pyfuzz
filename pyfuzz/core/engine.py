"""
Main fuzzing engine

This is the core loop that:
1. Takes a seed input from the corpus
2. Mutates it
3. Sends it to the target
4. Checks for crashes
5. If we found new coverage, save the input

I tried to model this after how AFL works, but simplified a lot.
The real AFL has way more optimizations and features.
"""

import time
import hashlib
from dataclasses import dataclass, field
from typing import List, Dict, Callable, Optional, Set
from pathlib import Path

from .mutators import Mutator, DictionaryMutator


@dataclass
class FuzzResult:
    """
    Result from running a single fuzz case.
    """
    input_data: bytes
    crashed: bool = False
    error_message: str = ""
    response_data: bytes = b""
    execution_time: float = 0.0
    coverage_hash: str = ""


@dataclass
class FuzzStats:
    """
    Statistics about the fuzzing session.
    
    These are the numbers you see in AFL's status screen.
    """
    total_executions: int = 0
    unique_crashes: int = 0
    unique_paths: int = 0
    start_time: float = field(default_factory=time.time)
    last_new_path_time: float = 0.0
    
    @property
    def execs_per_sec(self) -> float:
        """Calculate executions per second."""
        elapsed = time.time() - self.start_time
        if elapsed == 0:
            return 0
        return self.total_executions / elapsed
    
    @property
    def runtime(self) -> float:
        """Total runtime in seconds."""
        return time.time() - self.start_time


class FuzzingEngine:
    """
    The main fuzzing loop.
    
    This coordinates between:
    - The corpus (collection of seed inputs)
    - The mutator (creates new inputs from seeds)
    - The target (the thing we're fuzzing)
    - The monitor (detects crashes and coverage)
    """
    
    def __init__(
        self,
        target_func: Callable[[bytes], FuzzResult],
        seeds_dir: str = "seeds",
        crashes_dir: str = "crashes",
        use_dictionary: bool = True,
    ):
        """
        Initialize the fuzzing engine.
        
        Args:
            target_func: Function that runs input against target and returns result
            seeds_dir: Directory with initial seed inputs
            crashes_dir: Directory to save crashes
            use_dictionary: Whether to use dictionary-based mutations
        """
        self.target_func = target_func
        self.seeds_dir = Path(seeds_dir)
        self.crashes_dir = Path(crashes_dir)
        

        self.seeds_dir.mkdir(parents=True, exist_ok=True)
        self.crashes_dir.mkdir(parents=True, exist_ok=True)
        

        if use_dictionary:
            self.mutator = DictionaryMutator()
        else:
            self.mutator = Mutator()
        

        self.corpus: List[bytes] = []
        self._load_seeds()
        

        self.seen_coverage: Set[str] = set()
        

        self.seen_crashes: Set[str] = set()
        

        self.stats = FuzzStats()
    
    def _load_seeds(self):
        """
        Load initial seed inputs from the seeds directory.
        
        Good seeds are examples of valid inputs to the target.
        The fuzzer will mutate these to try to find bugs.
        """
        if not self.seeds_dir.exists():
            self.corpus.append(b"test")
            return
        
        for seed_file in self.seeds_dir.iterdir():
            if seed_file.is_file():
                try:
                    data = seed_file.read_bytes()
                    self.corpus.append(data)
                    print(f"[*] Loaded seed: {seed_file.name} ({len(data)} bytes)")
                except Exception as e:
                    print(f"[!] Failed to load seed {seed_file}: {e}")
        
        if not self.corpus:
            print("[!] No seeds found, using default")
            self.corpus.append(b"test")
    
    def _pick_input(self) -> bytes:
        """
        Pick an input from the corpus to mutate.
        
        For now, just random selection. A smarter approach would
        prioritize inputs that recently found new coverage.
        """
        import random
        return random.choice(self.corpus)
    
    def _hash_crash(self, result: FuzzResult) -> str:
        """
        Create a hash to identify unique crashes.
        
        We use this to avoid saving duplicate crash cases.
        In a real fuzzer, you'd want to look at the stack trace too.
        """
        return hashlib.md5(
            result.error_message.encode() + result.input_data
        ).hexdigest()[:16]
    
    def _save_crash(self, result: FuzzResult):
        """
        Save a crash-inducing input to disk.
        """
        crash_hash = self._hash_crash(result)
        
        if crash_hash in self.seen_crashes:
            return
        
        self.seen_crashes.add(crash_hash)
        self.stats.unique_crashes += 1
        

        crash_file = self.crashes_dir / f"crash_{crash_hash}.bin"
        crash_file.write_bytes(result.input_data)
        

        info_file = self.crashes_dir / f"crash_{crash_hash}.txt"
        info_file.write_text(
            f"Crash found at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"Error: {result.error_message}\n"
            f"Input size: {len(result.input_data)} bytes\n"
        )
        
        print(f"\n[!] NEW CRASH: {crash_hash}")
        print(f"    Error: {result.error_message[:100]}")
        print(f"    Saved to: {crash_file}")
    
    def _check_new_coverage(self, result: FuzzResult) -> bool:
        """
        Check if this result found new code coverage.
        
        If we found a new path, add the input to our corpus.
        This is the "coverage-guided" part of fuzzing.
        """
        if not result.coverage_hash:
            return False
        
        if result.coverage_hash not in self.seen_coverage:
            self.seen_coverage.add(result.coverage_hash)
            self.corpus.append(result.input_data)
            self.stats.unique_paths += 1
            self.stats.last_new_path_time = time.time()
            return True
        
        return False
    
    def _print_status(self):
        """
        Print status line (like AFL's status screen, but simpler).
        """
        print(
            f"\r[{self.stats.runtime:.1f}s] "
            f"execs: {self.stats.total_executions} "
            f"({self.stats.execs_per_sec:.1f}/s) | "
            f"crashes: {self.stats.unique_crashes} | "
            f"corpus: {len(self.corpus)} | "
            f"paths: {self.stats.unique_paths}",
            end="",
            flush=True,
        )
    
    def run(self, max_iterations: int = 10000, print_interval: int = 100):
        """
        Main fuzzing loop.
        
        Args:
            max_iterations: Maximum number of test cases to run
            print_interval: How often to print status
        """
        print("[*] Starting fuzzing...")
        print(f"[*] Corpus size: {len(self.corpus)}")
        print(f"[*] Seeds dir: {self.seeds_dir}")
        print(f"[*] Crashes dir: {self.crashes_dir}")
        print("")
        
        try:
            for i in range(max_iterations):

                seed = self._pick_input()
                

                mutated = self.mutator.mutate(seed)
                

                result = self.target_func(mutated)
                
                self.stats.total_executions += 1
                

                if result.crashed:
                    self._save_crash(result)
                

                self._check_new_coverage(result)
                

                if i % print_interval == 0:
                    self._print_status()
        
        except KeyboardInterrupt:
            print("\n\n[*] Fuzzing interrupted by user")
        
        print("\n")
        print("=" * 50)
        print("FUZZING COMPLETE")
        print("=" * 50)
        print(f"Total executions: {self.stats.total_executions}")
        print(f"Unique crashes:   {self.stats.unique_crashes}")
        print(f"Unique paths:     {self.stats.unique_paths}")
        print(f"Final corpus:     {len(self.corpus)}")
        print(f"Runtime:          {self.stats.runtime:.2f} seconds")
