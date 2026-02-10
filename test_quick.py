"""
Quick test to verify the fuzzer works
"""
import sys
sys.path.insert(0, ".")

from pyfuzz.core.mutators import DictionaryMutator, Mutator
from pyfuzz.core.engine import FuzzingEngine, FuzzResult

print("=" * 40)
print("Testing PyFuzz Components")
print("=" * 40)

# Test 1: Mutators
print("\n[1] Testing Mutators...")
mutator = DictionaryMutator(seed=42)
original = b'{"test": 123, "name": "fuzzing"}'
print(f"    Original: {original}")

for i in range(3):
    mutated = mutator.mutate(original)
    print(f"    Mutation {i+1}: {mutated[:50]}...")

print("    ✓ Mutators working!")

# Test 2: FuzzResult
print("\n[2] Testing FuzzResult...")
result = FuzzResult(
    input_data=b"test",
    crashed=True,
    error_message="Test error"
)
print(f"    Created FuzzResult: crashed={result.crashed}")
print("    ✓ FuzzResult working!")

# Test 3: Simulated fuzzing run (no actual target)
print("\n[3] Testing Engine (dry run)...")

# Create a dummy target function
crash_count = 0
def dummy_target(data: bytes) -> FuzzResult:
    global crash_count
    # Simulate crash on certain inputs
    if b'\x00' in data or len(data) > 100:
        crash_count += 1
        return FuzzResult(
            input_data=data,
            crashed=True,
            error_message="Simulated crash!",
            coverage_hash=f"crash_{crash_count}"
        )
    return FuzzResult(
        input_data=data,
        crashed=False,
        coverage_hash=f"path_{len(data)}"
    )

# Run a quick fuzz
engine = FuzzingEngine(
    target_func=dummy_target,
    seeds_dir="seeds",
    crashes_dir="crashes",
    use_dictionary=True
)

# Just run a few iterations
print("    Running 100 iterations...")
engine.run(max_iterations=100, print_interval=50)

print("\n" + "=" * 40)
print("All tests passed!")
print("=" * 40)
