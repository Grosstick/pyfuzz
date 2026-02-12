"""
PyFuzz - Command Line Interface

Usage:
    python main.py --target http://localhost:5000/api/parse
    python main.py --target http://localhost:5000/api/parse --iterations 1000
    python main.py --help
"""

import argparse
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent))

from pyfuzz.core.engine import FuzzingEngine
from pyfuzz.targets.http_target import create_target_function


def print_banner():
    """Print a cool banner because why not."""
    banner = """
    ██████╗ ██╗   ██╗███████╗██╗   ██╗███████╗███████╗
    ██╔══██╗╚██╗ ██╔╝██╔════╝██║   ██║╚══███╔╝╚══███╔╝
    ██████╔╝ ╚████╔╝ █████╗  ██║   ██║  ███╔╝   ███╔╝
    ██╔═══╝   ╚██╔╝  ██╔══╝  ██║   ██║ ███╔╝   ███╔╝
    ██║        ██║   ██║     ╚██████╔╝███████╗███████╗
    ╚═╝        ╚═╝   ╚═╝      ╚═════╝ ╚══════╝╚══════╝

    ═══ Beginner Fuzzing Framework v0.1 ═══
    """
    print(banner)


def create_default_seeds(seeds_dir: Path):
    """
    Create some default seed files if the directory is empty.
    
    Good seeds help the fuzzer start with valid inputs
    that it can then mutate to find bugs.
    """
    seeds_dir.mkdir(parents=True, exist_ok=True)
    

    existing = list(seeds_dir.iterdir())
    if existing:
        return
    

    seeds = {
        "simple.json": b'{"value": 42}',
        "nested.json": b'{"a": {"b": {"c": 1}}}',
        "array.json": b'{"items": [1, 2, 3, 4, 5]}',
        "string.json": b'{"name": "test", "data": "hello world"}',
        "calc.json": b'{"a": 10, "b": 5, "op": "add"}',
    }
    
    for filename, content in seeds.items():
        seed_file = seeds_dir / filename
        seed_file.write_bytes(content)
        print(f"[*] Created seed: {filename}")


def main():
    parser = argparse.ArgumentParser(
        description="PyFuzz - A beginner-friendly fuzzing framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Fuzz the vulnerable test app
  python main.py --target http://localhost:5000/api/parse

  # Run with more iterations
  python main.py --target http://localhost:5000/api/parse --iterations 5000

  # Use a custom seeds directory
  python main.py --target http://localhost:5000/api/parse --seeds ./my_seeds
        """
    )
    
    parser.add_argument(
        "--target", "-t",
        required=True,
        help="Target URL to fuzz"
    )
    
    parser.add_argument(
        "--method", "-m",
        default="POST",
        choices=["GET", "POST", "PUT", "DELETE"],
        help="HTTP method to use (default: POST)"
    )
    
    parser.add_argument(
        "--iterations", "-i",
        type=int,
        default=10000,
        help="Maximum number of test cases (default: 10000)"
    )
    
    parser.add_argument(
        "--seeds", "-s",
        default="seeds",
        help="Directory containing seed inputs (default: seeds)"
    )
    
    parser.add_argument(
        "--crashes", "-c",
        default="crashes",
        help="Directory to save crashes (default: crashes)"
    )
    
    parser.add_argument(
        "--no-dictionary",
        action="store_true",
        help="Disable dictionary-based mutations"
    )
    
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show configuration without fuzzing"
    )
    
    args = parser.parse_args()
    
    print_banner()
    

    seeds_dir = Path(args.seeds)
    crashes_dir = Path(args.crashes)
    
    print(f"[*] Target:     {args.target}")
    print(f"[*] Method:     {args.method}")
    print(f"[*] Seeds dir:  {seeds_dir}")
    print(f"[*] Crashes dir: {crashes_dir}")
    print(f"[*] Iterations: {args.iterations}")
    print("")
    
    if args.dry_run:
        print("[!] Dry run mode - not fuzzing")
        return
    

    create_default_seeds(seeds_dir)
    print("")
    

    target_func = create_target_function(args.target, args.method)
    

    engine = FuzzingEngine(
        target_func=target_func,
        seeds_dir=str(seeds_dir),
        crashes_dir=str(crashes_dir),
        use_dictionary=not args.no_dictionary,
    )
    
    engine.run(max_iterations=args.iterations)


if __name__ == "__main__":
    main()
