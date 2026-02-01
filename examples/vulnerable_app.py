"""
Intentionally Vulnerable Application

!! THIS APP HAS BUGS ON PURPOSE !!

This Flask app contains several common vulnerabilities that
the fuzzer should be able to find. It's meant for testing only.

Vulnerabilities included:
1. JSON parsing crashes on malformed input
2. Integer overflow in calculation endpoint
3. Command injection in ping endpoint
4. Path traversal in file endpoint
5. Regex DoS (ReDoS) vulnerability

DO NOT deploy this anywhere - it's for local testing only!
"""

from flask import Flask, request, jsonify
import json
import re
import subprocess
import os

app = Flask(__name__)


@app.route('/')
def index():
    """Health check endpoint."""
    return jsonify({
        "status": "running",
        "message": "Vulnerable test application",
        "endpoints": [
            "/api/parse",
            "/api/calculate",
            "/api/ping",
            "/api/file",
            "/api/regex"
        ]
    })


@app.route('/api/parse', methods=['POST'])
def parse_json():
    """
    BUG 1: Improper JSON parsing
    
    This endpoint tries to parse JSON but doesn't handle
    malformed input properly. The fuzzer should find inputs
    that cause exceptions.
    """
    try:
        data = request.get_data()
        
        # Bug: We decode as JSON but don't catch all errors
        parsed = json.loads(data)
        
        # Bug: Accessing keys without checking if they exist
        if "value" in parsed:
            # Bug: Type confusion - what if value isn't a number?
            result = parsed["value"] * 2
            return jsonify({"result": result})
        
        # Bug: Recursion depth issue with deeply nested JSON
        def count_depth(obj, depth=0):
            if depth > 100:
                raise RecursionError("Too deep!")
            if isinstance(obj, dict):
                return max([count_depth(v, depth+1) for v in obj.values()] or [depth])
            elif isinstance(obj, list):
                return max([count_depth(v, depth+1) for v in obj] or [depth])
            return depth
        
        depth = count_depth(parsed)
        return jsonify({"parsed": True, "depth": depth})
        
    except json.JSONDecodeError as e:
        # Intentionally return detailed error (information disclosure)
        return jsonify({"error": str(e), "input": data.decode(errors="replace")}), 400
    except Exception as e:
        # Bug: Return 500 with full exception details
        return jsonify({"error": str(e), "type": type(e).__name__}), 500


@app.route('/api/calculate', methods=['POST'])
def calculate():
    """
    BUG 2: Integer overflow / type issues
    
    This endpoint does math but doesn't validate input types
    or handle edge cases properly.
    """
    try:
        data = json.loads(request.get_data())
        
        a = data.get("a", 0)
        b = data.get("b", 0)
        op = data.get("op", "add")
        
        # Bug: No type checking - what if a or b are strings?
        if op == "add":
            result = a + b
        elif op == "multiply":
            result = a * b
        elif op == "divide":
            # Bug: Division by zero not handled
            result = a / b
        elif op == "power":
            # Bug: Can cause very large numbers or hang
            result = a ** b
        else:
            result = 0
        
        return jsonify({"result": result})
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/ping', methods=['POST'])
def ping():
    """
    BUG 3: Command injection
    
    This endpoint runs a system command with user input.
    VERY DANGEROUS - classic command injection vulnerability.
    """
    try:
        data = json.loads(request.get_data())
        host = data.get("host", "localhost")
        
        # Bug: Command injection!
        # An attacker could send: {"host": "localhost; cat /etc/passwd"}
        # We're using shell=True which makes this exploitable
        
        # NOTE: This is intentionally vulnerable for fuzzing practice
        # NEVER do this in real code!
        if os.name == 'nt':
            cmd = f"ping -n 1 {host}"
        else:
            cmd = f"ping -c 1 {host}"
        
        # Limit command execution for safety in testing
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=5
        )
        
        return jsonify({
            "stdout": result.stdout[:500],
            "returncode": result.returncode
        })
        
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Command timeout"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/file', methods=['POST'])
def read_file():
    """
    BUG 4: Path traversal
    
    This endpoint reads files but doesn't properly validate
    the path, allowing directory traversal attacks.
    """
    try:
        data = json.loads(request.get_data())
        filename = data.get("filename", "")
        
        # Bug: Path traversal vulnerability
        # Attacker could send: {"filename": "../../../etc/passwd"}
        
        # Weak "protection" that's easily bypassed
        if ".." in filename:
            # Bug: Can be bypassed with encoding or other tricks
            return jsonify({"error": "Nice try!"}), 403
        
        # Still vulnerable to absolute paths and other tricks
        base_dir = os.path.dirname(__file__)
        filepath = os.path.join(base_dir, "data", filename)
        
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                content = f.read(1000)  # Limit size
            return jsonify({"content": content})
        else:
            return jsonify({"error": f"File not found: {filename}"}), 404
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/regex', methods=['POST'])
def regex_match():
    """
    BUG 5: ReDoS (Regular Expression Denial of Service)
    
    This endpoint uses a regex that's vulnerable to
    catastrophic backtracking with certain inputs.
    """
    try:
        data = json.loads(request.get_data())
        pattern = data.get("pattern", "")
        text = data.get("text", "")
        
        # Bug: User-controlled regex pattern
        # Malicious patterns can cause exponential execution time
        
        # Example evil pattern: (a+)+b
        # With input: "aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        
        # Adding a timeout would be smart, but we "forgot"
        compiled = re.compile(pattern)
        matches = compiled.findall(text)
        
        return jsonify({
            "matches": matches[:10],  # Limit response size
            "count": len(matches)
        })
        
    except re.error as e:
        return jsonify({"error": f"Invalid regex: {e}"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    print("=" * 50)
    print("VULNERABLE TEST APPLICATION")
    print("=" * 50)
    print("")
    print("WARNING: This app contains intentional bugs!")
    print("Only run this locally for fuzzing practice.")
    print("")
    print("Endpoints:")
    print("  POST /api/parse     - JSON parsing bugs")
    print("  POST /api/calculate - Integer/math bugs")
    print("  POST /api/ping      - Command injection")
    print("  POST /api/file      - Path traversal")
    print("  POST /api/regex     - ReDoS vulnerability")
    print("")
    print("Starting server on http://localhost:5000")
    print("=" * 50)
    
    # Debug mode intentionally on (more info disclosure)
    app.run(debug=True, port=5000)
