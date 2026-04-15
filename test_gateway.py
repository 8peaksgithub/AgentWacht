#!/usr/bin/env python3
"""
MCP Shield - Test Suite
=================================
Quick smoke tests to verify the gateway is working correctly.

Usage:
    python test_gateway.py [--host localhost] [--port 8000]
"""

import argparse
import json
import sys
import time
from typing import Dict, Any

import httpx


class Colors:
    """ANSI color codes for terminal output"""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


def print_test(name: str):
    """Print test name"""
    print(f"{Colors.BLUE}{Colors.BOLD}[TEST]{Colors.RESET} {name}", end=" ... ")
    sys.stdout.flush()


def print_pass():
    """Print pass status"""
    print(f"{Colors.GREEN}✓ PASS{Colors.RESET}")


def print_fail(reason: str = ""):
    """Print fail status"""
    msg = f"{Colors.RED}✗ FAIL{Colors.RESET}"
    if reason:
        msg += f" - {reason}"
    print(msg)


def print_warn(msg: str):
    """Print warning"""
    print(f"{Colors.YELLOW}⚠ WARNING:{Colors.RESET} {msg}")


def test_health_check(base_url: str) -> bool:
    """Test 1: Health check endpoint"""
    print_test("Health check endpoint")
    try:
        response = httpx.get(f"{base_url}/health", timeout=5.0)
        if response.status_code == 200:
            data = response.json()
            if "status" in data and "upstreams" in data:
                print_pass()
                return True
        print_fail(f"Status {response.status_code}")
        return False
    except Exception as e:
        print_fail(str(e))
        return False


def test_root_endpoint(base_url: str) -> bool:
    """Test 2: Root info endpoint"""
    print_test("Root info endpoint")
    try:
        response = httpx.get(f"{base_url}/", timeout=5.0)
        if response.status_code == 200:
            data = response.json()
            if "service" in data and "version" in data:
                print_pass()
                return True
        print_fail(f"Status {response.status_code}")
        return False
    except Exception as e:
        print_fail(str(e))
        return False


def test_list_tools_no_auth(base_url: str) -> bool:
    """Test 3: List tools without authentication"""
    print_test("List tools - no auth (should fail)")
    try:
        response = httpx.post(f"{base_url}/tools/list", timeout=5.0)
        if response.status_code == 401:
            print_pass()
            return True
        print_fail(f"Expected 401, got {response.status_code}")
        return False
    except Exception as e:
        print_fail(str(e))
        return False


def test_list_tools_invalid_auth(base_url: str) -> bool:
    """Test 4: List tools with invalid API key"""
    print_test("List tools - invalid auth (should fail)")
    try:
        headers = {"X-API-Key": "invalid-key-12345"}
        response = httpx.post(f"{base_url}/tools/list", headers=headers, timeout=5.0)
        if response.status_code == 401:
            print_pass()
            return True
        print_fail(f"Expected 401, got {response.status_code}")
        return False
    except Exception as e:
        print_fail(str(e))
        return False


def test_list_tools_valid_auth(base_url: str, api_key: str) -> bool:
    """Test 5: List tools with valid API key"""
    print_test("List tools - valid auth")
    try:
        headers = {"X-API-Key": api_key}
        response = httpx.post(f"{base_url}/tools/list", headers=headers, timeout=5.0)
        if response.status_code == 200:
            data = response.json()
            if "tools" in data and isinstance(data["tools"], list):
                print_pass()
                print(f"    → Found {len(data['tools'])} tools")
                return True
        print_fail(f"Status {response.status_code}")
        return False
    except Exception as e:
        print_fail(str(e))
        return False


def test_call_tool_no_auth(base_url: str) -> bool:
    """Test 6: Call tool without authentication"""
    print_test("Call tool - no auth (should fail)")
    try:
        payload = {"name": "test_tool", "arguments": {}}
        response = httpx.post(f"{base_url}/tools/call", json=payload, timeout=5.0)
        if response.status_code == 401:
            print_pass()
            return True
        print_fail(f"Expected 401, got {response.status_code}")
        return False
    except Exception as e:
        print_fail(str(e))
        return False


def test_call_nonexistent_tool(base_url: str, api_key: str) -> bool:
    """Test 7: Call a tool that doesn't exist"""
    print_test("Call nonexistent tool (should fail)")
    try:
        headers = {"X-API-Key": api_key}
        payload = {"name": "nonexistent_tool_xyz", "arguments": {}}
        response = httpx.post(f"{base_url}/tools/call", headers=headers, json=payload, timeout=5.0)
        if response.status_code in [403, 404, 503]:  # Permission denied or not found
            print_pass()
            return True
        print_fail(f"Expected 403/404/503, got {response.status_code}")
        return False
    except Exception as e:
        print_fail(str(e))
        return False


def test_rbac_filtering(base_url: str, api_keys: Dict[str, str]) -> bool:
    """Test 8: RBAC filtering - different users see different tools"""
    print_test("RBAC filtering")
    
    tool_counts = {}
    
    for username, api_key in api_keys.items():
        try:
            headers = {"X-API-Key": api_key}
            response = httpx.post(f"{base_url}/tools/list", headers=headers, timeout=5.0)
            if response.status_code == 200:
                data = response.json()
                tool_counts[username] = len(data["tools"])
            else:
                tool_counts[username] = -1
        except Exception:
            tool_counts[username] = -1
    
    # Check if different users see different tool counts (indicates RBAC is working)
    unique_counts = set(tool_counts.values())
    if len(unique_counts) > 1 and -1 not in unique_counts:
        print_pass()
        for username, count in tool_counts.items():
            print(f"    → {username}: {count} tools")
        return True
    elif len(api_keys) == 1:
        print_pass()
        print(f"    → Only one user configured (can't test RBAC filtering)")
        return True
    else:
        print_fail(f"All users see same tools or errors: {tool_counts}")
        return False


def test_sse_endpoint(base_url: str, api_key: str) -> bool:
    """Test 9: SSE endpoint connectivity"""
    print_test("SSE endpoint")
    try:
        headers = {"X-API-Key": api_key}
        with httpx.stream("GET", f"{base_url}/sse", headers=headers, timeout=10.0) as response:
            if response.status_code == 200:
                # Read first SSE event
                for line in response.iter_lines():
                    if line.startswith("data:"):
                        data = json.loads(line[5:].strip())
                        if "type" in data:
                            print_pass()
                            print(f"    → Received SSE event: {data['type']}")
                            return True
                        break
        print_fail("No SSE events received")
        return False
    except Exception as e:
        print_fail(str(e))
        return False


def load_test_config() -> Dict[str, Any]:
    """Load test configuration from policy.yaml"""
    try:
        import yaml
        with open("policy.yaml", 'r') as f:
            config = yaml.safe_load(f)
        
        # Extract API keys for testing
        api_keys = {}
        for user in config.get("users", []):
            api_keys[user["username"]] = user["api_key"]
        
        return {
            "api_keys": api_keys,
            "upstream_count": len(config.get("upstream_servers", [])),
            "user_count": len(config.get("users", [])),
            "role_count": len(config.get("roles", {}))
        }
    except Exception as e:
        print_warn(f"Could not load config: {e}")
        return {
            "api_keys": {},
            "upstream_count": 0,
            "user_count": 0,
            "role_count": 0
        }


def main():
    parser = argparse.ArgumentParser(description="Test MCP Shield")
    parser.add_argument("--host", default="localhost", help="Gateway host")
    parser.add_argument("--port", type=int, default=8000, help="Gateway port")
    args = parser.parse_args()
    
    base_url = f"http://{args.host}:{args.port}"
    
    print(f"{Colors.BOLD}MCP Shield - Test Suite{Colors.RESET}")
    print(f"Target: {base_url}")
    print("=" * 60)
    
    # Load config
    config = load_test_config()
    print(f"Configuration: {config['user_count']} users, {config['upstream_count']} upstreams, {config['role_count']} roles")
    print("=" * 60)
    
    # Check if gateway is running
    try:
        httpx.get(base_url, timeout=2.0)
    except Exception:
        print_fail("Gateway is not running!")
        print(f"\nPlease start the gateway first:")
        print(f"  python run_gateway.py --port {args.port}")
        sys.exit(1)
    
    # Run tests
    results = []
    
    results.append(test_health_check(base_url))
    results.append(test_root_endpoint(base_url))
    results.append(test_list_tools_no_auth(base_url))
    results.append(test_list_tools_invalid_auth(base_url))
    
    # Tests requiring valid API key
    if config["api_keys"]:
        first_api_key = list(config["api_keys"].values())[0]
        results.append(test_list_tools_valid_auth(base_url, first_api_key))
        results.append(test_call_tool_no_auth(base_url))
        results.append(test_call_nonexistent_tool(base_url, first_api_key))
        results.append(test_rbac_filtering(base_url, config["api_keys"]))
        results.append(test_sse_endpoint(base_url, first_api_key))
    else:
        print_warn("No users configured in policy.yaml - skipping auth tests")
    
    # Summary
    print("=" * 60)
    passed = sum(results)
    total = len(results)
    
    if passed == total:
        print(f"{Colors.GREEN}{Colors.BOLD}✓ ALL TESTS PASSED ({passed}/{total}){Colors.RESET}")
        sys.exit(0)
    else:
        print(f"{Colors.RED}{Colors.BOLD}✗ SOME TESTS FAILED ({passed}/{total} passed){Colors.RESET}")
        sys.exit(1)


if __name__ == "__main__":
    main()
