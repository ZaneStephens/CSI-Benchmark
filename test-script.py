import os
import sys
import json
import subprocess
import logging
from datetime import datetime

# Set up basic logging
logging.basicConfig(
    filename=f'cis_benchmark_test_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def run_test(test_name, command, expected_return_code=0):
    """Run a test and log the results."""
    logging.info(f"Running test: {test_name}")
    print(f"\n----- Running test: {test_name} -----")
    
    try:
        start_time = datetime.now()
        result = subprocess.run(command, capture_output=True, text=True)
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        print(f"Command: {' '.join(command)}")
        print(f"Duration: {duration:.2f} seconds")
        print(f"Return code: {result.returncode}")
        
        # Log truncated output to avoid massive logs
        stdout_preview = result.stdout[:500] + "..." if len(result.stdout) > 500 else result.stdout
        stderr_preview = result.stderr[:500] + "..." if len(result.stderr) > 500 else result.stderr
        
        print(f"STDOUT (preview): {stdout_preview}")
        if result.stderr:
            print(f"STDERR (preview): {stderr_preview}")
        
        test_passed = result.returncode == expected_return_code
        status = "PASSED" if test_passed else "FAILED"
        print(f"Test status: {status}")
        
        logging.info(f"Test '{test_name}' {status} (return code: {result.returncode}, duration: {duration:.2f}s)")
        if not test_passed:
            logging.error(f"Test '{test_name}' failed with return code {result.returncode}")
            logging.error(f"STDERR: {result.stderr}")
            
        return test_passed
    except Exception as e:
        print(f"Error running test: {e}")
        logging.error(f"Error running test '{test_name}': {e}")
        return False

def main():
    """Run a series of tests on the CIS benchmark checker."""
    print("Starting CIS Benchmark Checker Tests")
    
    total_tests = 0
    passed_tests = 0
    
    # Test 1: Make sure the config validator works
    test = "Config Validator"
    cmd = [sys.executable, "config_validator.py", "checks_config.json"]
    if run_test(test, cmd):
        passed_tests += 1
    total_tests += 1
    
    # Test 2: Registry checks subset
    test = "Registry Checks Subset"
    cmd = [sys.executable, "cli.py", "--config", "checks_config.json", "--type", "registry", "--format", "table", "--no-progress"]
    if run_test(test, cmd):
        passed_tests += 1
    total_tests += 1
    
    # Test 3: Service checks subset
    test = "Service Checks Subset"
    cmd = [sys.executable, "cli.py", "--config", "checks_config.json", "--type", "service", "--format", "table", "--no-progress"]
    if run_test(test, cmd):
        passed_tests += 1
    total_tests += 1
    
    # Test 4: GPO checks subset
    test = "GPO Checks Subset"
    cmd = [sys.executable, "cli.py", "--config", "checks_config.json", "--type", "gpo", "--format", "table", "--no-progress"]
    if run_test(test, cmd):
        passed_tests += 1
    total_tests += 1
    
    # Test 5: Other checks subset
    test = "Other Checks Subset"
    cmd = [sys.executable, "cli.py", "--config", "checks_config.json", "--type", "other", "--format", "table", "--no-progress"]
    if run_test(test, cmd):
        passed_tests += 1
    total_tests += 1
    
    # Test 6: Category filtering
    test = "Category Filtering"
    cmd = [sys.executable, "cli.py", "--config", "checks_config.json", "--category", "Windows Defender", "--format", "table", "--no-progress"]
    if run_test(test, cmd):
        passed_tests += 1
    total_tests += 1
    
    # Test 7: Tag filtering
    test = "Tag Filtering"
    cmd = [sys.executable, "cli.py", "--config", "checks_config.json", "--tag", "firewall", "--format", "table", "--no-progress"]
    if run_test(test, cmd):
        passed_tests += 1
    total_tests += 1
    
    # Test 8: List checks without running
    test = "List Checks Without Running"
    cmd = [sys.executable, "cli.py", "--config", "checks_config.json", "--list"]
    if run_test(test, cmd):
        passed_tests += 1
    total_tests += 1
    
    # Test 9: Generate HTML report
    test = "Generate HTML Report"
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    cmd = [sys.executable, "cli.py", "--config", "checks_config.json", "--output", f"test_report_{timestamp}.json", "--html", "--no-progress", "--quiet"]
    if run_test(test, cmd):
        passed_tests += 1
    total_tests += 1
    
    # Test 10: Run full benchmark
    test = "Full Benchmark Run"
    cmd = [sys.executable, "cli.py", "--config", "checks_config.json", "--no-progress", "--format", "text", "--fail-only"]
    if run_test(test, cmd):
        passed_tests += 1
    total_tests += 1
    
    # Print summary
    print("\n----- Test Summary -----")
    print(f"Total tests: {total_tests}")
    print(f"Passed tests: {passed_tests}")
    print(f"Failed tests: {total_tests - passed_tests}")
    print(f"Success rate: {(passed_tests / total_tests) * 100:.1f}%")
    
    logging.info(f"Test summary: {passed_tests}/{total_tests} tests passed ({(passed_tests / total_tests) * 100:.1f}%)")
    
    # Return success if all tests passed
    return passed_tests == total_tests

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
