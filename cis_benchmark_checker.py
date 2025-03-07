import json
import logging
import datetime
import sys
from tqdm import tqdm
from logging_config import setup_logging
from utils import is_admin
from registry_checks import check_registry
from service_checks import check_service
from gpo_checks import check_gpo
from other_checks import check_other

def run_checks(checks, show_progress=True):
    """
    Run the specified checks and return results.
    
    Args:
        checks: List of check definitions
        show_progress: Whether to show a progress bar
        
    Returns:
        Dictionary with results
    """
    setup_logging()
    
    if not is_admin():
        logging.error("This script requires administrative privileges.")
        print("Error: This script requires administrative privileges.")
        sys.exit(1)
    
    start_time = datetime.datetime.now()
    logging.info(f"CIS Benchmark check started at {start_time}")
    
    results = {
        'total': 0,
        'pass': 0,
        'fail': 0,
        'error': 0,
        'checks': [],
        'start_time': start_time.isoformat(),
        'end_time': None,
        'duration_seconds': 0
    }

    # Create progress bar if requested
    check_iterator = checks
    if show_progress:
        check_iterator = tqdm(checks, desc="Running checks", unit="check")

    for check in check_iterator:
        check_type = check.get('type', 'unknown')
        results['total'] += 1
        
        try:
            if check_type == 'registry':
                result = check_registry(check)
            elif check_type == 'service':
                result = check_service(check)
            elif check_type == 'gpo':
                result = check_gpo(check)
            elif check_type == 'other':
                result = check_other(check)
            else:
                result = {'actual_value': f"Unknown check type: {check_type}", 'result': 'Error'}
                logging.warning(f"Unknown check type: {check_type}")

            # Update result counters
            if result['result'] == 'Pass':
                results['pass'] += 1
            elif result['result'] == 'Fail':
                results['fail'] += 1
            else:  # Error or any other status
                results['error'] += 1

            # Store check result
            check_result = {
                'id': check.get('id', f"{check_type}_{results['total']}"),
                'description': check.get('description', 'No description'),
                'category': check.get('category', 'Uncategorized'),
                'type': check_type,
                'actual_value': result['actual_value'],
                'result': result['result']
            }
            results['checks'].append(check_result)

            # Log the result
            logging.info(f"Check: {check_result['description']}")
            logging.info(f"Type: {check_type}")
            logging.info(f"Parameters: {check}")
            logging.info(f"Actual value: {result['actual_value']}")
            logging.info(f"Result: {result['result']}")
            logging.info("-" * 50)
        
        except Exception as e:
            logging.error(f"Error performing check {check.get('description', 'unknown')}: {e}")
            results['error'] += 1
            results['checks'].append({
                'id': check.get('id', f"{check_type}_{results['total']}"),
                'description': check.get('description', 'No description'),
                'category': check.get('category', 'Uncategorized'),
                'type': check_type,
                'actual_value': str(e),
                'result': 'Error'
            })

    # Complete the results
    end_time = datetime.datetime.now()
    duration = end_time - start_time
    
    results['end_time'] = end_time.isoformat()
    results['duration_seconds'] = duration.total_seconds()
    
    # Log summary
    summary = f"""
    CIS Benchmark Check Summary:
    --------------------------
    Start Time: {start_time}
    Completion Time: {end_time}
    Duration: {duration}
    Total Checks: {results['total']}
    Passed: {results['pass']} ({results['pass']/results['total']*100 if results['total'] > 0 else 0:.1f}%)
    Failed: {results['fail']} ({results['fail']/results['total']*100 if results['total'] > 0 else 0:.1f}%)
    Errors: {results['error']} ({results['error']/results['total']*100 if results['total'] > 0 else 0:.1f}%)
    """
    
    logging.info(summary)
    return results

def main():
    """Legacy entry point for direct script execution."""
    try:
        with open('checks_config.json', 'r') as f:
            checks = json.load(f)
    except Exception as e:
        logging.error(f"Error loading configuration file: {e}")
        print(f"Error loading configuration file: {e}")
        return

    # Run checks and get results
    results = run_checks(checks)
    
    # Print summary to console
    print(f"\nTotal Checks: {results['total']}")
    print(f"Passed: {results['pass']} ({results['pass']/results['total']*100 if results['total'] > 0 else 0:.1f}%)")
    print(f"Failed: {results['fail']} ({results['fail']/results['total']*100 if results['total'] > 0 else 0:.1f}%)")
    print(f"Errors: {results['error']} ({results['error']/results['total']*100 if results['total'] > 0 else 0:.1f}%)")
    
    # Generate a report file
    try:
        report_file = f"cis_benchmark_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(results, f, indent=4)
        logging.info(f"Report saved to {report_file}")
        print(f"Report saved to {report_file}")
    except Exception as e:
        logging.error(f"Error saving report: {e}")

if __name__ == "__main__":
    main()