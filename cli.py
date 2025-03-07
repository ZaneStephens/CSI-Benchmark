import argparse
import json
import sys
import os
from datetime import datetime
from colorama import init, Fore, Style
from tabulate import tabulate
from tqdm import tqdm

# Initialize colorama for cross-platform colored terminal output
init()

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='CIS Benchmark Checker for Windows')
    
    # Basic options
    parser.add_argument('--config', default='checks_config.json', 
                        help='Path to configuration file (default: checks_config.json)')
    parser.add_argument('--output', 
                        help='Path to save results JSON (default: auto-generated filename)')
    parser.add_argument('--html', action='store_true',
                        help='Generate HTML report in addition to JSON')
    
    # Filtering options
    parser.add_argument('--type', choices=['registry', 'service', 'gpo', 'other'],
                        help='Only run checks of specified type')
    parser.add_argument('--category', 
                        help='Only run checks from specified category')
    parser.add_argument('--id', 
                        help='Only run check with specified ID')
    parser.add_argument('--tag', 
                        help='Only run checks with specified tag')
    
    # Output control
    parser.add_argument('--quiet', action='store_true',
                        help='Suppress console output except errors')
    parser.add_argument('--verbose', action='store_true',
                        help='Show detailed information for each check')
    parser.add_argument('--no-progress', action='store_true',
                        help='Disable progress bar')
    parser.add_argument('--format', choices=['text', 'table', 'json'], default='table',
                        help='Output format for console (default: table)')
    parser.add_argument('--fail-only', action='store_true',
                        help='Only show failed checks in output')
    
    # Actions
    parser.add_argument('--list', action='store_true',
                        help='List all checks without running them')
    parser.add_argument('--remediate', action='store_true',
                        help='Attempt to remediate failed checks (requires additional confirmation)')
    parser.add_argument('--compare', 
                        help='Compare with previous results file')
    
    return parser.parse_args()

def filter_checks(checks, args):
    """Filter checks based on command line arguments."""
    filtered_checks = checks
    
    if args.type:
        filtered_checks = [c for c in filtered_checks if c.get('type') == args.type]
        
    if args.category:
        filtered_checks = [c for c in filtered_checks if c.get('category', '').lower() == args.category.lower()]
        
    if args.id:
        filtered_checks = [c for c in filtered_checks if c.get('id') == args.id]
        
    if args.tag:
        filtered_checks = [c for c in filtered_checks 
                          if 'tags' in c and args.tag in c.get('tags', [])]
        
    return filtered_checks

def display_check_list(checks):
    """Display a list of checks without running them."""
    headers = ["ID", "Type", "Category", "Description"]
    rows = []
    
    for check in checks:
        rows.append([
            check.get('id', 'N/A'),
            check.get('type', 'N/A'),
            check.get('category', 'N/A'),
            check.get('description', 'No description')
        ])
    
    print(tabulate(rows, headers=headers, tablefmt="grid"))
    print(f"\nTotal: {len(checks)} checks")

def display_results_table(results):
    """Display results in a formatted table."""
    headers = ["Result", "ID", "Description", "Value"]
    rows = []
    
    # Color mapping for results
    color_map = {
        'Pass': Fore.GREEN,
        'Fail': Fore.RED,
        'Error': Fore.YELLOW
    }
    
    for check in results['checks']:
        result = check['result']
        color = color_map.get(result, '')
        
        rows.append([
            f"{color}{result}{Style.RESET_ALL}",
            check.get('id', 'N/A'),
            check.get('description', 'No description'),
            check.get('actual_value', 'N/A')
        ])
    
    print(tabulate(rows, headers=headers, tablefmt="grid"))
    
    # Summary
    pass_pct = results['pass']/results['total']*100 if results['total'] > 0 else 0
    fail_pct = results['fail']/results['total']*100 if results['total'] > 0 else 0
    error_pct = results['error']/results['total']*100 if results['total'] > 0 else 0
    
    print("\nSummary:")
    print(f"Total Checks: {results['total']}")
    print(f"Passed: {Fore.GREEN}{results['pass']}{Style.RESET_ALL} ({pass_pct:.1f}%)")
    print(f"Failed: {Fore.RED}{results['fail']}{Style.RESET_ALL} ({fail_pct:.1f}%)")
    print(f"Errors: {Fore.YELLOW}{results['error']}{Style.RESET_ALL} ({error_pct:.1f}%)")

def compare_results(current_results, previous_file):
    """Compare current results with a previous run."""
    try:
        with open(previous_file, 'r') as f:
            previous_results = json.load(f)
            
        current_checks = {check.get('id', i): check 
                         for i, check in enumerate(current_results['checks'])}
        previous_checks = {check.get('id', i): check 
                          for i, check in enumerate(previous_results['checks'])}
        
        # Find differences
        improved = []
        regressed = []
        unchanged_fail = []
        
        for check_id, current in current_checks.items():
            if check_id in previous_checks:
                previous = previous_checks[check_id]
                
                # Check was failing but is now passing
                if previous['result'] == 'Fail' and current['result'] == 'Pass':
                    improved.append(current)
                
                # Check was passing but is now failing
                elif previous['result'] == 'Pass' and current['result'] == 'Fail':
                    regressed.append(current)
                
                # Check is still failing
                elif previous['result'] == 'Fail' and current['result'] == 'Fail':
                    unchanged_fail.append(current)
        
        # Display comparison
        print("\n=== Comparison with Previous Results ===")
        print(f"Previous file: {previous_file}")
        print(f"Improved checks (Fail → Pass): {len(improved)}")
        print(f"Regressed checks (Pass → Fail): {len(regressed)}")
        print(f"Unchanged failing checks: {len(unchanged_fail)}")
        
        if regressed:
            print(f"\n{Fore.RED}Regressions:{Style.RESET_ALL}")
            for check in regressed:
                print(f"- {check.get('description', 'No description')}")
                
        if improved:
            print(f"\n{Fore.GREEN}Improvements:{Style.RESET_ALL}")
            for check in improved:
                print(f"- {check.get('description', 'No description')}")
                
    except Exception as e:
        print(f"Error comparing results: {e}")

def main():
    args = parse_arguments()
    
    try:
        # Load configuration
        with open(args.config, 'r') as f:
            checks = json.load(f)
            
        # Filter checks
        filtered_checks = filter_checks(checks, args)
        
        if not filtered_checks:
            print("No checks match the specified filters.")
            return
            
        if args.list:
            display_check_list(filtered_checks)
            return
        
        # Import the main checker here to avoid circular imports
        from cis_benchmark_checker import run_checks
        
        # Run the checks
        if not args.quiet:
            print(f"Running {len(filtered_checks)} CIS Benchmark checks...")
            
        results = run_checks(filtered_checks, show_progress=not args.no_progress)
        
        # Save results
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = args.output or f"cis_benchmark_report_{timestamp}.json"
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=4)
            
        if not args.quiet:
            print(f"\nResults saved to {output_file}")
            
        # Generate HTML report if requested
        if args.html:
            from report_generator import generate_html_report
            html_file = generate_html_report(output_file)
            if not args.quiet:
                print(f"HTML report generated: {html_file}")
                
        # Display results
        if not args.quiet:
            if args.format == 'table':
                display_results_table(results)
            elif args.format == 'json':
                print(json.dumps(results, indent=2))
            else:  # text format
                for check in results['checks']:
                    if args.fail_only and check['result'] != 'Fail':
                        continue
                    print(f"{check['result']}: {check.get('description', 'No description')}")
                    if args.verbose:
                        print(f"  Value: {check.get('actual_value', 'N/A')}")
                        
                # Show summary
                print(f"\nTotal: {results['total']}, Pass: {results['pass']}, " +
                     f"Fail: {results['fail']}, Error: {results['error']}")
                
        # Compare with previous results if requested
        if args.compare:
            compare_results(results, args.compare)
            
    except FileNotFoundError:
        print(f"Error: Configuration file '{args.config}' not found.")
    except json.JSONDecodeError:
        print(f"Error: Configuration file '{args.config}' is not valid JSON.")
    except Exception as e:
        print(f"Error: {e}")
        
if __name__ == "__main__":
    main()
