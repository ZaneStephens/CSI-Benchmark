import json
import sys
import os
from datetime import datetime

def generate_html_report(json_file):
    # Read the JSON report file
    with open(json_file, 'r') as f:
        data = json.load(f)
    
    # Create HTML content
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>CIS Benchmark Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            h1, h2 {{ color: #333; }}
            .summary {{ background-color: #f5f5f5; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
            .pass {{ color: green; }}
            .fail {{ color: red; }}
            .error {{ color: orange; }}
            table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
            tr:nth-child(even) {{ background-color: #f9f9f9; }}
        </style>
    </head>
    <body>
        <h1>CIS Benchmark Report</h1>
        <div class="summary">
            <h2>Summary</h2>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>Total Checks: {data['total']}</p>
            <p class="pass">Passed: {data['pass']} ({data['pass']/data['total']*100 if data['total'] > 0 else 0:.1f}%)</p>
            <p class="fail">Failed: {data['fail']} ({data['fail']/data['total']*100 if data['total'] > 0 else 0:.1f}%)</p>
            <p class="error">Errors: {data['error']} ({data['error']/data['total']*100 if data['total'] > 0 else 0:.1f}%)</p>
        </div>

        <h2>Detailed Results</h2>
        <table>
            <tr>
                <th>Description</th>
                <th>Type</th>
                <th>Actual Value</th>
                <th>Result</th>
            </tr>
    """
    
    # Add each check result to the table
    for check in data['checks']:
        result_class = check['result'].lower()
        html_content += f"""
            <tr>
                <td>{check['description']}</td>
                <td>{check['type']}</td>
                <td>{check['actual_value']}</td>
                <td class="{result_class}">{check['result']}</td>
            </tr>
        """
    
    # Close HTML tags
    html_content += """
        </table>
    </body>
    </html>
    """
    
    # Write HTML to file
    output_file = json_file.replace('.json', '.html')
    with open(output_file, 'w') as f:
        f.write(html_content)
    
    return output_file

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python report_generator.py <json_report_file>")
        sys.exit(1)
    
    json_file = sys.argv[1]
    if not os.path.exists(json_file):
        print(f"Error: File '{json_file}' not found")
        sys.exit(1)
    
    output_file = generate_html_report(json_file)
    print(f"HTML report generated: {output_file}")
