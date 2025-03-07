from flask import Flask, render_template, request, jsonify, redirect, url_for, send_file
import json
import os
import datetime
import threading
import uuid
from cis_benchmark_checker import run_checks
from utils import is_admin

app = Flask(__name__)

# Store job status and results
jobs = {}

@app.route('/')
def index():
    """Home page - show configuration options and previous reports"""
    # Get list of available configuration files
    config_files = [f for f in os.listdir() if f.endswith('.json') and 'config' in f.lower()]
    
    # Get list of generated reports
    report_files = [f for f in os.listdir() if f.endswith('.json') and 'report' in f.lower()]
    report_files.sort(key=lambda x: os.path.getmtime(x), reverse=True)  # Sort by modification time
    
    # Check for admin privileges
    admin_status = is_admin()
    
    return render_template(
        'index.html',
        config_files=config_files,
        report_files=report_files,
        admin_status=admin_status,
        active_jobs=jobs
    )

def run_job(job_id, config_file, selected_checks):
    """Run checks in a background thread"""
    try:
        # Load checks from config file
        with open(config_file, 'r') as f:
            all_checks = json.load(f)
            
        # Filter checks if specific ones were selected
        if selected_checks:
            checks = [c for c in all_checks if c.get('id') in selected_checks]
        else:
            checks = all_checks
            
        # Update job status
        jobs[job_id]['status'] = 'Running'
        jobs[job_id]['total_checks'] = len(checks)
        jobs[job_id]['checks_completed'] = 0
        
        # Create a progress callback
        def progress_callback(check_index):
            jobs[job_id]['checks_completed'] = check_index + 1
        
        # Run the checks
        results = run_checks(checks, show_progress=False)
        
        # Generate output files
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = f"cis_benchmark_report_{timestamp}.json"
        
        with open(report_file, 'w') as f:
            json.dump(results, f, indent=4)
            
        # Generate HTML report
        from report_generator import generate_html_report
        html_file = generate_html_report(report_file)
        
        # Update job status with results
        jobs[job_id]['status'] = 'Complete'
        jobs[job_id]['result_file'] = report_file
        jobs[job_id]['html_file'] = html_file
        jobs[job_id]['summary'] = {
            'total': results['total'],
            'pass': results['pass'],
            'fail': results['fail'],
            'error': results['error'],
            'pass_percentage': results['pass']/results['total']*100 if results['total'] > 0 else 0
        }
        
    except Exception as e:
        jobs[job_id]['status'] = 'Failed'
        jobs[job_id]['error'] = str(e)

@app.route('/start_check', methods=['POST'])
def start_check():
    """Start a new benchmark check"""
    if not is_admin():
        return jsonify({'error': 'This application requires administrative privileges'}), 403
        
    config_file = request.form.get('config_file', 'checks_config.json')
    selected_checks = request.form.getlist('checks')
    
    # Create a new job ID
    job_id = str(uuid.uuid4())
    
    # Initialize job status
    jobs[job_id] = {
        'id': job_id,
        'status': 'Starting',
        'config_file': config_file,
        'start_time': datetime.datetime.now().isoformat(),
        'checks_completed': 0,
        'total_checks': 0
    }
    
    # Start the job in a background thread
    thread = threading.Thread(target=run_job, args=(job_id, config_file, selected_checks))
    thread.daemon = True
    thread.start()
    
    return jsonify({'job_id': job_id})

@app.route('/job_status/<job_id>')
def job_status(job_id):
    """Get the status of a running job"""
    if job_id not in jobs:
        return jsonify({'error': 'Job not found'}), 404
        
    return jsonify(jobs[job_id])

@app.route('/view_report/<report_file>')
def view_report(report_file):
    """View an HTML report"""
    html_file = report_file.replace('.json', '.html')
    
    if not os.path.exists(html_file):
        # If HTML doesn't exist, try to generate it
        if os.path.exists(report_file):
            try:
                from report_generator import generate_html_report
                html_file = generate_html_report(report_file)
            except Exception as e:
                return f"Error generating HTML report: {e}"
        else:
            return f"Report file not found: {report_file}", 404
            
    return send_file(html_file)

@app.route('/download_report/<report_file>')
def download_report(report_file):
    """Download a report file"""
    if not os.path.exists(report_file):
        return f"File not found: {report_file}", 404
        
    return send_file(report_file, as_attachment=True)

@app.route('/configure')
def configure():
    """Page to edit check configurations"""
    return render_template('configure.html')

@app.route('/save_config', methods=['POST'])
def save_config():
    """Save a configuration file"""
    config_data = request.json
    filename = request.args.get('filename', 'custom_config.json')
    
    try:
        with open(filename, 'w') as f:
            json.dump(config_data, f, indent=2)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/cleanup_jobs', methods=['POST'])
def cleanup_jobs():
    """Remove old completed jobs from memory"""
    to_remove = []
    
    for job_id, job in jobs.items():
        if job['status'] in ['Complete', 'Failed']:
            # Keep jobs for at most 1 hour
            start_time = datetime.datetime.fromisoformat(job['start_time'])
            if (datetime.datetime.now() - start_time).total_seconds() > 3600:
                to_remove.append(job_id)
                
    for job_id in to_remove:
        del jobs[job_id]
        
    return jsonify({'removed': len(to_remove)})

if __name__ == '__main__':
    # Create templates directory if it doesn't exist
    os.makedirs('templates', exist_ok=True)
    
    # Create a basic template if it doesn't exist
    template_path = os.path.join('templates', 'index.html')
    if not os.path.exists(template_path):
        basic_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>CIS Benchmark Checker</title>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                h1, h2 { color: #333; }
                .container { max-width: 1200px; margin: 0 auto; }
                .card { background-color: #f8f9fa; border-radius: 5px; padding: 15px; margin-bottom: 20px; }
                .btn { background-color: #007bff; color: white; padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; }
                .btn-danger { background-color: #dc3545; }
                .alert { padding: 15px; margin-bottom: 20px; border-radius: 4px; }
                .alert-warning { background-color: #fff3cd; color: #856404; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>CIS Benchmark Checker</h1>
                
                {% if not admin_status %}
                <div class="alert alert-warning">
                    <strong>Warning!</strong> This application requires administrative privileges to run checks.
                </div>
                {% endif %}
                
                <div class="card">
                    <h2>Run New Check</h2>
                    <form action="/start_check" method="post" id="checkForm">
                        <div>
                            <label for="config_file">Configuration File:</label>
                            <select name="config_file" id="config_file">
                                {% for file in config_files %}
                                <option value="{{ file }}">{{ file }}</option>
                                {% endfor %}
                            </select>
                        </div>
                        <button type="submit" class="btn">Start Check</button>
                    </form>
                </div>
                
                <div class="card">
                    <h2>Active Jobs</h2>
                    <div id="activeJobs">
                        {% if active_jobs %}
                        <ul>
                            {% for job_id, job in active_jobs.items() %}
                            <li>{{ job.status }}: {{ job.config_file }} ({{ job.checks_completed }}/{{ job.total_checks }})</li>
                            {% endfor %}
                        </ul>
                        {% else %}
                        <p>No active jobs</p>
                        {% endif %}
                    </div>
                </div>
                
                <div class="card">
                    <h2>Previous Reports</h2>
                    {% if report_files %}
                    <ul>
                        {% for file in report_files %}
                        <li>
                            {{ file }} - 
                            <a href="/view_report/{{ file }}">View</a> | 
                            <a href="/download_report/{{ file }}">Download</a>
                        </li>
                        {% endfor %}
                    </ul>
                    {% else %}
                    <p>No reports found</p>
                    {% endif %}
                </div>
            </div>
            
            <script>
                // Simple JS to submit the form via AJAX
                document.getElementById('checkForm').addEventListener('submit', function(e) {
                    e.preventDefault();
                    const formData = new FormData(this);
                    
                    fetch('/start_check', {
                        method: 'POST',
                        body: formData
                    })
                    .then(response => response.json())
                    .then(data => {
                        alert('Check started! Job ID: ' + data.job_id);
                        // Here you could add code to poll for job status
                    })
                    .catch(error => {
                        alert('Error starting check: ' + error);
                    });
                });
            </script>
        </body>
        </html>
        """
        
        with open(template_path, 'w') as f:
            f.write(basic_template)
    
    app.run(debug=True, port=5000)