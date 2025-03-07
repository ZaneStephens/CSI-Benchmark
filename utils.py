import ctypes
import platform
import os
import time
import socket
import subprocess
import re
from datetime import datetime

def is_admin():
    """Check if the current process has admin privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def get_windows_version():
    """Get detailed Windows version information."""
    try:
        version = platform.win32_ver()
        build = platform.version().split('.')
        return {
            'version': version[0],
            'build': build[2] if len(build) > 2 else 'Unknown',
            'name': get_windows_name(version[0]),
            'full_string': platform.platform()
        }
    except Exception as e:
        return {'error': str(e)}

def get_windows_name(version):
    """Convert Windows version number to friendly name."""
    versions = {
        '10': 'Windows 10',
        '11': 'Windows 11',
        '8.1': 'Windows 8.1',
        '8': 'Windows 8',
        '7': 'Windows 7',
    }
    return versions.get(version, f"Windows {version}")

def get_hostname():
    """Get the machine's hostname."""
    return socket.gethostname()

def get_ip_addresses():
    """Get all IP addresses for this machine."""
    hostname = socket.gethostname()
    return socket.gethostbyname_ex(hostname)[2]

def get_domain():
    """Check if machine is domain-joined and return domain name."""
    try:
        cmd = ['systeminfo']
        result = subprocess.run(cmd, capture_output=True, text=True)
        if 'Domain:' in result.stdout:
            domain = re.search(r'Domain:\s*(.*)', result.stdout)
            if domain:
                return domain.group(1).strip()
        return None  # Not domain joined
    except:
        return None

def time_function(func):
    """Decorator to measure execution time of a function."""
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        print(f"🕒 Function {func.__name__} took {end_time - start_time:.4f} seconds to run")
        return result
    return wrapper

def format_size(size_bytes):
    """Format file size from bytes to human-readable format."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"

def sid_to_username(sid):
    """Convert a SID to username if possible."""
    try:
        cmd = ['wmic', 'useraccount', 'where', f'sid="{sid}"', 'get', 'name', '/value']
        result = subprocess.run(cmd, capture_output=True, text=True)
        name_match = re.search(r'Name=(.+)', result.stdout)
        if name_match:
            return name_match.group(1).strip()
        return sid  # Return original SID if conversion fails
    except:
        return sid  # Return original SID if any error occurs

def get_system_info():
    """Get basic system information dictionary."""
    info = {
        'hostname': get_hostname(),
        'ip_addresses': get_ip_addresses(),
        'windows': get_windows_version(),
        'domain': get_domain(),
        'timestamp': datetime.now().isoformat(),
        'is_admin': is_admin(),
        'cpu_count': os.cpu_count(),
        'platform': platform.platform(),
        'machine': platform.machine()
    }
    return info

def create_report_filename(prefix="cis_benchmark_report"):
    """Generate a timestamped filename for reports."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    return f"{prefix}_{timestamp}.json"
