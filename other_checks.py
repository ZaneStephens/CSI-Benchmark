import subprocess
import logging
import re
import os
import socket
import winreg

def check_bitlocker(check):
    """Check BitLocker encryption status using manage-bde"""
    try:
        # Get BitLocker status for the specified drive
        drive = check.get('drive', 'C:')
        cmd = ['manage-bde', '-status', drive]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        # Parse the output
        encryption_status = None
        protection_status = None
        
        for line in result.stdout.splitlines():
            if "Encryption Method" in line:
                encryption_status = line.split(':')[1].strip()
            if "Protection Status" in line:
                protection_status = line.split(':')[1].strip()
        
        if encryption_status and protection_status:
            status = f"Encryption: {encryption_status}, Protection: {protection_status}"
            # Check if the drive is encrypted and protection is on
            is_compliant = "AES" in encryption_status and "Protection On" in protection_status
            result = 'Pass' if is_compliant else 'Fail'
            return {'actual_value': status, 'result': result}
        else:
            return {'actual_value': 'Unable to determine BitLocker status', 'result': 'Fail'}
    except Exception as e:
        logging.error(f"Error checking BitLocker: {e}")
        return {'actual_value': str(e), 'result': 'Error'}

def check_firewall_rule(check):
    """Check Windows Firewall rules using netsh"""
    try:
        # Get firewall rule details
        rule_name = check['rule_name']
        cmd = ['netsh', 'advfirewall', 'firewall', 'show', 'rule', f'name="{rule_name}"']
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if "No rules match the specified criteria" in result.stdout:
            return {'actual_value': f"Rule '{rule_name}' not found", 'result': 'Fail'}
        
        # Check if rule is enabled
        enabled = re.search(r"Enabled:\s*(Yes|No)", result.stdout)
        direction = re.search(r"Direction:\s*(In|Out)", result.stdout)
        action = re.search(r"Action:\s*(Allow|Block)", result.stdout)
        
        if enabled and direction and action:
            is_enabled = enabled.group(1) == "Yes"
            rule_direction = direction.group(1)
            rule_action = action.group(1)
            
            status = f"Enabled: {is_enabled}, Direction: {rule_direction}, Action: {rule_action}"
            
            # Check compliance based on expected values
            is_compliant = (
                (not check.get('enabled') or is_enabled == check['enabled']) and
                (not check.get('direction') or rule_direction == check['direction']) and
                (not check.get('action') or rule_action == check['action'])
            )
            
            result = 'Pass' if is_compliant else 'Fail'
            return {'actual_value': status, 'result': result}
        else:
            return {'actual_value': 'Unable to determine rule status', 'result': 'Fail'}
    except Exception as e:
        logging.error(f"Error checking firewall rule: {e}")
        return {'actual_value': str(e), 'result': 'Error'}

def check_windows_feature(check):
    """Check if a Windows feature is enabled/disabled using DISM"""
    try:
        feature_name = check['feature_name']
        cmd = ['dism', '/online', '/get-featureinfo', f'/featurename:{feature_name}']
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        # Check if feature exists and its state
        if "Error" in result.stdout and "not found" in result.stdout:
            return {'actual_value': f"Feature '{feature_name}' not found", 'result': 'Fail'}
        
        state = re.search(r"State\s*:\s*(\w+)", result.stdout)
        if state:
            feature_state = state.group(1)
            expected_state = check.get('expected_state', 'Disabled')
            is_compliant = feature_state == expected_state
            result = 'Pass' if is_compliant else 'Fail'
            return {'actual_value': f"State: {feature_state}", 'result': result}
        else:
            return {'actual_value': 'Unable to determine feature state', 'result': 'Fail'}
    except Exception as e:
        logging.error(f"Error checking Windows feature: {e}")
        return {'actual_value': str(e), 'result': 'Error'}

def check_installed_software(check):
    """Check if specific software is installed/not installed"""
    try:
        software_name = check.get('software_name', '')
        should_be_installed = check.get('should_be_installed', False)
        
        # Check both 32-bit and 64-bit software
        registry_paths = [
            (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'),
            (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
        ]
        
        found = False
        installed_version = None
        
        for hive, path in registry_paths:
            try:
                with winreg.OpenKey(hive, path) as key:
                    # Enumerate all subkeys (installed software)
                    subkey_count = winreg.QueryInfoKey(key)[0]
                    
                    for i in range(subkey_count):
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            with winreg.OpenKey(key, subkey_name) as subkey:
                                try:
                                    display_name = winreg.QueryValueEx(subkey, 'DisplayName')[0]
                                    if software_name.lower() in display_name.lower():
                                        found = True
                                        try:
                                            installed_version = winreg.QueryValueEx(subkey, 'DisplayVersion')[0]
                                        except:
                                            installed_version = "Unknown"
                                        break
                                except (WindowsError, FileNotFoundError):
                                    continue
                        except (WindowsError, FileNotFoundError):
                            continue
            except (WindowsError, FileNotFoundError):
                continue
        
        is_compliant = found == should_be_installed
        result = 'Pass' if is_compliant else 'Fail'
        
        if found:
            actual_value = f"Installed, version: {installed_version}"
        else:
            actual_value = "Not installed"
            
        return {'actual_value': actual_value, 'result': result}
    except Exception as e:
        logging.error(f"Error checking installed software: {e}")
        return {'actual_value': str(e), 'result': 'Error'}

def check_network_settings(check):
    """Check network configuration settings"""
    try:
        setting_type = check.get('setting_type', '')
        
        if setting_type == 'tcp_port':
            port = check.get('port')
            should_be_open = check.get('should_be_open', False)
            
            # Check if port is open
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            result = s.connect_ex(('localhost', port))
            s.close()
            
            is_open = (result == 0)
            is_compliant = is_open == should_be_open
            
            actual_value = f"Port {port} is {'open' if is_open else 'closed'}"
            result = 'Pass' if is_compliant else 'Fail'
            
            return {'actual_value': actual_value, 'result': result}
            
        elif setting_type == 'ip_config':
            setting_name = check.get('setting_name', '')
            expected_value = check.get('expected_value', '')
            
            # Use ipconfig /all to get network settings
            cmd = ['ipconfig', '/all']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            # Check for the setting in the output
            # This is simplified and may need more robust pattern matching
            pattern = rf"{setting_name}.*?:\s*(.+)"
            match = re.search(pattern, result.stdout, re.IGNORECASE)
            
            if match:
                actual_value = match.group(1).strip()
                is_compliant = (actual_value == expected_value)
                result = 'Pass' if is_compliant else 'Fail'
                return {'actual_value': actual_value, 'result': result}
            else:
                return {'actual_value': f"Setting '{setting_name}' not found", 'result': 'Fail'}
        
        else:
            return {'actual_value': f"Unknown network setting type: {setting_type}", 'result': 'Error'}
            
    except Exception as e:
        logging.error(f"Error checking network settings: {e}")
        return {'actual_value': str(e), 'result': 'Error'}

def check_file_permissions(check):
    """Check file existence, content or permissions"""
    try:
        file_path = check.get('path', '')
        check_type = check.get('file_check_type', 'exists')
        
        if not os.path.exists(file_path):
            should_exist = check.get('should_exist', True)
            result = 'Fail' if should_exist else 'Pass'
            return {'actual_value': f"File does not exist", 'result': result}
            
        if check_type == 'exists':
            return {'actual_value': "File exists", 'result': 'Pass'}
            
        elif check_type == 'content':
            expected_content = check.get('expected_content', '')
            content_comparison = check.get('content_comparison', 'contains')
            
            with open(file_path, 'r', errors='ignore') as f:
                content = f.read()
                
            if content_comparison == 'contains':
                is_compliant = expected_content in content
            elif content_comparison == 'exact':
                is_compliant = expected_content == content
            elif content_comparison == 'regex':
                is_compliant = bool(re.search(expected_content, content))
            else:
                return {'actual_value': f"Unknown comparison type: {content_comparison}", 'result': 'Error'}
                
            result = 'Pass' if is_compliant else 'Fail'
            actual_value = f"Content {'matches' if is_compliant else 'does not match'} expected"
            return {'actual_value': actual_value, 'result': result}
            
        elif check_type == 'permissions':
            # Get file permissions with icacls
            cmd = ['icacls', file_path]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            permissions = result.stdout.strip()
            expected_permissions = check.get('expected_permissions', [])
            
            # Very simple check - see if all expected permissions are mentioned
            is_compliant = all(perm in permissions for perm in expected_permissions)
            
            result = 'Pass' if is_compliant else 'Fail'
            return {'actual_value': permissions, 'result': result}
            
        else:
            return {'actual_value': f"Unknown file check type: {check_type}", 'result': 'Error'}
            
    except Exception as e:
        logging.error(f"Error checking file: {e}")
        return {'actual_value': str(e), 'result': 'Error'}

def check_powershell_policy(check):
    """Check PowerShell execution policy"""
    try:
        # Run PowerShell to get the execution policy
        cmd = ['powershell', '-Command', 'Get-ExecutionPolicy']
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        policy = result.stdout.strip()
        expected_policy = check.get('expected_policy', 'Restricted')
        
        is_compliant = (policy == expected_policy)
        result = 'Pass' if is_compliant else 'Fail'
        
        return {'actual_value': policy, 'result': result}
    except Exception as e:
        logging.error(f"Error checking PowerShell policy: {e}")
        return {'actual_value': str(e), 'result': 'Error'}

def check_other(check):
    """Route to appropriate check function based on subtype"""
    if check.get('subtype') == 'bitlocker':
        return check_bitlocker(check)
    elif check.get('subtype') == 'firewall_rule':
        return check_firewall_rule(check)
    elif check.get('subtype') == 'windows_feature':
        return check_windows_feature(check)
    elif check.get('subtype') == 'installed_software':
        return check_installed_software(check)
    elif check.get('subtype') == 'network_settings':
        return check_network_settings(check)
    elif check.get('subtype') == 'file':
        return check_file_permissions(check)
    elif check.get('subtype') == 'powershell_policy':
        return check_powershell_policy(check)
    else:
        return {'actual_value': f"Unknown check subtype: {check.get('subtype')}", 'result': 'Error'}
