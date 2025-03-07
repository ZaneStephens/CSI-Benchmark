import winreg
import subprocess
import logging
import re
import os
import tempfile
from typing import Dict, Any, Union, List, Optional

def check_audit_policy(check: Dict[str, Any]) -> Dict[str, Union[str, bool]]:
    """
    Check audit policy settings using auditpol command.
    
    Args:
        check: Dictionary with check parameters:
            - category: Audit policy category to check
            - subcategory: Optional specific subcategory to check
            - expected_value: Expected audit setting (e.g., "Success and Failure")
            
    Returns:
        Dictionary with actual_value and result ('Pass', 'Fail', or 'Error')
    """
    try:
        category = check.get('category', '')
        subcategory = check.get('subcategory')
        expected_value = check.get('expected_value', '')
        
        # Build the auditpol command
        cmd = ['auditpol', '/get']
        
        if subcategory:
            cmd.extend(['/subcategory:"{}"'.format(subcategory)])
        else:
            cmd.extend(['/category:*'])
        
        cmd.append('/r')  # CSV format for easier parsing
        
        # Run the command
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            return {'actual_value': f"Error running auditpol: {result.stderr}", 'result': 'Error'}
        
        # Parse the CSV output
        lines = result.stdout.strip().split('\n')
        headers = lines[0].split(',') if lines else []
        
        # Find the index of the setting column (usually the last one)
        setting_idx = len(headers) - 1 if headers else -1
        
        for line in lines[1:]:  # Skip header row
            fields = line.split(',')
            if len(fields) <= setting_idx:
                continue
                
            # Check if this is the category/subcategory we're looking for
            cat_match = category.lower() in fields[2].lower() if len(fields) > 2 else False
            subcat_match = subcategory is None or (
                subcategory.lower() in fields[1].lower() if len(fields) > 1 else False
            )
            
            if cat_match and subcat_match:
                current_setting = fields[setting_idx].strip()
                
                # Check if the setting matches the expected value
                is_compliant = current_setting.lower() == expected_value.lower()
                result = 'Pass' if is_compliant else 'Fail'
                
                return {
                    'actual_value': current_setting,
                    'result': result
                }
        
        return {'actual_value': 'Setting not found', 'result': 'Fail'}
    except Exception as e:
        logging.error(f"Error checking audit policy: {e}")
        return {'actual_value': str(e), 'result': 'Error'}

def check_user_rights(check: Dict[str, Any]) -> Dict[str, Union[str, bool]]:
    """
    Check user rights assignment using secedit export/import.
    
    Args:
        check: Dictionary with check parameters:
            - right: User right to check (e.g., "SeNetworkLogonRight")
            - expected_accounts: List of accounts expected to have this right
            - unexpected_accounts: Optional list of accounts that should NOT have this right
            - exact_match: Whether the accounts list must match exactly
            
    Returns:
        Dictionary with actual_value and result ('Pass', 'Fail', or 'Error')
    """
    temp_file = None
    try:
        # Create a temporary file for the security policy export
        temp_dir = tempfile.gettempdir()
        temp_file = os.path.join(temp_dir, f"secpol_{os.getpid()}.cfg")
        
        # Export current security policy
        cmd = ['secedit', '/export', '/cfg', temp_file, '/areas', 'USER_RIGHTS']
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0 or not os.path.exists(temp_file):
            return {'actual_value': f"Error exporting security policy: {result.stderr}", 'result': 'Error'}
        
        # Read the exported policy file
        with open(temp_file, 'r', encoding='utf-16') as f:
            policy_content = f.read()
        
        # The right we're looking for
        right = check.get('right', '')
        
        # Find the specific right in the policy file
        pattern = rf"{right}\s*=\s*(.*)"
        match = re.search(pattern, policy_content, re.IGNORECASE)
        
        if not match:
            # Right not found in policy
            if not check.get('expected_accounts'):
                # If we expect no accounts to have this right, that's a pass
                return {'actual_value': 'Right not assigned to any accounts', 'result': 'Pass'}
            else:
                return {'actual_value': 'Right not found in policy', 'result': 'Fail'}
        
        # Get the accounts that have this right
        accounts_str = match.group(1).strip()
        current_accounts = []
        
        # Parse the accounts - they're usually in SID form
        if accounts_str:
            # Split by commas if there are multiple accounts
            current_accounts = [acc.strip() for acc in accounts_str.split(',')]
            
            # Try to convert SIDs to account names for readability
            readable_accounts = []
            for acc in current_accounts:
                if acc.startswith('*S-'):
                    # This is a SID, try to convert it to a name
                    try:
                        cmd = ['wmic', 'useraccount', 'where', f'sid="{acc[1:]}"', 'get', 'name', '/value']
                        result = subprocess.run(cmd, capture_output=True, text=True)
                        name_match = re.search(r'Name=(.+)', result.stdout)
                        if name_match:
                            readable_accounts.append(name_match.group(1).strip())
                        else:
                            readable_accounts.append(acc)
                    except:
                        readable_accounts.append(acc)
                else:
                    readable_accounts.append(acc)
            
            current_accounts = readable_accounts
        
        # Check if the accounts match the expected list
        expected_accounts = check.get('expected_accounts', [])
        unexpected_accounts = check.get('unexpected_accounts', [])
        exact_match = check.get('exact_match', False)
        
        if exact_match:
            # All expected accounts must be present, and no others
            expected_match = set(current_accounts) == set(expected_accounts)
        else:
            # All expected accounts must be present (but others can be too)
            expected_match = all(acc in current_accounts for acc in expected_accounts)
        
        # No unexpected accounts should be present
        unexpected_match = not any(acc in current_accounts for acc in unexpected_accounts)
        
        is_compliant = expected_match and unexpected_match
        result = 'Pass' if is_compliant else 'Fail'
        
        return {
            'actual_value': f"Assigned to: {', '.join(current_accounts)}",
            'result': result
        }
        
    except Exception as e:
        logging.error(f"Error checking user rights: {e}")
        return {'actual_value': str(e), 'result': 'Error'}
    finally:
        # Clean up the temporary file
        if temp_file and os.path.exists(temp_file):
            try:
                os.remove(temp_file)
            except:
                pass

def check_security_options(check: Dict[str, Any]) -> Dict[str, Union[str, bool]]:
    """
    Check security options policy settings.
    Many of these map to registry values, so we use the registry check for those.
    For others that don't have direct registry equivalents, we might need to use secedit.
    
    Args:
        check: Dictionary with check parameters (varies depending on the specific setting)
            
    Returns:
        Dictionary with actual_value and result ('Pass', 'Fail', or 'Error')
    """
    # For most security options, we can use the registry check
    if 'hive' in check and 'path' in check and 'key' in check:
        import registry_checks
        return registry_checks.check_registry(check)
    
    # For others, we might need custom logic
    setting = check.get('setting', '')
    expected_value = check.get('expected_value')
    
    # Example of a custom check for a specific security option
    if setting == 'LimitBlankPasswordUse':
        try:
            # This is in HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse
            import registry_checks
            registry_check = {
                'hive': 'HKLM',
                'path': r'SYSTEM\CurrentControlSet\Control\Lsa',
                'key': 'LimitBlankPasswordUse',
                'value_type': 'REG_DWORD',
                'expected_value': expected_value
            }
            return registry_checks.check_registry_value(registry_check)
        except Exception as e:
            return {'actual_value': str(e), 'result': 'Error'}
    
    # Default case - setting not handled
    return {'actual_value': f"Security option '{setting}' checking not implemented", 'result': 'Error'}

def check_advanced_audit_policy(check: Dict[str, Any]) -> Dict[str, Union[str, bool]]:
    """
    Check advanced audit policy settings, which require different auditpol syntax.
    
    Args:
        check: Dictionary with check parameters:
            - subcategory: Specific audit subcategory to check
            - expected_value: Expected audit setting
            
    Returns:
        Dictionary with actual_value and result ('Pass', 'Fail', or 'Error')
    """
    try:
        subcategory = check.get('subcategory', '')
        expected_value = check.get('expected_value', '')
        
        if not subcategory:
            return {'actual_value': 'No subcategory specified', 'result': 'Error'}
        
        # Run auditpol to get the current setting
        cmd = ['auditpol', '/get', '/subcategory:"{}"'.format(subcategory), '/r']
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            return {'actual_value': f"Error running auditpol: {result.stderr}", 'result': 'Error'}
        
        # Parse the CSV output (should be just header and one data row)
        lines = result.stdout.strip().split('\n')
        if len(lines) < 2:
            return {'actual_value': 'No audit policy data returned', 'result': 'Fail'}
        
        # The setting should be in the last column
        data_row = lines[1].split(',')
        current_setting = data_row[-1].strip() if data_row else ''
        
        is_compliant = current_setting.lower() == expected_value.lower()
        result = 'Pass' if is_compliant else 'Fail'
        
        return {'actual_value': current_setting, 'result': result}
    except Exception as e:
        logging.error(f"Error checking advanced audit policy: {e}")
        return {'actual_value': str(e), 'result': 'Error'}

def check_credential_guard(check: Dict[str, Any]) -> Dict[str, Union[str, bool]]:
    """
    Check Windows Credential Guard status.
    
    Args:
        check: Dictionary with check parameters
            
    Returns:
        Dictionary with actual_value and result ('Pass', 'Fail', or 'Error')
    """
    try:
        # First check if virtualization-based security is enabled in registry
        import registry_checks
        vbs_check = {
            'hive': 'HKLM',
            'path': r'SYSTEM\CurrentControlSet\Control\DeviceGuard',
            'key': 'EnableVirtualizationBasedSecurity',
            'value_type': 'REG_DWORD',
            'expected_value': 1
        }
        vbs_result = registry_checks.check_registry_value(vbs_check)
        
        if vbs_result['result'] != 'Pass':
            return {'actual_value': 'Virtualization-based security not enabled', 'result': 'Fail'}
        
        # Check if credential guard is enabled
        cred_guard_check = {
            'hive': 'HKLM',
            'path': r'SYSTEM\CurrentControlSet\Control\LSA',
            'key': 'LsaCfgFlags',
            'value_type': 'REG_DWORD',
            'expected_value': 1
        }
        cred_guard_result = registry_checks.check_registry_value(cred_guard_check)
        
        # You can also try to query the status using PowerShell
        cmd = ['powershell', '-Command', 'Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard | Select-Object SecurityServicesRunning']
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0 and '{1}' in result.stdout:
            # 1 in the SecurityServicesRunning array means Credential Guard is running
            return {'actual_value': 'Credential Guard is running', 'result': 'Pass'}
        elif cred_guard_result['result'] == 'Pass':
            return {'actual_value': 'Credential Guard is enabled, but may not be running', 'result': 'Pass'}
        else:
            return {'actual_value': 'Credential Guard is not enabled', 'result': 'Fail'}
    except Exception as e:
        logging.error(f"Error checking Credential Guard: {e}")
        return {'actual_value': str(e), 'result': 'Error'}

def check_exploit_protection(check: Dict[str, Any]) -> Dict[str, Union[str, bool]]:
    """
    Check Windows Exploit Protection settings.
    
    Args:
        check: Dictionary with check parameters:
            - feature: Specific exploit protection feature to check
            - expected_value: Expected setting
            
    Returns:
        Dictionary with actual_value and result ('Pass', 'Fail', or 'Error')
    """
    try:
        feature = check.get('feature', '')
        expected_value = check.get('expected_value', '')
        
        # Use PowerShell to check exploit protection settings
        cmd = ['powershell', '-Command', 'Get-ProcessMitigation -System']
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            return {'actual_value': f"Error running Get-ProcessMitigation: {result.stderr}", 'result': 'Error'}
        
        # Parse output based on feature
        if feature == 'DEP':
            # Check if DEP is enabled
            if "DEP: Enable" in result.stdout:
                return {'actual_value': 'DEP is enabled', 'result': 'Pass'}
            else:
                return {'actual_value': 'DEP is not enabled', 'result': 'Fail'}
        elif feature == 'ASLR':
            # Check if ASLR is enabled
            if "ASLR: ForceRelocateImages" in result.stdout:
                return {'actual_value': 'ASLR is enabled', 'result': 'Pass'}
            else:
                return {'actual_value': 'ASLR is not enabled', 'result': 'Fail'}
        elif feature == 'CFG':
            # Check if Control Flow Guard is enabled
            if "CFG: Enable" in result.stdout:
                return {'actual_value': 'CFG is enabled', 'result': 'Pass'}
            else:
                return {'actual_value': 'CFG is not enabled', 'result': 'Fail'}
        else:
            return {'actual_value': f"Unknown exploit protection feature: {feature}", 'result': 'Error'}
    except Exception as e:
        logging.error(f"Error checking exploit protection: {e}")
        return {'actual_value': str(e), 'result': 'Error'}

def check_secure_boot(check: Dict[str, Any]) -> Dict[str, Union[str, bool]]:
    """
    Check if Secure Boot is enabled.
    
    Args:
        check: Dictionary with check parameters
            
    Returns:
        Dictionary with actual_value and result ('Pass', 'Fail', or 'Error')
    """
    try:
        # Check Secure Boot status using PowerShell
        cmd = ['powershell', '-Command', 'Confirm-SecureBootUEFI']
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0 and "True" in result.stdout:
            return {'actual_value': 'Secure Boot is enabled', 'result': 'Pass'}
        else:
            return {'actual_value': 'Secure Boot is not enabled', 'result': 'Fail'}
    except Exception as e:
        logging.error(f"Error checking Secure Boot: {e}")
        return {'actual_value': str(e), 'result': 'Error'}

def check_gpo(check: Dict[str, Any]) -> Dict[str, Union[str, bool]]:
    """
    Main function to route GPO checks based on check type.
    
    Args:
        check: Dictionary with check parameters
        
    Returns:
        Dictionary with actual_value and result ('Pass', 'Fail', or 'Error')
    """
    subtype = check.get('subtype', '')
    
    if subtype == 'audit_policy':
        return check_audit_policy(check)
    elif subtype == 'user_rights':
        return check_user_rights(check)
    elif subtype == 'registry_policy':
        # For registry-based policy settings, use the registry check
        import registry_checks
        return registry_checks.check_registry(check)
    elif subtype == 'security_options':
        return check_security_options(check)
    elif subtype == 'advanced_audit_policy':
        return check_advanced_audit_policy(check)
    elif subtype == 'credential_guard':
        return check_credential_guard(check)
    elif subtype == 'exploit_protection':
        return check_exploit_protection(check)
    elif subtype == 'secure_boot':
        return check_secure_boot(check)
    else:
        return {'actual_value': f"Unknown GPO subtype: {subtype}", 'result': 'Error'}