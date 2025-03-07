import winreg
import logging
import re
import binascii
from typing import Dict, Any, Union, List, Optional

# Registry value type mappings
REG_TYPE_MAP = {
    'REG_SZ': winreg.REG_SZ,
    'REG_MULTI_SZ': winreg.REG_MULTI_SZ,
    'REG_EXPAND_SZ': winreg.REG_EXPAND_SZ,
    'REG_DWORD': winreg.REG_DWORD,
    'REG_QWORD': winreg.REG_QWORD,
    'REG_BINARY': winreg.REG_BINARY
}

# Registry hive mappings
HIVE_MAP = {
    'HKLM': winreg.HKEY_LOCAL_MACHINE,
    'HKCU': winreg.HKEY_CURRENT_USER,
    'HKCR': winreg.HKEY_CLASSES_ROOT,
    'HKU': winreg.HKEY_USERS,
    'HKCC': winreg.HKEY_CURRENT_CONFIG
}

def convert_value_by_type(value: Any, value_type: str) -> Any:
    """Convert a value to the appropriate type based on the registry value type."""
    if value_type == 'REG_DWORD' or value_type == 'REG_QWORD':
        # Ensure numeric values are integers
        if isinstance(value, str):
            if value.startswith("0x"):
                return int(value, 16)
            return int(value)
        return value
    elif value_type == 'REG_BINARY':
        # Convert binary string representation to bytes
        if isinstance(value, str):
            # Handle format like "01 02 03 04"
            if ' ' in value:
                return bytes([int(x, 16) for x in value.split()])
            # Handle format like "01020304"
            return binascii.unhexlify(value)
        return value
    elif value_type == 'REG_MULTI_SZ':
        # Ensure it's a list of strings
        if isinstance(value, str):
            return value.split(',')
        return value
    else:
        # REG_SZ, REG_EXPAND_SZ and others as string
        return str(value)

def compare_values(actual_value: Any, expected_value: Any, comparison_op: str = 'equals') -> bool:
    """
    Compare actual and expected values with the specified comparison operator.
    Supported operators: equals, not_equals, contains, not_contains, greater_than, less_than,
    greater_than_or_equal, less_than_or_equal, regex_match
    """
    try:
        if comparison_op == 'equals':
            return actual_value == expected_value
        elif comparison_op == 'not_equals':
            return actual_value != expected_value
        elif comparison_op == 'contains':
            if isinstance(actual_value, list):
                return expected_value in actual_value
            return str(expected_value) in str(actual_value)
        elif comparison_op == 'not_contains':
            if isinstance(actual_value, list):
                return expected_value not in actual_value
            return str(expected_value) not in str(actual_value)
        elif comparison_op == 'greater_than':
            return actual_value > expected_value
        elif comparison_op == 'less_than':
            return actual_value < expected_value
        elif comparison_op == 'greater_than_or_equal':
            return actual_value >= expected_value
        elif comparison_op == 'less_than_or_equal':
            return actual_value <= expected_value
        elif comparison_op == 'regex_match':
            return bool(re.search(expected_value, str(actual_value)))
        else:
            logging.warning(f"Unknown comparison operator: {comparison_op}, defaulting to equals")
            return actual_value == expected_value
    except Exception as e:
        logging.error(f"Error during value comparison: {e}")
        return False

def check_registry_value(check: Dict[str, Any]) -> Dict[str, Union[str, bool]]:
    """
    Check a registry value against expected criteria.
    
    Args:
        check: Dictionary containing check parameters:
            - hive: Registry hive (e.g., 'HKLM', 'HKCU')
            - path: Registry key path
            - key: Value name to check
            - expected_value: Expected value
            - value_type: Registry value type (e.g., 'REG_DWORD', 'REG_SZ')
            - comparison_op: Comparison operator (default: 'equals')
            - missing_is_compliant: Whether a missing key/value is compliant
            
    Returns:
        Dictionary with actual_value and result ('Pass', 'Fail', or 'Error')
    """
    hive_str = check.get('hive', 'HKLM')
    path = check.get('path', '')
    key = check.get('key', '')
    expected_value = check.get('expected_value')
    value_type = check.get('value_type', 'REG_SZ')
    comparison_op = check.get('comparison_op', 'equals')
    missing_is_compliant = check.get('missing_is_compliant', False)
    
    # Get the hive constant
    hive = HIVE_MAP.get(hive_str)
    if hive is None:
        return {'actual_value': f"Invalid hive: {hive_str}", 'result': 'Error'}
    
    try:
        with winreg.OpenKey(hive, path) as reg_key:
            try:
                actual_value, value_type_id = winreg.QueryValueEx(reg_key, key)
                
                # Format binary data for readability
                if value_type_id == winreg.REG_BINARY and isinstance(actual_value, bytes):
                    actual_value_display = binascii.hexlify(actual_value).decode('utf-8')
                    actual_value_display = ' '.join(actual_value_display[i:i+2] for i in range(0, len(actual_value_display), 2))
                else:
                    actual_value_display = actual_value
                
                # Convert the expected value to the correct type for comparison
                typed_expected_value = convert_value_by_type(expected_value, value_type)
                
                # Compare values
                is_compliant = compare_values(actual_value, typed_expected_value, comparison_op)
                result = 'Pass' if is_compliant else 'Fail'
                
                return {'actual_value': actual_value_display, 'result': result}
            except FileNotFoundError:
                result = 'Pass' if missing_is_compliant else 'Fail'
                return {'actual_value': f"Value '{key}' not found", 'result': result}
    except FileNotFoundError:
        result = 'Pass' if missing_is_compliant else 'Fail'
        return {'actual_value': f"Key '{path}' not found", 'result': result}
    except Exception as e:
        logging.error(f"Error checking registry value {hive_str}\\{path}\\{key}: {e}")
        return {'actual_value': str(e), 'result': 'Error'}

def check_registry_key_exists(check: Dict[str, Any]) -> Dict[str, Union[str, bool]]:
    """Check if a registry key exists."""
    hive_str = check.get('hive', 'HKLM')
    path = check.get('path', '')
    should_exist = check.get('should_exist', True)
    
    hive = HIVE_MAP.get(hive_str)
    if hive is None:
        return {'actual_value': f"Invalid hive: {hive_str}", 'result': 'Error'}
    
    try:
        with winreg.OpenKey(hive, path):
            exists = True
    except FileNotFoundError:
        exists = False
    except Exception as e:
        logging.error(f"Error checking registry key {hive_str}\\{path}: {e}")
        return {'actual_value': str(e), 'result': 'Error'}
    
    is_compliant = exists == should_exist
    result = 'Pass' if is_compliant else 'Fail'
    status = "Exists" if exists else "Does not exist"
    
    return {'actual_value': status, 'result': result}

def check_registry_values_in_key(check: Dict[str, Any]) -> Dict[str, Union[str, bool]]:
    """
    Check if any value in a key matches specified criteria.
    Useful for checks where you need to search for any value matching a pattern.
    """
    hive_str = check.get('hive', 'HKLM')
    path = check.get('path', '')
    pattern = check.get('value_pattern', '')
    expected_content = check.get('expected_content', '')
    content_comparison_op = check.get('content_comparison_op', 'contains')
    
    hive = HIVE_MAP.get(hive_str)
    if hive is None:
        return {'actual_value': f"Invalid hive: {hive_str}", 'result': 'Error'}
    
    try:
        with winreg.OpenKey(hive, path) as reg_key:
            matching_values = []
            try:
                i = 0
                while True:
                    value_name, value_data, value_type = winreg.EnumValue(reg_key, i)
                    # Check if value name matches pattern
                    if re.search(pattern, value_name):
                        # Convert the value data to string for pattern matching
                        if value_type == winreg.REG_BINARY:
                            value_data_str = binascii.hexlify(value_data).decode('utf-8')
                        else:
                            value_data_str = str(value_data)
                        
                        # Check if value data matches expected content
                        if compare_values(value_data_str, expected_content, content_comparison_op):
                            matching_values.append(f"{value_name}={value_data_str}")
                    i += 1
            except WindowsError:
                # No more values
                pass
            
            if matching_values:
                return {'actual_value': '; '.join(matching_values), 'result': 'Pass' if check.get('should_match', True) else 'Fail'}
            else:
                return {'actual_value': 'No matching values found', 'result': 'Fail' if check.get('should_match', True) else 'Pass'}
    except FileNotFoundError:
        return {'actual_value': f"Key '{path}' not found", 'result': 'Fail'}
    except Exception as e:
        logging.error(f"Error checking registry values in {hive_str}\\{path}: {e}")
        return {'actual_value': str(e), 'result': 'Error'}

def check_multiple_registry_values(check: Dict[str, Any]) -> Dict[str, Union[str, bool]]:
    """Check multiple registry values from the same path."""
    hive_str = check.get('hive', 'HKLM')
    path = check.get('path', '')
    value_checks = check.get('value_checks', [])
    
    if not value_checks:
        return {'actual_value': 'No value checks specified', 'result': 'Error'}
    
    results = []
    all_passed = True
    
    for value_check in value_checks:
        # Create a new check dictionary for each value
        sub_check = {
            'hive': hive_str,
            'path': path,
            'key': value_check.get('key', ''),
            'expected_value': value_check.get('expected_value'),
            'value_type': value_check.get('value_type', 'REG_SZ'),
            'comparison_op': value_check.get('comparison_op', 'equals'),
            'missing_is_compliant': value_check.get('missing_is_compliant', False)
        }
        
        result = check_registry_value(sub_check)
        results.append(f"{sub_check['key']}: {result['actual_value']} - {result['result']}")
        
        if result['result'] != 'Pass':
            all_passed = False
    
    return {
        'actual_value': '; '.join(results),
        'result': 'Pass' if all_passed else 'Fail'
    }

def check_registry_for_all_users(check: Dict[str, Any]) -> Dict[str, Union[str, bool]]:
    """Check a registry value for all user profiles."""
    # Get the common part of the check
    path = check.get('path', '')
    key = check.get('key', '')
    expected_value = check.get('expected_value')
    value_type = check.get('value_type', 'REG_SZ')
    comparison_op = check.get('comparison_op', 'equals')
    missing_is_compliant = check.get('missing_is_compliant', False)
    
    try:
        # Get list of all user SIDs from HKU
        user_results = []
        all_passed = True
        
        with winreg.OpenKey(winreg.HKEY_USERS, '') as users_key:
            try:
                i = 0
                while True:
                    user_sid = winreg.EnumKey(users_key, i)
                    
                    # Skip system accounts like .DEFAULT, S-1-5-18, etc.
                    if user_sid not in ['.DEFAULT', 'S-1-5-18', 'S-1-5-19', 'S-1-5-20'] and '_Classes' not in user_sid:
                        # Create a check for this user
                        user_check = {
                            'hive': 'HKU',
                            'path': f"{user_sid}\\{path}",
                            'key': key,
                            'expected_value': expected_value,
                            'value_type': value_type,
                            'comparison_op': comparison_op,
                            'missing_is_compliant': missing_is_compliant
                        }
                        
                        result = check_registry_value(user_check)
                        user_results.append(f"User {user_sid}: {result['actual_value']} - {result['result']}")
                        
                        if result['result'] != 'Pass':
                            all_passed = False
                    
                    i += 1
            except WindowsError:
                # No more users
                pass
        
        if not user_results:
            return {'actual_value': 'No user profiles found to check', 'result': 'Error'}
        
        return {
            'actual_value': '; '.join(user_results),
            'result': 'Pass' if all_passed else 'Fail'
        }
    except Exception as e:
        logging.error(f"Error checking registry for all users: {e}")
        return {'actual_value': str(e), 'result': 'Error'}

def check_registry(check: Dict[str, Any]) -> Dict[str, Union[str, bool]]:
    """Main function to route registry checks based on check type."""
    check_type = check.get('subtype', 'value')
    
    if check_type == 'key_exists':
        return check_registry_key_exists(check)
    elif check_type == 'values_in_key':
        return check_registry_values_in_key(check)
    elif check_type == 'multiple_values':
        return check_multiple_registry_values(check)
    elif check_type == 'all_users':
        return check_registry_for_all_users(check)
    else:
        # Default to standard value check
        return check_registry_value(check)