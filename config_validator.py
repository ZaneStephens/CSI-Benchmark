import json
import sys
import os
from typing import Dict, List, Any, Set

def validate_config(config_file: str) -> bool:
    """
    Validate a CIS Benchmark configuration file.
    
    Checks for:
    - Valid JSON format
    - Required fields for each check type
    - Unique IDs
    - Valid check types
    
    Args:
        config_file: Path to the configuration file
        
    Returns:
        True if validation passes, False otherwise
    """
    print(f"Validating configuration file: {config_file}")
    
    try:
        # Check if file exists
        if not os.path.exists(config_file):
            print(f"Error: File '{config_file}' not found")
            return False
            
        # Try to load the JSON
        with open(config_file, 'r') as f:
            try:
                checks = json.load(f)
            except json.JSONDecodeError as e:
                print(f"Error: Invalid JSON format: {e}")
                return False
                
        if not isinstance(checks, list):
            print("Error: Configuration must be a list of checks")
            return False
            
        # Valid check types
        valid_types = {'registry', 'service', 'gpo', 'other'}
        
        # Required fields for each check type
        required_fields = {
            'registry': ['description', 'hive', 'path'],
            'service': ['description', 'name'],
            'gpo': ['description', 'subtype'],
            'other': ['description', 'subtype']
        }
        
        # Required fields based on subtype
        subtype_fields = {
            'audit_policy': ['category', 'expected_value'],
            'user_rights': ['right', 'expected_accounts'],
            'registry_policy': ['hive', 'path', 'key', 'expected_value'],
            'bitlocker': ['drive'],
            'firewall_rule': ['rule_name'],
            'windows_feature': ['feature_name', 'expected_state'],
            'installed_software': ['software_name'],
            'network_settings': ['setting_type'],
            'file': ['path', 'file_check_type'],
            'powershell_policy': ['expected_policy']
        }
        
        # Track IDs to ensure uniqueness
        ids: Set[str] = set()
        
        # Validate each check
        for i, check in enumerate(checks):
            check_num = i + 1
            
            # Check for required fields
            if 'type' not in check:
                print(f"Error in check #{check_num}: Missing 'type' field")
                return False
                
            check_type = check.get('type')
            if check_type not in valid_types:
                print(f"Error in check #{check_num}: Invalid type '{check_type}', must be one of {valid_types}")
                return False
                
            # Check for required fields based on type
            for field in required_fields.get(check_type, []):
                if field not in check:
                    print(f"Error in check #{check_num}: Missing required field '{field}' for type '{check_type}'")
                    return False
                    
            # Check for required fields based on subtype
            if 'subtype' in check:
                subtype = check.get('subtype')
                if subtype in subtype_fields:
                    for field in subtype_fields[subtype]:
                        if field not in check:
                            print(f"Error in check #{check_num}: Missing required field '{field}' for subtype '{subtype}'")
                            return False
                            
            # Check ID uniqueness
            if 'id' in check:
                check_id = check.get('id')
                if check_id in ids:
                    print(f"Error in check #{check_num}: Duplicate ID '{check_id}'")
                    return False
                ids.add(check_id)
                
        print(f"Validation successful! Found {len(checks)} valid checks.")
        return True
        
    except Exception as e:
        print(f"Error during validation: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python config_validator.py <config_file>")
        sys.exit(1)
        
    config_file = sys.argv[1]
    if validate_config(config_file):
        sys.exit(0)
    else:
        sys.exit(1)