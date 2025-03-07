import win32serviceutil
import win32service
import win32security
import logging
from typing import Dict, Any, Union, List, Optional

# Service status mappings
SERVICE_STATUS_MAP = {
    1: "Stopped",
    2: "Start Pending",
    3: "Stop Pending",
    4: "Running",
    5: "Continue Pending",
    6: "Pause Pending",
    7: "Paused"
}

# Service start type mappings
SERVICE_STARTUP_MAP = {
    0: "Boot",
    1: "System",
    2: "Automatic",
    3: "Manual",
    4: "Disabled"
}

def get_service_info(service_name: str) -> Dict[str, Any]:
    """
    Get detailed information about a Windows service.
    
    Args:
        service_name: Name of the service to query
        
    Returns:
        Dictionary with service information
    """
    try:
        # Query basic service status
        status_info = win32serviceutil.QueryServiceStatus(service_name)
        status_code = status_info[1]
        
        # Get service configuration
        config = win32serviceutil.QueryServiceConfig(service_name)
        startup_type = config[1]
        binary_path = config[3]
        service_type = config[0]
        account = config[7]
        
        # Map codes to human-readable strings
        status = SERVICE_STATUS_MAP.get(status_code, f"Unknown ({status_code})")
        startup = SERVICE_STARTUP_MAP.get(startup_type, f"Unknown ({startup_type})")
        
        # Get additional service info like description
        try:
            service_handle = win32service.OpenService(
                win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ALL_ACCESS),
                service_name,
                win32service.SERVICE_QUERY_CONFIG
            )
            description_info = win32service.QueryServiceConfig2(
                service_handle,
                win32service.SERVICE_CONFIG_DESCRIPTION
            )
            description = description_info.get('lpDescription', '')
        except:
            description = ''
            
        # Get service dependencies
        try:
            dependencies = win32serviceutil.EnumDependentServices(service_name)
            dependent_services = [dep[0] for dep in dependencies]
        except:
            dependent_services = []

        return {
            "name": service_name,
            "status": status,
            "status_code": status_code,
            "startup_type": startup,
            "startup_code": startup_type,
            "binary_path": binary_path,
            "service_type": service_type,
            "account": account,
            "description": description,
            "dependent_services": dependent_services
        }
    except Exception as e:
        logging.error(f"Error getting service info for '{service_name}': {e}")
        raise

def check_service_status(check: Dict[str, Any]) -> Dict[str, Union[str, bool]]:
    """
    Check if a service's status and startup type match expected values.
    
    Args:
        check: Dictionary with check parameters:
            - name: Service name
            - expected_status: Expected status string ("Running", "Stopped", etc.)
            - expected_startup: Expected startup type ("Automatic", "Disabled", etc.)
            - missing_is_compliant: Whether a missing service is considered compliant
            
    Returns:
        Dictionary with actual_value and result ('Pass', 'Fail', or 'Error')
    """
    service_name = check.get('name', '')
    expected_status = check.get('expected_status')
    expected_startup = check.get('expected_startup')
    missing_is_compliant = check.get('missing_is_compliant', False)
    
    try:
        service_info = get_service_info(service_name)
        actual_status = service_info["status"]
        actual_startup = service_info["startup_type"]
        
        # Check if both status and startup type match expected values
        status_match = expected_status is None or actual_status == expected_status
        startup_match = expected_startup is None or actual_startup == expected_startup
        
        is_compliant = status_match and startup_match
        result = 'Pass' if is_compliant else 'Fail'
        
        actual_value = f"Status: {actual_status}, Startup: {actual_startup}"
        if not status_match:
            actual_value += f" (Expected Status: {expected_status})"
        if not startup_match:
            actual_value += f" (Expected Startup: {expected_startup})"
            
        return {'actual_value': actual_value, 'result': result}
    except Exception as e:
        # If service is missing, check if this is considered compliant
        if "The specified service does not exist" in str(e):
            result = 'Pass' if missing_is_compliant else 'Fail'
            return {'actual_value': f"Service '{service_name}' not found", 'result': result}
        else:
            return {'actual_value': str(e), 'result': 'Error'}

def check_service_permissions(check: Dict[str, Any]) -> Dict[str, Union[str, bool]]:
    """
    Check if a service has appropriate permissions.
    
    Args:
        check: Dictionary with check parameters:
            - name: Service name
            - expected_permissions: List of expected permissions/accounts
            - strict: Whether to require exact match or just containment
            
    Returns:
        Dictionary with actual_value and result ('Pass', 'Fail', or 'Error')
    """
    service_name = check.get('name', '')
    expected_perms = check.get('expected_permissions', [])
    strict_check = check.get('strict', False)
    
    try:
        # Get service's security descriptor
        service_handle = win32service.OpenService(
            win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ALL_ACCESS),
            service_name,
            win32service.SERVICE_QUERY_CONFIG
        )
        
        sd = win32service.QueryServiceObjectSecurity(
            service_handle,
            win32security.DACL_SECURITY_INFORMATION
        )
        
        # Get DACL from security descriptor
        dacl = sd.GetSecurityDescriptorDacl()
        
        # Check each ACE in the DACL
        current_perms = []
        for i in range(dacl.GetAceCount()):
            ace = dacl.GetAce(i)
            ace_type, ace_flags, mask = ace[0]
            
            # Get SID and try to translate to account name
            sid = ace[1]
            try:
                name, domain, sid_type = win32security.LookupAccountSid(None, sid)
                account = f"{domain}\\{name}" if domain else name
            except:
                account = str(sid)
                
            perm_info = f"{account} ({mask:08x})"
            current_perms.append(perm_info)
        
        # Compare with expected permissions
        if strict_check:
            # For strict comparison, lengths must match and all items must be in both lists
            is_compliant = len(current_perms) == len(expected_perms) and all(
                any(exp.lower() in curr.lower() for curr in current_perms)
                for exp in expected_perms
            )
        else:
            # For non-strict, just make sure all expected permissions are present
            is_compliant = all(
                any(exp.lower() in curr.lower() for curr in current_perms)
                for exp in expected_perms
            )
        
        result = 'Pass' if is_compliant else 'Fail'
        return {
            'actual_value': f"Permissions: {', '.join(current_perms)}",
            'result': result
        }
    except Exception as e:
        if "The specified service does not exist" in str(e):
            result = 'Pass' if check.get('missing_is_compliant', False) else 'Fail'
            return {'actual_value': f"Service '{service_name}' not found", 'result': result}
        else:
            logging.error(f"Error checking service permissions: {e}")
            return {'actual_value': str(e), 'result': 'Error'}

def check_service_dependencies(check: Dict[str, Any]) -> Dict[str, Union[str, bool]]:
    """
    Check a service's dependencies against expected values.
    
    Args:
        check: Dictionary with check parameters:
            - name: Service name
            - expected_dependencies: List of expected services this service depends on
            - expected_dependents: List of expected services that depend on this service
            
    Returns:
        Dictionary with actual_value and result ('Pass', 'Fail', or 'Error')
    """
    service_name = check.get('name', '')
    expected_deps = check.get('expected_dependencies', [])
    expected_dependents = check.get('expected_dependents', [])
    
    try:
        # Get service dependencies
        dependencies = win32serviceutil.EnumDependentServices(service_name, win32service.SERVICE_STATE_ALL)
        dependent_services = [dep[0] for dep in dependencies]
        
        # Get services this service depends on
        service_info = get_service_info(service_name)
        depends_on = service_info.get('dependencies', [])
        
        # Check if dependencies match
        deps_match = all(dep in depends_on for dep in expected_deps)
        dependents_match = all(dep in dependent_services for dep in expected_dependents)
        
        is_compliant = deps_match and dependents_match
        result = 'Pass' if is_compliant else 'Fail'
        
        actual_value = f"Depends on: {', '.join(depends_on) if depends_on else 'None'}"
        actual_value += f"; Dependents: {', '.join(dependent_services) if dependent_services else 'None'}"
        
        return {'actual_value': actual_value, 'result': result}
    except Exception as e:
        if "The specified service does not exist" in str(e):
            result = 'Pass' if check.get('missing_is_compliant', False) else 'Fail'
            return {'actual_value': f"Service '{service_name}' not found", 'result': result}
        else:
            logging.error(f"Error checking service dependencies: {e}")
            return {'actual_value': str(e), 'result': 'Error'}

def check_multiple_services(check: Dict[str, Any]) -> Dict[str, Union[str, bool]]:
    """
    Check multiple services at once against the same criteria.
    
    Args:
        check: Dictionary with check parameters:
            - names: List of service names to check
            - expected_status: Expected status string
            - expected_startup: Expected startup type
            
    Returns:
        Dictionary with actual_value and result ('Pass', 'Fail', or 'Error')
    """
    service_names = check.get('names', [])
    if not service_names:
        return {'actual_value': 'No services specified', 'result': 'Error'}
        
    expected_status = check.get('expected_status')
    expected_startup = check.get('expected_startup')
    missing_is_compliant = check.get('missing_is_compliant', False)
    
    results = []
    all_passed = True
    
    for service_name in service_names:
        service_check = {
            'name': service_name,
            'expected_status': expected_status,
            'expected_startup': expected_startup,
            'missing_is_compliant': missing_is_compliant
        }
        
        result = check_service_status(service_check)
        results.append(f"{service_name}: {result['actual_value']} - {result['result']}")
        
        if result['result'] != 'Pass':
            all_passed = False
    
    return {
        'actual_value': '; '.join(results),
        'result': 'Pass' if all_passed else 'Fail'
    }

def check_service(check: Dict[str, Any]) -> Dict[str, Union[str, bool]]:
    """
    Main function to route service checks based on check type.
    
    Args:
        check: Dictionary with check parameters
        
    Returns:
        Dictionary with actual_value and result ('Pass', 'Fail', or 'Error')
    """
    check_type = check.get('subtype', 'status')
    
    if check_type == 'status':
        return check_service_status(check)
    elif check_type == 'permissions':
        return check_service_permissions(check)
    elif check_type == 'dependencies':
        return check_service_dependencies(check)
    elif check_type == 'multiple':
        return check_multiple_services(check)
    else:
        logging.warning(f"Unknown service check type: {check_type}")
        return {'actual_value': f"Unknown check type: {check_type}", 'result': 'Error'}