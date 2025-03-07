def check_edge_settings(check):
    """Check Microsoft Edge security settings"""
    try:
        # Most Edge settings are in registry
        import registry_checks
        
        setting_name = check.get('setting', '')
        
        # Map setting names to registry paths
        edge_settings = {
            'block_third_party_cookies': {
                'hive': 'HKLM',
                'path': 'SOFTWARE\\Policies\\Microsoft\\Edge',
                'key': 'BlockThirdPartyCookies',
                'value_type': 'REG_DWORD',
                'expected_value': 1
            },
            'enable_site_isolation': {
                'hive': 'HKLM',
                'path': 'SOFTWARE\\Policies\\Microsoft\\Edge',
                'key': 'SitePerProcess',
                'value_type': 'REG_DWORD',
                'expected_value': 1
            },
            'tracking_prevention': {
                'hive': 'HKLM',
                'path': 'SOFTWARE\\Policies\\Microsoft\\Edge',
                'key': 'TrackingPrevention',
                'value_type': 'REG_DWORD',
                'expected_value': 2  # 0=off, 1=basic, 2=balanced, 3=strict
            },
            'disable_password_manager': {
                'hive': 'HKLM',
                'path': 'SOFTWARE\\Policies\\Microsoft\\Edge',
                'key': 'PasswordManagerEnabled',
                'value_type': 'REG_DWORD',
                'expected_value': 0
            },
            'prevent_smart_screen_override': {
                'hive': 'HKLM',
                'path': 'SOFTWARE\\Policies\\Microsoft\\Edge',
                'key': 'PreventSmartScreenPromptOverride',
                'value_type': 'REG_DWORD',
                'expected_value': 1
            }
        }
        
        if setting_name in edge_settings:
            registry_check = edge_settings[setting_name]
            return registry_checks.check_registry_value(registry_check)
        else:
            return {'actual_value': f"Unknown Edge setting: {setting_name}", 'result': 'Error'}
    except Exception as e:
        logging.error(f"Error checking Edge settings: {e}")
        return {'actual_value': str(e), 'result': 'Error'}

def check_defender_atp(check):
    """Check Windows Defender Advanced Threat Protection settings"""
    try:
        # Most Defender ATP settings are in registry
        import registry_checks
        
        setting_name = check.get('setting', '')
        
        # Map setting names to registry paths
        atp_settings = {
            'enable_atp': {
                'hive': 'HKLM',
                'path': 'SOFTWARE\\Policies\\Microsoft\\Windows Advanced Threat Protection',
                'key': 'Configuration',
                'value_type': 'REG_DWORD',
                'expected_value': 1
            },
            'sample_sharing': {
                'hive': 'HKLM',
                'path': 'SOFTWARE\\Policies\\Microsoft\\Windows Advanced Threat Protection',
                'key': 'AllowSampleCollection',
                'value_type': 'REG_DWORD',
                'expected_value': 1
            },
            'tamper_protection': {
                'hive': 'HKLM',
                'path': 'SOFTWARE\\Microsoft\\Windows Defender\\Features',
                'key': 'TamperProtection',
                'value_type': 'REG_DWORD',
                'expected_value': 1
            },
            'pua_protection': {
                'hive': 'HKLM',
                'path': 'SOFTWARE\\Policies\\Microsoft\\Windows Defender',
                'key': 'PUAProtection',
                'value_type': 'REG_DWORD',
                'expected_value': 1
            }
        }
        
        if setting_name in atp_settings:
            registry_check = atp_settings[setting_name]
            return registry_checks.check_registry_value(registry_check)
        else:
            # Try to check using PowerShell for some settings like tamper protection
            if setting_name == 'tamper_protection':
                cmd = ['powershell', '-Command', 'Get-MpComputerStatus | Select-Object IsTamperProtected']
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if "True" in result.stdout:
                    return {'actual_value': 'Tamper Protection is enabled', 'result': 'Pass'}
                else:
                    return {'actual_value': 'Tamper Protection is not enabled', 'result': 'Fail'}
            return {'actual_value': f"Unknown Defender ATP setting: {setting_name}", 'result': 'Error'}
    except Exception as e:
        logging.error(f"Error checking Defender ATP settings: {e}")
        return {'actual_value': str(e), 'result': 'Error'}

def check_tpm(check):
    """Check TPM (Trusted Platform Module) status"""
    try:
        # Check TPM status using PowerShell
        cmd = ['powershell', '-Command', 'Get-Tpm | Select-Object -Property TpmPresent,TpmReady,TpmEnabled']
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            return {'actual_value': f"Error running Get-Tpm: {result.stderr}", 'result': 'Error'}
        
        # Parse the output
        tpm_present = "TpmPresent : True" in result.stdout
        tpm_ready = "TpmReady : True" in result.stdout
        tpm_enabled = "TpmEnabled : True" in result.stdout
        
        if tpm_present and tpm_ready and tpm_enabled:
            status = "TPM is present, ready, and enabled"
            result = 'Pass'
        elif tpm_present:
            status = f"TPM is present but not fully configured (Ready: {tpm_ready}, Enabled: {tpm_enabled})"
            result = 'Fail'
        else:
            status = "TPM is not present"
            result = 'Fail'
            
        return {'actual_value': status, 'result': result}
    except Exception as e:
        logging.error(f"Error checking TPM: {e}")
        return {'actual_value': str(e), 'result': 'Error'}

def check_microsoft_store(check):
    """Check Microsoft Store app settings"""
    try:
        import registry_checks
        
        policy_name = check.get('policy', '')
        
        store_policies = {
            'disable_store': {
                'hive': 'HKLM',
                'path': 'SOFTWARE\\Policies\\Microsoft\\WindowsStore',
                'key': 'RemoveWindowsStore',
                'value_type': 'REG_DWORD',
                'expected_value': 1
            },
            'disable_store_apps': {
                'hive': 'HKLM',
                'path': 'SOFTWARE\\Policies\\Microsoft\\WindowsStore',
                'key': 'DisableStoreApplications',
                'value_type': 'REG_DWORD',
                'expected_value': 1
            },
            'require_private_store': {
                'hive': 'HKLM',
                'path': 'SOFTWARE\\Policies\\Microsoft\\WindowsStore',
                'key': 'RequirePrivateStoreOnly',
                'value_type': 'REG_DWORD',
                'expected_value': 1
            }
        }
        
        if policy_name in store_policies:
            registry_check = store_policies[policy_name]
            return registry_checks.check_registry_value(registry_check)
        else:
            return {'actual_value': f"Unknown Microsoft Store policy: {policy_name}", 'result': 'Error'}
    except Exception as e:
        logging.error(f"Error checking Microsoft Store policies: {e}")
        return {'actual_value': str(e), 'result': 'Error'}

def check_laps(check):
    """Check Local Administrator Password Solution (LAPS) settings"""
    try:
        import registry_checks
        
        # Check if LAPS is installed
        laps_check = {
            'hive': 'HKLM',
            'path': 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
            'subtype': 'values_in_key',
            'value_pattern': '.*LAPS.*',
            'expected_content': 'Local Administrator Password Solution',
            'content_comparison_op': 'contains',
            'should_match': True
        }
        
        # For values_in_key, we need to do a custom check since this isn't a direct registry check
        registry_values = registry_checks.check_registry_values_in_key(laps_check)
        
        if registry_values['result'] == 'Pass':
            # Check specific LAPS settings if installed
            setting_name = check.get('setting', '')
            
            if setting_name == 'password_age':
                # Check password age policy
                age_check = {
                    'hive': 'HKLM',
                    'path': 'SOFTWARE\\Policies\\Microsoft Services\\AdmPwd',
                    'key': 'PasswordAgeDays',
                    'value_type': 'REG_DWORD',
                    'expected_value': check.get('expected_value', 30),
                    'comparison_op': 'less_than_or_equal'
                }
                return registry_checks.check_registry_value(age_check)
            elif setting_name == 'complexity':
                # Check password complexity policy
                complexity_check = {
                    'hive': 'HKLM',
                    'path': 'SOFTWARE\\Policies\\Microsoft Services\\AdmPwd',
                    'key': 'PasswordComplexity',
                    'value_type': 'REG_DWORD',
                    'expected_value': check.get('expected_value', 4)
                }
                return registry_checks.check_registry_value(complexity_check)
            else:
                return {'actual_value': f"LAPS is installed, but unknown setting: {setting_name}", 'result': 'Error'}
        else:
            return {'actual_value': "LAPS is not installed", 'result': 'Fail'}
    except Exception as e:
        logging.error(f"Error checking LAPS: {e}")
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
    elif check.get('subtype') == 'edge_settings':
        return check_edge_settings(check)
    elif check.get('subtype') == 'defender_atp':
        return check_defender_atp(check)
    elif check.get('subtype') == 'tpm':
        return check_tpm(check)
    elif check.get('subtype') == 'microsoft_store':
        return check_microsoft_store(check)
    elif check.get('subtype') == 'laps':
        return check_laps(check)
    else:
        return {'actual_value': f"Unknown check subtype: {check.get('subtype')}", 'result': 'Error'}
