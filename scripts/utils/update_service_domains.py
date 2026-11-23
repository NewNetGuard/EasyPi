#!/usr/bin/env python3
"""
Update netprotection_service.py to use service_domains module
"""

import re

filepath = '/opt/EasyPi/backend/app/services/netprotection_service.py'

with open(filepath, 'r') as f:
    content = f.read()

# Check if already using the module import
if 'from easypi_netprotection.service_domains import' in content:
    print('Already using service_domains module!')
    exit(0)

# 1. Find and remove the inline SERVICE_DOMAINS dict
# It starts with "SERVICE_DOMAINS = {" and ends before "class NetProtectionService:"
pattern = r'# Service-to-domains mapping.*?^SERVICE_DOMAINS = \{.*?\n\}\n\n'
match = re.search(pattern, content, re.MULTILINE | re.DOTALL)

if match:
    content = content[:match.start()] + content[match.end():]
    print('Removed inline SERVICE_DOMAINS dict')
else:
    # Try alternative pattern - may have been patched differently
    pattern2 = r'^SERVICE_DOMAINS = \{.*?\n\}\n'
    match2 = re.search(pattern2, content, re.MULTILINE | re.DOTALL)
    if match2:
        content = content[:match2.start()] + content[match2.end():]
        print('Removed inline SERVICE_DOMAINS dict (alt pattern)')

# 2. Add import after existing netprotection imports
import_line = '\n# Service domains for parental control\nfrom easypi_netprotection.service_domains import SERVICE_DOMAINS, SERVICE_CATEGORIES, get_all_domains_for_services\n'

# Find where to insert - after "FLOW_LOGGER_AVAILABLE = True" section
insert_marker = 'except ImportError as e:\n    logger.warning(f"FlowLogger module not available: {e}")'
if insert_marker in content:
    content = content.replace(
        insert_marker,
        insert_marker + import_line
    )
    print('Added import for service_domains module')
else:
    print('WARNING: Could not find import insertion point')

# 3. Update the blacklist building logic to use get_all_domains_for_services
old_logic = '''                if blocked_services:
                    for service in blocked_services:
                        service_key = service.strip().lower()
                        # Check if service has predefined domains
                        if service_key in SERVICE_DOMAINS:
                            blacklist.extend(SERVICE_DOMAINS[service_key])
                        else:
                            # Fallback: treat as domain
                            domain = service_key
                            # Validate domain format
                            if not domain or len(domain) > 253:
                                continue
                            if not all(c.isalnum() or c in '.-' for c in domain):
                                continue
                            if '.' not in domain:
                                domain = f"{domain}.com"
                            if '..' in domain or domain.startswith('.') or domain.endswith('.'):
                                continue
                            blacklist.append(domain)
                            if not domain.startswith("www."):
                                blacklist.append(f"www.{domain}")
                            blacklist.append(f"*.{domain}")'''

new_logic = '''                if blocked_services:
                    # Use service_domains module to get all domains for services/categories
                    blacklist = get_all_domains_for_services(blocked_services)'''

if old_logic in content:
    content = content.replace(old_logic, new_logic)
    print('Updated blacklist building logic to use get_all_domains_for_services')
else:
    print('NOTE: Old logic not found - may already be updated or different')

# Write back
with open(filepath, 'w') as f:
    f.write(content)

print('Update completed!')
