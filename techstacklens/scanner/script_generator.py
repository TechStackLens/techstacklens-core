"""
Script generator for TechStackLens: generates standalone scanner scripts (PowerShell or Python)
based on selected technology stacks.
"""
import os


def generate_powershell_scanner(selected_stacks):
    ps_lines = [
        '# PowerShell TechStackLens Scanner Script',
        '$ErrorActionPreference = "Stop"',
        '',
    ]
    # IIS scanning logic
    if 'iis' in selected_stacks:
        ps_lines += [
            '# Get IIS Sites',
            '$sites = Get-Website | Select-Object Name, ID, State, PhysicalPath',
            '',
            '# Build results object',
            '$results = @{',
            '    iis_sites = @()',
            '    hostname_map = @{}',
            '    app_types = @{}',
            '}',
            '',
            'foreach ($site in $sites) {',
            '    $siteObj = @{',
            '        id = $site.ID',
            '        name = $site.Name',
            '        state = $site.State',
            '        physical_path = $site.PhysicalPath',
            '        bindings = @()',
            '    }',
            '    # Get bindings for this site',
            '    $siteBindings = Get-WebBinding -Name $site.Name',
            '    foreach ($binding in $siteBindings) {',
            '        $bindingObj = @{',
            '            protocol = $binding.protocol',
            '            bindingInformation = $binding.bindingInformation',
            '            hostname = $binding.HostHeader',
            '            port = $binding.Port',
            '            ip = $binding.IP',
            '        }',
            '        $siteObj.bindings += $bindingObj',
            '        if ($binding.HostHeader) {',
            '            $results.hostname_map[$binding.HostHeader] = @{',
            '                site_name = $site.Name',
            '                site_id = $site.ID',
            '                ip = $binding.IP',
            '                port = $binding.Port',
            '                protocol = $binding.protocol',
            '            }',
            '        }',
            '    }',
            '    $results.iis_sites += $siteObj',
            '}',
            '',
        ]
    # Network scanning logic (using nmap if available)
    if 'network' in selected_stacks:
        ps_lines += [
            '# Network scan using nmap',
            '$nmapPath = "nmap"',
            '$networkRange = Read-Host "Enter network range to scan (e.g., 192.168.1.0/24)"',
            '$nmapOutput = "nmap_scan.xml"',
            'Write-Host "Running nmap scan..."',
            'if ($networkRange) {',
            '    & $nmapPath -sV -oX $nmapOutput $networkRange',
            '    $results.network_scan = Get-Content $nmapOutput -Raw',
            '}',
            '',
        ]
    # Docker scanning logic (basic example)
    if 'docker' in selected_stacks:
        ps_lines += [
            '# Docker scan',
            'Write-Host "Collecting Docker info..."',
            '$dockerInfo = & docker info 2>&1',
            '$results.docker_info = $dockerInfo',
            '',
        ]
    # Add more PowerShell logic for other Windows-friendly stacks as needed
    ps_lines += [
        '# Output as JSON',
        '$json = $results | ConvertTo-Json -Depth 6',
        '$output = "techstacklens_scan_results.json"',
        'Set-Content -Path $output -Value $json',
        'Write-Host "Scan complete. Results saved to $output"',
    ]
    return '\n'.join(ps_lines)


def generate_python_scanner(selected_stacks):
    script_lines = [
        "#!/usr/bin/env python3",
        '"""TechStackLens Custom Scanner Script\n\nGenerated for: ' + ', '.join(selected_stacks) + '\n"""',
        "import sys",
        "import json",
        "import logging",
        "import argparse",
        "from pathlib import Path",
        "from datetime import datetime",
    ]
    # Inline scanner code for each selected stack
    scanner_dir = os.path.join(os.path.dirname(__file__), '')
    if 'network' in selected_stacks:
        with open(os.path.join(scanner_dir, 'network_scanner.py'), 'r') as f:
            script_lines.append(f.read())
    if 'iis' in selected_stacks:
        with open(os.path.join(scanner_dir, 'iis_scanner.py'), 'r') as f:
            script_lines.append(f.read())
    if 'cloud' in selected_stacks:
        with open(os.path.join(scanner_dir, 'cloud_scanner.py'), 'r') as f:
            script_lines.append(f.read())
    if 'lamp' in selected_stacks:
        with open(os.path.join(scanner_dir, 'lamp_scanner.py'), 'r') as f:
            script_lines.append(f.read())
    if 'tomcat' in selected_stacks:
        with open(os.path.join(scanner_dir, 'tomcat_scanner.py'), 'r') as f:
            script_lines.append(f.read())
    if 'jboss' in selected_stacks:
        with open(os.path.join(scanner_dir, 'jboss_scanner.py'), 'r') as f:
            script_lines.append(f.read())
    if 'xampp' in selected_stacks:
        with open(os.path.join(scanner_dir, 'xampp_scanner.py'), 'r') as f:
            script_lines.append(f.read())
    if 'nodejs' in selected_stacks:
        with open(os.path.join(scanner_dir, 'nodejs_scanner.py'), 'r') as f:
            script_lines.append(f.read())
    if 'react' in selected_stacks:
        with open(os.path.join(scanner_dir, 'react_scanner.py'), 'r') as f:
            script_lines.append(f.read())
    if 'kubernetes' in selected_stacks:
        with open(os.path.join(scanner_dir, 'kubectl_scanner.py'), 'r') as f:
            script_lines.append(f.read())
    if 'docker' in selected_stacks:
        with open(os.path.join(scanner_dir, 'docker_scanner.py'), 'r') as f:
            script_lines.append(f.read())
    if 'mean' in selected_stacks:
        with open(os.path.join(scanner_dir, 'mean_scanner.py'), 'r') as f:
            script_lines.append(f.read())
    script_lines.append("")
    script_lines.append("def main():")
    script_lines.append("    parser = argparse.ArgumentParser(description=\"TechStackLens Custom Scanner\")")
    if 'network' in selected_stacks:
        script_lines.append("    parser.add_argument('--network-range', help='Network range to scan (e.g., 192.168.1.0/24)')")
    script_lines.append("    parser.add_argument('--output', default='techstacklens_scan_results.json', help='Output JSON file')")
    script_lines.append("    args = parser.parse_args()")
    script_lines.append("")
    script_lines.append("    results = {}")
    if 'network' in selected_stacks:
        script_lines.append("    if args.network_range:")
        script_lines.append("        try:")
        script_lines.append("            scanner = NetworkScanner()")
        script_lines.append("            results.update(scanner.scan(args.network_range))")
        script_lines.append("        except Exception as e:")
        script_lines.append("            logging.warning(f'Network scan failed: {e}')")
    if 'iis' in selected_stacks:
        script_lines.append("    try:")
        script_lines.append("        scanner = IISScanner()")
        script_lines.append("        results.update(scanner.scan())")
        script_lines.append("    except Exception as e:")
        script_lines.append("        logging.warning(f'IIS scan failed: {e}')")
    if 'cloud' in selected_stacks:
        script_lines.append("    try:")
        script_lines.append("        scanner = CloudScanner()")
        script_lines.append("        results.update(scanner.scan())")
        script_lines.append("    except Exception as e:")
        script_lines.append("        logging.warning(f'Cloud scan failed: {e}')")
    if 'lamp' in selected_stacks:
        script_lines.append("    try:")
        script_lines.append("        scanner = LAMPScanner()")
        script_lines.append("        results.update(scanner.scan())")
        script_lines.append("    except Exception as e:")
        script_lines.append("        logging.warning(f'LAMP scan failed: {e}')")
    if 'tomcat' in selected_stacks:
        script_lines.append("    try:")
        script_lines.append("        scanner = TomcatScanner()")
        script_lines.append("        results.update(scanner.scan())")
        script_lines.append("    except Exception as e:")
        script_lines.append("        logging.warning(f'Tomcat scan failed: {e}')")
    if 'jboss' in selected_stacks:
        script_lines.append("    try:")
        script_lines.append("        scanner = JBossScanner()")
        script_lines.append("        results.update(scanner.scan())")
        script_lines.append("    except Exception as e:")
        script_lines.append("        logging.warning(f'JBoss scan failed: {e}')")
    if 'xampp' in selected_stacks:
        script_lines.append("    try:")
        script_lines.append("        scanner = XAMPPScanner()")
        script_lines.append("        results.update(scanner.scan())")
        script_lines.append("    except Exception as e:")
        script_lines.append("        logging.warning(f'XAMPP scan failed: {e}')")
    if 'nodejs' in selected_stacks:
        script_lines.append("    try:")
        script_lines.append("        scanner = NodejsScanner()")
        script_lines.append("        results.update(scanner.scan())")
        script_lines.append("    except Exception as e:")
        script_lines.append("        logging.warning(f'Node.js scan failed: {e}')")
    if 'react' in selected_stacks:
        script_lines.append("    try:")
        script_lines.append("        scanner = ReactScanner()")
        script_lines.append("        results.update(scanner.scan())")
        script_lines.append("    except Exception as e:")
        script_lines.append("        logging.warning(f'React scan failed: {e}')")
    if 'kubernetes' in selected_stacks:
        script_lines.append("    try:")
        script_lines.append("        scanner = KubectlScanner()")
        script_lines.append("        results.update(scanner.scan())")
        script_lines.append("    except Exception as e:")
        script_lines.append("        logging.warning(f'Kubernetes scan failed: {e}')")
    if 'docker' in selected_stacks:
        script_lines.append("    try:")
        script_lines.append("        scanner = DockerScanner()")
        script_lines.append("        results.update(scanner.scan())")
        script_lines.append("    except Exception as e:")
        script_lines.append("        logging.warning(f'Docker scan failed: {e}')")
    if 'mean' in selected_stacks:
        script_lines.append("    try:")
        script_lines.append("        scanner = MEANScanner()")
        script_lines.append("        results.update(scanner.scan())")
        script_lines.append("    except Exception as e:")
        script_lines.append("        logging.warning(f'MEAN scan failed: {e}')")
    script_lines.append("")
    script_lines.append("    with open(args.output, 'w') as f:")
    script_lines.append("        json.dump(results, f, indent=2)")
    script_lines.append("    print(f'Scan complete. Results saved to {args.output}')")
    script_lines.append("")
    script_lines.append("if __name__ == '__main__':")
    script_lines.append("    main()")
    return '\n'.join(script_lines)


def generate_scanner_script(selected_stacks, script_type='auto'):
    """
    Generate a scanner script (PowerShell or Python) based on selected stacks.
    script_type: 'auto', 'powershell', or 'python'
    Returns: (script_content, script_ext)
    """
    # Normalize stack names
    selected_stacks = [s.strip().lower() for s in selected_stacks]
    if script_type == 'powershell' or (script_type == 'auto' and 'iis' in selected_stacks):
        return generate_powershell_scanner(selected_stacks), 'ps1'
    else:
        return generate_python_scanner(selected_stacks), 'py'
