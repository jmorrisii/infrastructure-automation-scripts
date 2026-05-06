# Infrastructure Automation Scripts

Production-ready automation scripts for enterprise infrastructure management, developed through 10+ years of managing 100+ MSP client environments across healthcare, financial services, and professional sectors.

## Overview

This repository contains battle-tested automation tools used to maintain infrastructure uptime, ensure security compliance, and streamline operations across diverse technology stacks.

**Production Statistics:**
- Supporting 100+ enterprise clients
- Managing infrastructure serving 15,000+ users
- Maintaining 99.5% uptime across multi-tenant environments
- Preventing communication outages through proactive monitoring

## Repository Structure

```
infrastructure-automation-scripts/
├── powershell/          # Windows Server and cloud automation
├── python/              # Network device and infrastructure monitoring
├── bash/                # Linux server management and health checks
└── docs/                # Additional documentation and examples
```

## Scripts Included

### PowerShell Scripts

#### `New-BulkADUsers.ps1`
Bulk Active Directory user creation and configuration from CSV input.

**Features:**
- Automated user account provisioning with naming conventions
- Group membership assignment
- Secure password generation
- Home directory creation
- Comprehensive logging and error handling

**Use Case:** Onboarding new employees across multiple client organizations

```powershell
.\New-BulkADUsers.ps1 -CSVPath "users.csv" -OUPath "OU=Users,DC=contoso,DC=com" -Domain "contoso.com"
```

#### `Get-ExchangeOnlineReport.ps1`
Comprehensive Exchange Online mailbox audit and reporting tool.

**Features:**
- Mailbox size and usage statistics
- Inactive mailbox identification (90+ days)
- Permission audit (FullAccess, SendAs, SendOnBehalf)
- Forwarding rule detection
- Litigation hold status

**Use Case:** Monthly compliance reporting for 75+ enterprise M365 tenants

```powershell
.\Get-ExchangeOnlineReport.ps1 -TenantName "ContosoLLC" -ExportPath "C:\Reports" -IncludeArchive
```

#### `Get-AzureInventory.ps1`
Azure resource inventory and cost optimization analysis.

**Features:**
- VM inventory with power state and sizing
- Storage account usage analysis
- Network security group rules audit
- Unused resource identification
- Cost optimization recommendations

**Use Case:** Cloud infrastructure governance and cost management

```powershell
.\Get-AzureInventory.ps1 -SubscriptionId "12345..." -ExportPath "C:\Reports" -IncludeCostAnalysis
```

### Python Scripts

#### `network_device_backup.py`
Automated network device configuration backup via SSH.

**Features:**
- Multi-threaded device backup (Cisco, Fortinet, generic SSH devices)
- Configuration change detection with versioning
- Automated archiving of previous configurations
- Password sanitization for security
- Comprehensive logging and error handling

**Use Case:** Daily automated backup of 100+ network devices across client environments

```bash
python network_device_backup.py -i inventory.json -b /backups -w 10
```

**Inventory Format (JSON):**
```json
{
  "default_username": "admin",
  "default_password": "password",
  "devices": [
    {
      "hostname": "firewall-01",
      "ip_address": "10.1.1.1",
      "device_type": "fortinet",
      "port": 22
    },
    {
      "hostname": "core-switch-01",
      "ip_address": "10.1.1.2",
      "device_type": "cisco_ios"
    }
  ]
}
```

#### `ssl_certificate_monitor.py`
SSL/TLS certificate expiration monitoring and alerting.

**Features:**
- Multi-threaded certificate checking
- Configurable warning/critical thresholds
- CSV report generation
- Historical tracking
- Identifies expired, critical (1-7 days), and warning (8-30 days) certificates

**Use Case:** Prevented communication outages for 15,000+ users through proactive SSL certificate management

```bash
python ssl_certificate_monitor.py -f hosts.txt -o /reports -w 30 -c 7
```

**Hosts Format (Plain Text):**
```
mail.contoso.com
portal.fabrikam.com:8443
firewall.example.com:443
```

### Bash Scripts

#### `linux_health_check.sh`
Comprehensive Linux server health monitoring and reporting.

**Features:**
- CPU, memory, and disk utilization monitoring
- Critical service status checks
- Security update identification
- Failed login attempt audit
- Network statistics and listening ports
- Automated report generation

**Use Case:** Daily health checks on 100+ enterprise Linux servers

```bash
sudo ./linux_health_check.sh
```

## Requirements

### PowerShell Scripts
- **PowerShell 5.1+** or **PowerShell Core 7+**
- Required modules (installed automatically):
  - ActiveDirectory (for `New-BulkADUsers.ps1`)
  - ExchangeOnlineManagement (for `Get-ExchangeOnlineReport.ps1`)
  - Az.* modules (for `Get-AzureInventory.ps1`)

### Python Scripts
- **Python 3.7+**
- Required packages:
  ```bash
  pip install paramiko  # For network_device_backup.py
  ```

### Bash Scripts
- **Bash 4.0+**
- Linux distributions: Ubuntu, Debian, RHEL, CentOS
- Root or sudo privileges for full health checks

## Installation

### Clone Repository
```bash
git clone https://github.com/jmorrisii/infrastructure-automation-scripts.git
cd infrastructure-automation-scripts
```

### Python Dependencies
```bash
pip install -r requirements.txt
```

### Make Bash Scripts Executable
```bash
chmod +x bash/*.sh
```

## Usage Examples

### Daily Network Device Backups
```bash
# Cron job for daily 2 AM backup
0 2 * * * /usr/bin/python3 /opt/scripts/network_device_backup.py -i /etc/devices.json -b /backups/network
```

### Weekly SSL Certificate Monitoring
```bash
# Cron job for weekly Sunday check
0 6 * * 0 /usr/bin/python3 /opt/scripts/ssl_certificate_monitor.py -f /etc/ssl_hosts.txt -o /var/reports
```

### Monthly Azure Cost Reports
```powershell
# Scheduled task for first day of month
$Trigger = New-ScheduledTaskTrigger -Monthly -At 8am -DaysOfMonth 1
$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File C:\Scripts\Get-AzureInventory.ps1"
Register-ScheduledTask -TaskName "Azure Monthly Report" -Trigger $Trigger -Action $Action
```

## Security Best Practices

### Credential Management
- **Never hardcode passwords** in scripts or inventory files
- Use secure credential stores:
  - Windows: PowerShell SecureString or Windows Credential Manager
  - Linux: Encrypted configuration files or secrets management tools
  - Azure: Azure Key Vault
  - AWS: AWS Secrets Manager

### File Permissions
```bash
# Secure inventory files containing credentials
chmod 600 inventory.json
chown root:root inventory.json
```

### Logging
- All scripts include comprehensive logging
- Log files contain timestamps, severity levels, and detailed error messages
- Review logs regularly for security events and failures

## Maintenance and Support

### Version History
- **v4.x** - Current production versions
- Tested on: Windows Server 2016/2019/2022, Ubuntu 18.04/20.04/22.04, RHEL/CentOS 7/8

### Contributing
These scripts are provided as examples from production MSP environments. Feel free to:
- Adapt for your specific environment
- Add additional functionality
- Report issues or suggestions

### Known Limitations
- Network device backups require SSH access and appropriate credentials
- Azure scripts require appropriate RBAC permissions (Reader minimum, Billing Reader for cost data)
- SSL monitoring requires network access to monitored hosts on specified ports

## Author

**Jonathan Morris**  
Senior Infrastructure Engineer  
10+ years MSP experience supporting enterprise infrastructure

**Certifications:**
- Cisco Certified Network Associate (CCNA)
- AWS Certified Cloud Practitioner
- Microsoft Certified: Azure Administrator (AZ-104)
- CompTIA Security+

**Connect:**
- LinkedIn: [linkedin.com/in/jmorrisii](https://linkedin.com/in/jmorrisii)
- Email: j.morris@cyberservices.com

## License

MIT License - See LICENSE file for details

## Acknowledgments

Developed through practical experience managing:
- Healthcare infrastructure (HIPAA compliance)
- Financial services systems (PCI-DSS compliance)
- Multi-tenant MSP environments
- Cloud and hybrid infrastructure deployments

---

**Production Stats:**
- 99.5% infrastructure uptime
- 95% Tier-3 escalation resolution within SLA
- $1.2M annual cost savings through infrastructure optimization
- 15,000+ users supported across 100+ client environments
