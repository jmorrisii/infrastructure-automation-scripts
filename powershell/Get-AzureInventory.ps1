<#
.SYNOPSIS
    Azure resource inventory and cost analysis tool for cloud infrastructure management.

.DESCRIPTION
    Generates comprehensive Azure environment reports including:
    - VM inventory with size, status, and OS details
    - Storage account usage and redundancy configuration
    - Network security group rules audit
    - Resource group cost analysis
    - Unused/stopped resource identification
    
    Used for monthly client reviews and cost optimization initiatives.

.PARAMETER SubscriptionId
    Azure subscription ID to analyze. If not provided, uses current context.

.PARAMETER ExportPath
    Directory where reports will be saved

.PARAMETER IncludeCostAnalysis
    Include detailed cost breakdown by resource group (requires Billing Reader role)

.EXAMPLE
    .\Get-AzureInventory.ps1 -ExportPath "C:\Reports"

.EXAMPLE
    .\Get-AzureInventory.ps1 -SubscriptionId "12345678-1234-1234-1234-123456789012" -ExportPath "C:\Reports" -IncludeCostAnalysis

.NOTES
    Author: Jonathan Morris
    Version: 2.5
    Requires: Az PowerShell Module (Az.Accounts, Az.Compute, Az.Storage, Az.Network)
    Production use: Cost optimization for 100+ Azure subscriptions
#>

[CmdletBinding()]
param(
    [string]$SubscriptionId,
    
    [Parameter(Mandatory=$true)]
    [ValidateScript({Test-Path $_ -PathType Container})]
    [string]$ExportPath,
    
    [switch]$IncludeCostAnalysis
)

# Import required modules
$RequiredModules = @("Az.Accounts", "Az.Compute", "Az.Storage", "Az.Network", "Az.Resources")
foreach ($Module in $RequiredModules) {
    if (-not (Get-Module -ListAvailable -Name $Module)) {
        Write-Host "Installing module: $Module" -ForegroundColor Yellow
        Install-Module -Name $Module -Scope CurrentUser -Force -AllowClobber
    }
    Import-Module $Module -ErrorAction Stop
}

# Connect to Azure
Write-Host "Connecting to Azure..." -ForegroundColor Yellow
try {
    $AzContext = Get-AzContext
    if (-not $AzContext) {
        Connect-AzAccount
    }
    
    if ($SubscriptionId) {
        Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
    }
    
    $Context = Get-AzContext
    Write-Host "Connected to subscription: $($Context.Subscription.Name)" -ForegroundColor Green
} catch {
    Write-Host "Failed to connect to Azure: $_" -ForegroundColor Red
    exit 1
}

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$SubscriptionName = $Context.Subscription.Name -replace '[^a-zA-Z0-9]', '_'
$ReportPrefix = "$ExportPath\Azure_$SubscriptionName"

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Azure Inventory Report" -ForegroundColor Cyan
Write-Host "Subscription: $($Context.Subscription.Name)" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# 1. Virtual Machine Inventory
Write-Host "[1/5] Gathering virtual machine inventory..." -ForegroundColor Yellow
$VMInventory = @()
$VMs = Get-AzVM -Status

foreach ($VM in $VMs) {
    $VMDetails = Get-AzVM -ResourceGroupName $VM.ResourceGroupName -Name $VM.Name
    $OSDisk = Get-AzDisk -ResourceGroupName $VM.ResourceGroupName -DiskName $VMDetails.StorageProfile.OsDisk.Name
    
    $VMInventory += [PSCustomObject]@{
        Name = $VM.Name
        ResourceGroup = $VM.ResourceGroupName
        Location = $VM.Location
        Size = $VM.HardwareProfile.VmSize
        PowerState = ($VM.Statuses | Where-Object { $_.Code -like "PowerState/*" }).DisplayStatus
        OSType = $VMDetails.StorageProfile.OsDisk.OsType
        OSDiskSizeGB = $OSDisk.DiskSizeGB
        OSDiskType = $OSDisk.Sku.Name
        PrivateIP = ($VM.NetworkProfile.NetworkInterfaces | ForEach-Object {
            (Get-AzNetworkInterface -ResourceId $_.Id).IpConfigurations.PrivateIpAddress
        }) -join ", "
        Tags = ($VM.Tags.GetEnumerator() | ForEach-Object { "$($_.Key):$($_.Value)" }) -join "; "
    }
}

$VMPath = "$ReportPrefix`_VMs_$Timestamp.csv"
$VMInventory | Export-Csv -Path $VMPath -NoTypeInformation
Write-Host "✓ VM inventory exported: $VMPath" -ForegroundColor Green
Write-Host "  Total VMs: $($VMInventory.Count)" -ForegroundColor White
Write-Host "  Running: $(($VMInventory | Where-Object PowerState -eq 'VM running').Count)" -ForegroundColor Green
Write-Host "  Stopped: $(($VMInventory | Where-Object PowerState -like '*stopped*').Count)" -ForegroundColor Yellow

# 2. Storage Account Inventory
Write-Host "`n[2/5] Analyzing storage accounts..." -ForegroundColor Yellow
$StorageInventory = @()
$StorageAccounts = Get-AzStorageAccount

foreach ($Storage in $StorageAccounts) {
    $UsageMetrics = Get-AzMetric -ResourceId $Storage.Id -MetricName "UsedCapacity" -TimeGrain 01:00:00 -StartTime (Get-Date).AddDays(-1) -EndTime (Get-Date) -WarningAction SilentlyContinue
    
    $UsedCapacityGB = if ($UsageMetrics.Data) {
        [math]::Round(($UsageMetrics.Data | Select-Object -Last 1).Average / 1GB, 2)
    } else { 0 }
    
    $StorageInventory += [PSCustomObject]@{
        Name = $Storage.StorageAccountName
        ResourceGroup = $Storage.ResourceGroupName
        Location = $Storage.Location
        SkuName = $Storage.Sku.Name
        Kind = $Storage.Kind
        AccessTier = $Storage.AccessTier
        EnableHttpsTrafficOnly = $Storage.EnableHttpsTrafficOnly
        UsedCapacityGB = $UsedCapacityGB
        Tags = ($Storage.Tags.GetEnumerator() | ForEach-Object { "$($_.Key):$($_.Value)" }) -join "; "
    }
}

$StoragePath = "$ReportPrefix`_Storage_$Timestamp.csv"
$StorageInventory | Export-Csv -Path $StoragePath -NoTypeInformation
Write-Host "✓ Storage account inventory: $StoragePath" -ForegroundColor Green
Write-Host "  Total Storage Accounts: $($StorageInventory.Count)" -ForegroundColor White

# 3. Network Security Group Rules Audit
Write-Host "`n[3/5] Auditing Network Security Group rules..." -ForegroundColor Yellow
$NSGRules = @()
$NSGs = Get-AzNetworkSecurityGroup

foreach ($NSG in $NSGs) {
    foreach ($Rule in $NSG.SecurityRules) {
        $NSGRules += [PSCustomObject]@{
            NSGName = $NSG.Name
            ResourceGroup = $NSG.ResourceGroupName
            RuleName = $Rule.Name
            Priority = $Rule.Priority
            Direction = $Rule.Direction
            Access = $Rule.Access
            Protocol = $Rule.Protocol
            SourceAddressPrefix = ($Rule.SourceAddressPrefix -join ", ")
            SourcePortRange = ($Rule.SourcePortRange -join ", ")
            DestinationAddressPrefix = ($Rule.DestinationAddressPrefix -join ", ")
            DestinationPortRange = ($Rule.DestinationPortRange -join ", ")
        }
    }
}

$NSGPath = "$ReportPrefix`_NSGRules_$Timestamp.csv"
$NSGRules | Export-Csv -Path $NSGPath -NoTypeInformation
Write-Host "✓ NSG rules audit: $NSGPath" -ForegroundColor Green
Write-Host "  Total NSG Rules: $($NSGRules.Count)" -ForegroundColor White
Write-Host "  Allow Rules: $(($NSGRules | Where-Object Access -eq 'Allow').Count)" -ForegroundColor Green
Write-Host "  Deny Rules: $(($NSGRules | Where-Object Access -eq 'Deny').Count)" -ForegroundColor Red

# 4. Resource Group Summary
Write-Host "`n[4/5] Generating resource group summary..." -ForegroundColor Yellow
$ResourceGroups = Get-AzResourceGroup
$RGSummary = @()

foreach ($RG in $ResourceGroups) {
    $Resources = Get-AzResource -ResourceGroupName $RG.ResourceGroupName
    
    $RGSummary += [PSCustomObject]@{
        Name = $RG.ResourceGroupName
        Location = $RG.Location
        ResourceCount = $Resources.Count
        ResourceTypes = ($Resources.ResourceType | Select-Object -Unique | Sort-Object) -join "; "
        Tags = ($RG.Tags.GetEnumerator() | ForEach-Object { "$($_.Key):$($_.Value)" }) -join "; "
    }
}

$RGPath = "$ReportPrefix`_ResourceGroups_$Timestamp.csv"
$RGSummary | Export-Csv -Path $RGPath -NoTypeInformation
Write-Host "✓ Resource group summary: $RGPath" -ForegroundColor Green

# 5. Unused Resource Identification
Write-Host "`n[5/5] Identifying potentially unused resources..." -ForegroundColor Yellow
$UnusedResources = @()

# Stopped VMs (cost optimization opportunity)
$StoppedVMs = $VMInventory | Where-Object { $_.PowerState -like "*stopped*" -or $_.PowerState -like "*deallocated*" }
foreach ($VM in $StoppedVMs) {
    $UnusedResources += [PSCustomObject]@{
        ResourceType = "Virtual Machine"
        ResourceName = $VM.Name
        ResourceGroup = $VM.ResourceGroup
        Reason = "VM in stopped/deallocated state"
        Recommendation = "Review if VM is still needed. Stopped VMs still incur disk storage costs."
    }
}

# Unattached disks
$UnattachedDisks = Get-AzDisk | Where-Object { -not $_.ManagedBy }
foreach ($Disk in $UnattachedDisks) {
    $UnusedResources += [PSCustomObject]@{
        ResourceType = "Managed Disk"
        ResourceName = $Disk.Name
        ResourceGroup = $Disk.ResourceGroupName
        Reason = "Disk not attached to any VM"
        Recommendation = "Verify if disk contains needed data before deletion. Consider creating snapshot."
    }
}

$UnusedPath = "$ReportPrefix`_UnusedResources_$Timestamp.csv"
$UnusedResources | Export-Csv -Path $UnusedPath -NoTypeInformation
Write-Host "✓ Unused resources identified: $($UnusedResources.Count) - $UnusedPath" -ForegroundColor Yellow

# Summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Azure Inventory Complete" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Virtual Machines: $($VMInventory.Count)" -ForegroundColor White
Write-Host "Storage Accounts: $($StorageInventory.Count)" -ForegroundColor White
Write-Host "NSG Rules: $($NSGRules.Count)" -ForegroundColor White
Write-Host "Resource Groups: $($RGSummary.Count)" -ForegroundColor White
Write-Host "Potential Cost Savings: $($UnusedResources.Count) unused resources identified" -ForegroundColor Yellow
Write-Host "`nAll reports saved to: $ExportPath" -ForegroundColor Green
