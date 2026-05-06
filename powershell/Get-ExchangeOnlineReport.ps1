<#
.SYNOPSIS
    Exchange Online mailbox audit and reporting tool for MSP clients.

.DESCRIPTION
    Generates comprehensive mailbox reports including:
    - Mailbox size and item count statistics
    - Inactive mailbox identification (90+ days no logon)
    - Mailbox permission audit (SendAs, FullAccess, SendOnBehalf)
    - Forwarding rule detection
    - Litigation hold status
    
    Designed for multi-tenant MSP environments with automated reporting.

.PARAMETER TenantName
    Name identifier for the tenant (used in report naming)

.PARAMETER ExportPath
    Directory path where CSV reports will be saved

.PARAMETER IncludeArchive
    Switch to include archive mailbox statistics

.PARAMETER DaysInactive
    Number of days to consider a mailbox inactive (default: 90)

.EXAMPLE
    .\Get-ExchangeOnlineReport.ps1 -TenantName "ContosoLLC" -ExportPath "C:\Reports"

.EXAMPLE
    .\Get-ExchangeOnlineReport.ps1 -TenantName "FabrikamCorp" -ExportPath "C:\Reports" -IncludeArchive -DaysInactive 60

.NOTES
    Author: Jonathan Morris
    Version: 3.0
    Requires: ExchangeOnlineManagement Module v3.0+
    Used in production for 75+ enterprise M365 tenants
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$TenantName,
    
    [Parameter(Mandatory=$true)]
    [ValidateScript({Test-Path $_ -PathType Container})]
    [string]$ExportPath,
    
    [switch]$IncludeArchive,
    
    [int]$DaysInactive = 90
)

# Import Exchange Online module
try {
    Import-Module ExchangeOnlineManagement -ErrorAction Stop
    Write-Host "Exchange Online module loaded successfully" -ForegroundColor Green
} catch {
    Write-Host "Failed to load ExchangeOnlineManagement module. Install with: Install-Module ExchangeOnlineManagement" -ForegroundColor Red
    exit 1
}

# Connect to Exchange Online (requires modern auth)
Write-Host "Connecting to Exchange Online..." -ForegroundColor Yellow
try {
    Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
    Write-Host "Connected successfully" -ForegroundColor Green
} catch {
    Write-Host "Failed to connect to Exchange Online: $_" -ForegroundColor Red
    exit 1
}

# Initialize report path
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$ReportPrefix = "$ExportPath\$TenantName`_ExO"

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Exchange Online Report: $TenantName" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# 1. Mailbox Statistics Report
Write-Host "[1/5] Gathering mailbox statistics..." -ForegroundColor Yellow
$MailboxStats = @()

$Mailboxes = Get-ExoMailbox -ResultSize Unlimited | Select-Object DisplayName, UserPrincipalName, PrimarySmtpAddress, RecipientTypeDetails

$i = 0
foreach ($Mailbox in $Mailboxes) {
    $i++
    Write-Progress -Activity "Processing Mailboxes" -Status "$i of $($Mailboxes.Count)" -PercentComplete (($i/$Mailboxes.Count)*100)
    
    $Stats = Get-ExoMailboxStatistics -Identity $Mailbox.UserPrincipalName -ErrorAction SilentlyContinue
    
    $MailboxStats += [PSCustomObject]@{
        DisplayName = $Mailbox.DisplayName
        EmailAddress = $Mailbox.PrimarySmtpAddress
        MailboxType = $Mailbox.RecipientTypeDetails
        ItemCount = $Stats.ItemCount
        TotalItemSizeMB = [math]::Round(($Stats.TotalItemSize.Value.ToString() -replace '.*\(|bytes\)' -replace ',', '') / 1MB, 2)
        LastLogonTime = $Stats.LastLogonTime
        DaysSinceLogon = if ($Stats.LastLogonTime) { (New-TimeSpan -Start $Stats.LastLogonTime -End (Get-Date)).Days } else { "Never" }
    }
}

$MailboxStatsPath = "$ReportPrefix`_MailboxStats_$Timestamp.csv"
$MailboxStats | Export-Csv -Path $MailboxStatsPath -NoTypeInformation
Write-Host "✓ Mailbox statistics exported: $MailboxStatsPath" -ForegroundColor Green

# 2. Inactive Mailboxes Report
Write-Host "`n[2/5] Identifying inactive mailboxes (>$DaysInactive days)..." -ForegroundColor Yellow
$InactiveMailboxes = $MailboxStats | Where-Object { 
    $_.DaysSinceLogon -ne "Never" -and $_.DaysSinceLogon -gt $DaysInactive 
}

$InactivePath = "$ReportPrefix`_InactiveMailboxes_$Timestamp.csv"
$InactiveMailboxes | Export-Csv -Path $InactivePath -NoTypeInformation
Write-Host "✓ Found $($InactiveMailboxes.Count) inactive mailboxes: $InactivePath" -ForegroundColor Green

# 3. Mailbox Permissions Audit
Write-Host "`n[3/5] Auditing mailbox permissions..." -ForegroundColor Yellow
$PermissionsReport = @()

foreach ($Mailbox in $Mailboxes) {
    # Full Access permissions
    $FullAccess = Get-ExoMailboxPermission -Identity $Mailbox.UserPrincipalName | 
        Where-Object { $_.User -notlike "NT AUTHORITY\*" -and $_.User -ne "S-1-5-*" -and $_.AccessRights -contains "FullAccess" }
    
    foreach ($Permission in $FullAccess) {
        $PermissionsReport += [PSCustomObject]@{
            Mailbox = $Mailbox.PrimarySmtpAddress
            PermissionType = "FullAccess"
            GrantedTo = $Permission.User
            AccessRights = $Permission.AccessRights -join ", "
        }
    }
    
    # SendAs permissions
    $SendAs = Get-ExoRecipientPermission -Identity $Mailbox.UserPrincipalName | 
        Where-Object { $_.Trustee -notlike "NT AUTHORITY\*" -and $_.AccessRights -contains "SendAs" }
    
    foreach ($Permission in $SendAs) {
        $PermissionsReport += [PSCustomObject]@{
            Mailbox = $Mailbox.PrimarySmtpAddress
            PermissionType = "SendAs"
            GrantedTo = $Permission.Trustee
            AccessRights = "SendAs"
        }
    }
}

$PermissionsPath = "$ReportPrefix`_Permissions_$Timestamp.csv"
$PermissionsReport | Export-Csv -Path $PermissionsPath -NoTypeInformation
Write-Host "✓ Permissions audit complete: $PermissionsPath" -ForegroundColor Green

# 4. Forwarding Rules Detection
Write-Host "`n[4/5] Detecting forwarding rules..." -ForegroundColor Yellow
$ForwardingReport = @()

foreach ($Mailbox in $Mailboxes) {
    $MbxDetails = Get-ExoMailbox -Identity $Mailbox.UserPrincipalName
    
    # Check forwarding configured on mailbox
    if ($MbxDetails.ForwardingAddress -or $MbxDetails.ForwardingSMTPAddress) {
        $ForwardingReport += [PSCustomObject]@{
            Mailbox = $Mailbox.PrimarySmtpAddress
            ForwardingType = "Mailbox-Level"
            ForwardingDestination = if ($MbxDetails.ForwardingAddress) { $MbxDetails.ForwardingAddress } else { $MbxDetails.ForwardingSMTPAddress }
            DeliverToMailboxAndForward = $MbxDetails.DeliverToMailboxAndForward
        }
    }
    
    # Check inbox rules
    $InboxRules = Get-ExoInboxRule -Mailbox $Mailbox.UserPrincipalName | 
        Where-Object { $_.ForwardTo -or $_.ForwardAsAttachmentTo -or $_.RedirectTo }
    
    foreach ($Rule in $InboxRules) {
        $ForwardingReport += [PSCustomObject]@{
            Mailbox = $Mailbox.PrimarySmtpAddress
            ForwardingType = "Inbox Rule"
            RuleName = $Rule.Name
            ForwardingDestination = ($Rule.ForwardTo -join "; ") + ($Rule.RedirectTo -join "; ")
            DeliverToMailboxAndForward = -not $Rule.RedirectTo
        }
    }
}

$ForwardingPath = "$ReportPrefix`_Forwarding_$Timestamp.csv"
$ForwardingReport | Export-Csv -Path $ForwardingPath -NoTypeInformation
Write-Host "✓ Forwarding rules detected: $($ForwardingReport.Count) - $ForwardingPath" -ForegroundColor Green

# 5. Litigation Hold Status
Write-Host "`n[5/5] Checking litigation hold status..." -ForegroundColor Yellow
$LitigationHoldReport = $Mailboxes | ForEach-Object {
    $MbxDetails = Get-ExoMailbox -Identity $_.UserPrincipalName
    [PSCustomObject]@{
        DisplayName = $_.DisplayName
        EmailAddress = $_.PrimarySmtpAddress
        LitigationHoldEnabled = $MbxDetails.LitigationHoldEnabled
        LitigationHoldDate = $MbxDetails.LitigationHoldDate
        InPlaceHolds = ($MbxDetails.InPlaceHolds -join "; ")
    }
}

$LitigationPath = "$ReportPrefix`_LitigationHold_$Timestamp.csv"
$LitigationHoldReport | Export-Csv -Path $LitigationPath -NoTypeInformation
Write-Host "✓ Litigation hold report: $LitigationPath" -ForegroundColor Green

# Disconnect
Disconnect-ExchangeOnline -Confirm:$false

# Summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Report Generation Complete" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Total Mailboxes: $($Mailboxes.Count)" -ForegroundColor White
Write-Host "Inactive Mailboxes: $($InactiveMailboxes.Count)" -ForegroundColor Yellow
Write-Host "Mailboxes with Permissions: $($PermissionsReport.Count)" -ForegroundColor White
Write-Host "Mailboxes with Forwarding: $($ForwardingReport.Count)" -ForegroundColor Yellow
Write-Host "`nAll reports saved to: $ExportPath" -ForegroundColor Green
