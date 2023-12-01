<# 
.Synopsis 
    Checks the health of a specified domain controller.
 
.DESCRIPTION 
    This script will check the following:
    Test TCP ports
    Installed Features
    Services
    NETLOGON and SYSVOL share
    NTDS Size
    C: drive free space
    Required running services
    DCDIAG
    Replication Error
    Time Error
    LDAP
 
.PRE-REQUISITE
    Working over PSSession on a Domain Controller
 
.CHANGELOG
    v1.0  
 
#>
 
Start-Transcript -path C:\temp\Scripts\Logs
$DC_FQDN = hostname
 
Write-Host " " 
Write-Host -ForegroundColor Yellow "===================================================================================================================" 
Write-Host " " 
Write-Host -ForegroundColor Cyan "Checking all required ports for $DC_FQDN"
 
$Ports = @( 
        '3389', 
        '445', 
        '88', 
        '135',    
        '464',  
        '389',  
        '3268', 
        '636', 
        '3269'
        )
 
$Ports | foreach {
 
    $Connection_Result = Test-NetConnection -ComputerName $DC_FQDN -InformationLevel "Detailed" -port $_ | Select ComputerName, RemoteAddress, RemotePort, NameResolutionResults, InterfaceAlias, SourceAddress, TcpTestSucceeded
 
    [int]$i= "0"
    If ($Connection_Result.TcpTestSucceeded -ne "True")
    {
        $RemotePort = $Connection_Result.RemotePort
        Write-Host -ForegroundColor Red "Please check $RemotePort"
        $i++
    }
 
}
 
If ($i -eq "0")  
{ 
    Write-Host -ForegroundColor Green "All required ports have successful connection."  
}
 
Write-Host " " 
Write-Host -ForegroundColor Yellow "===================================================================================================================" 
Write-Host " " 
Write-Host -ForegroundColor Cyan "Checking all required features for $DC_FQDN"
 
$Features = @( 
    'AD-Domain-Services',
    'FileAndStorage-Services',
    'File-Services',
    'FS-FileServer',
    'Storage-Services',
    'NET-Framework-45-Features',
    'NET-Framework-45-Core',
    'NET-WCF-Services45',
    'NET-WCF-TCP-PortSharing45',
    'BitLocker',
    'EnhancedStorage',
    'GPMC',
    'Windows-Defender',
    'RSAT',
    'RSAT-Feature-Tools',
    'RSAT-Feature-Tools-BitLocker',
    'RSAT-Feature-Tools-BitLocker-BdeAducExt',
    'RSAT-Role-Tools',
    'RSAT-AD-Tools',
    'RSAT-AD-PowerShell',
    'RSAT-ADDS',
    'RSAT-AD-AdminCenter',
    'RSAT-ADDS-Tools',
    'System-DataArchiver',
    'PowerShellRoot',
    'PowerShell',
    'WoW64-Support',
    'XPS-Viewer'
        )
 
$Features | foreach {
 
    $Query_Feature = Get-WindowsFeature -Name $_
 
    [int]$i= "0"
    If ($Query_Feature.Installed -ne "True")
    {
        $DisplayName = $Query_Feature.Name
        Write-Host -ForegroundColor Red "Please check $Name feature"
        $i++
    }
 
}
 
If ($i -eq "0")  
{ 
    Write-Host -ForegroundColor Green "All required features are installed."  
}
 
 
Write-Host " " 
Write-Host -ForegroundColor Yellow "===================================================================================================================" 
Write-Host " " 
Write-Host -ForegroundColor Cyan "Checking Sharing properties for SYSVOL and NETLOGON for $DC_FQDN"
 
$Check = Net Share
$CheckSysvol = $Check |Select-String "SYSVOL" 
$CheckNetlogon = $Check |Select-String "NETLOGON"
 
[int]$i= "0"
If ($CheckSysvol -eq $null -and $CheckNetlogon -ne $null) 
{ 
    Write-Host -ForegroundColor Yellow "SYSVOL is not shared on $Hostname, Please check." 
    $i++
}
 
elseif ($CheckSysvol -ne $null -and $CheckNetlogon -eq $null) 
{ 
    Write-Host -ForegroundColor Yellow "NETLOGON is not shared on $Hostname, Please check." 
    $i++ 
}
 
elseif ($CheckSysvol -eq $null -and $CheckNetlogon -eq $null) 
{ 
    Write-Host -ForegroundColor Yellow "SYSVOL and NETLOGON are not shared on $Hostname, Please check." 
    $i++ 
}
 
elseif ($i -eq "0")  
{ 
    Write-Host -ForegroundColor Green "SYSVOL and NETLOGON for all servers are shared."  
}
 
Write-Host " " 
Write-Host -ForegroundColor Yellow "===================================================================================================================" 
Write-Host " " 
Write-Host -ForegroundColor Cyan "Checking for NTDS Size for $DC_FQDN"
 
# Get Active Directory DB Size 
Function Get-ADDatabaseSize() { 
    try { 
        $DSADbFile = Get-ItemProperty -Path HKLM:\System\CurrentControlSet\Services\NTDS\Parameters | Select 'DSA Database File' 
        $DSADbFileSize = (Get-ItemProperty -Path $DSADbFile.'DSA Database File').Length /1MB 
    } 
    catch [exception] { 
        $DSADbFileSizeResult = "Failed" 
        $DSADbFileSizeReason = 'Unable to retrieve' 
    }
 
    $DSADbFileSizeResult = [Math]::Round($DSADbFileSize,2,[MidPointRounding]::AwayFromZero)   
 
    return $DSADbFileSizeResult, $DSADbFileSizeReason 
}
 
$DBSize_in_MB = Get-ADDatabaseSize
Write-Host -ForegroundColor Green "Current NTDS size is $DBSize_in_MB MB"
 
Write-Host " " 
Write-Host -ForegroundColor Yellow "===================================================================================================================" 
Write-Host " " 
Write-Host -ForegroundColor Cyan "Checking C Drive free space for $DC_FQDN"
 
#Query Disk and Free Space
$FreeSpace=@{Label='Free Space in GB'; expression={$_.freespace};formatstring='n0'} 
$DiskSize=@{Label='Size in GB'; expression={$_.Size};formatstring='n0'}
 
Get-WMIObject Win32_Logicaldisk -filter "deviceid='C:'" | FL $FreeSpace, $DiskSize
 
$c = Get-Culture
$c.NumberFormat.PercentDecimalDigits = 1
$Drive_Status = get-volume | select driveletter, FilesystemLabel, @{L='Free';E={($_.sizeremaining/$_.size).ToString("P")}}
$Drive_Status | foreach {
 
    If ($Drive_Status.Drive_Letter -eq "C" -and $Free -gt "20")
    {
 
        Write-Host -ForegroundColor Green "$Drive_Letter drive is Healthy"
 
    }
    ElseIf ($Drive_Status.Drive_Letter -eq "C" -and $Free -lt "20")
    {
 
        Write-Host -ForegroundColor Red "Please check $Drive_Letter Drive it is below 20% capacity"
 
    }
}
 
Write-Host " " 
Write-Host -ForegroundColor Yellow "===================================================================================================================" 
Write-Host " " 
Write-Host -ForegroundColor Cyan "Checking for required running services for $DC_FQDN"
 
# Check if the NTDS, ADWS, DNS, DNScache, KDC, Netlogon and W32Time services are running 
Function Get-DCServices($DC_FQDN) {
 
    $services = @( 
        'EventSystem', 
        'RpcSs', 
        'IsmServ', 
        'ntds',  
        'adws',  
        'dns',  
        'dnscache',  
        'kdc', 
        'LanmanServer', 
        'LanmanWorkstation' 
        'SamSs' 
        'w32time',  
        'netlogon'     
    )
 
    $stoppedServices = Get-Service -Name $services -ErrorAction Ignore | where {$_.Status -eq 'Stopped'}
 
    if ($stoppedServices.length -gt 0) { 
        $servicesResults = "Failed" 
        $stoppedServicesNames = $stoppedServices.Name -join ', ' 
        $servicesReason = "$stoppedServicesNames not running" 
    }
    #elseif (
    else{ 
        $servicesResults = "Success" 
    }
 
    return $servicesResults,$servicesReason 
}
 
Get-DCServices
 
Write-Host " " 
Write-Host -ForegroundColor Yellow "===================================================================================================================" 
Write-Host " " 
Write-Host -ForegroundColor Cyan "Running Diagnostics for $DC_FQDN"
 
function Get-DCDiagResults($DC_FQDN) { 
    # Skips services, we already checked them 
    $DcdiagOutput = Dcdiag.exe /skip:services
    if ($DcdiagOutput) { 
        $Results = New-Object PSCustomObject 
        $DcdiagOutput | ForEach-Object { 
            switch -Regex ($_) { 
                "Starting" { 
                    $TestName = ($_ -replace ".*Starting test: ").Trim() 
                } 
                "passed test|failed test" { 
                    $TestStatus = if ($_ -match "passed test") { "Passed" } else { "Failed" } 
                } 
            } 
            if ($null -ne $TestName -and $null -ne $TestStatus) { 
                $Results | Add-Member -Name $TestName.Trim() -Value $TestStatus -Type NoteProperty -Force 
                $TestName = $null 
                $TestStatus = $null 
            } 
        } 
    } 
    return $Results 
}
 
 
Get-DCDiagResults
 
Write-Host " " 
Write-Host -ForegroundColor Yellow "===================================================================================================================" 
Write-Host " " 
Write-Host -ForegroundColor Cyan "Checking Replication errors for $DC_FQDN"
 
function Get-ReplicationData { 
    $repPartnerData = Get-ADReplicationPartnerMetadata -Target $DC_FQDN
 
    $replResult = @{}
 
    # Get the replication partner 
    $replResult.repPartner = ($RepPartnerData.Partner -split ',')[1] -replace 'CN=', '';
 
    # Last attempt 
    try { 
        $replResult.lastRepAttempt = @() 
        $replLastRepAttempt = $repPartnerData.LastReplicationAttempt 
        $replFrequency = (Get-ADReplicationSiteLink -Filter *).ReplicationFrequencyInMinutes 
        if (((Get-Date) - $replLastRepAttempt).Minutes -gt $replFrequency) { 
            $replResult.lastRepAttempt += "Warning" 
            $replResult.lastRepAttempt += "More then $replFrequency minutes ago - $($replLastRepAttempt.ToString('yyyy-MM-dd HH:mm'))" 
        }else{ 
            $replResult.lastRepAttempt += "Success - $($replLastRepAttempt.ToString('yyyy-MM-dd HH:mm'))" 
        }
 
        # Last successfull replication 
        $replResult.lastRepSuccess = @() 
        $replLastRepSuccess = $repPartnerData.LastReplicationSuccess 
        if (((Get-Date) - $replLastRepSuccess).Minutes -gt $replFrequency) { 
            $replResult.lastRepSuccess += "Warning" 
            $replResult.lastRepSuccess += "More then $replFrequency minutes ago - $($replLastRepSuccess.ToString('yyyy-MM-dd HH:mm'))" 
        }else{ 
            $replResult.lastRepSuccess += "Success - $($replLastRepSuccess.ToString('yyyy-MM-dd HH:mm'))" 
        }
 
        # Get failure count 
        $replResult.failureCount = @() 
        $replFailureCount = (Get-ADReplicationFailure -Target $computername).FailureCount 
        if ($null -eq $replFailureCount) {  
            $replResult.failureCount += "Success" 
        }else{ 
            $replResult.failureCount += "Failed" 
            $replResult.failureCount += "$replFailureCount failed attempts" 
        }  
 
        # Get replication results 
        $replDelta = (Get-Date) - $replLastRepAttempt
 
        # Check if the delta is greater than 180 minutes (3 hours) 
        if ($replDelta.TotalMinutes -gt $replFrequency) { 
            $replResult.delta += "Failed" 
            $replResult.delta += "Delta is more then 180 minutes - $($replDelta.Minutes)" 
        }else{ 
            $replResult.delta += "Success - $($replDelta.Minutes) minutes" 
        } 
    } 
    catch [exception]{ 
        $replResult.lastRepAttempt += "Failed" 
        $replResult.lastRepAttempt += "Unable to retrieve replication data" 
        $replResult.lastRepSuccess += "Failed" 
        $replResult.lastRepSuccess += "Unable to retrieve replication data" 
        $replResult.failureCount += "Failed" 
        $replResult.failureCount += "Unable to retrieve replication data" 
        $replResult.delta += "Failed" 
        $replResult.delta += "Unable to retrieve replication data" 
    }
 
    return $replResult 
}
 
Get-ReplicationData
 
repadmin /replsum
 
Write-Host " " 
Write-Host -ForegroundColor Yellow "===================================================================================================================" 
Write-Host " " 
Write-Host -ForegroundColor Cyan "Checking time error for $DC_FQDN"
 
function Get-TimeDifference { 
    # credits: https://stackoverflow.com/a/63050189 
    $currentTime, $timeDifference = (& w32tm /stripchart /computer:$DC_FQDN /samples:1 /dataonly)[-1].Trim("s") -split ',\s*' 
    $diff = [double]$timeDifference
 
    if ($diff -ge 1) { 
        $timeResult = "Failed" 
        $timeReason = "Offset greater then 1" 
    }else{ 
        $diffRounded = [Math]::Round($diff,4,[MidPointRounding]::AwayFromZero) 
        $timeResult = "Success - $diffRounded" 
    } 
    return $timeResult, $timeReason 
}
 
Get-TimeDifference
 
Write-Host " " 
Write-Host -ForegroundColor Yellow "===================================================================================================================" 
Write-Host " " 
Write-Host -ForegroundColor Cyan "Performing LDAP and LDAPs checking for $DC_FQDN"
 
function Test-LDAPPorts {
[CmdletBinding()]
param(
    [string] $ServerName,
    [int] $Port
)
if ($ServerName -and $Port -ne 0) {
    try {
        $LDAP = "LDAP://" + $ServerName + ':' + $Port
        $Connection = [ADSI]($LDAP)
        $Connection.Close()
        return $true
    } catch {
        if ($_.Exception.ToString() -match "The server is not operational") {
            Write-Warning "Can't open $ServerName`:$Port."
        } elseif ($_.Exception.ToString() -match "The user name or password is incorrect") {
            Write-Warning "Current user ($Env:USERNAME) doesn't seem to have access to to LDAP on port $Server`:$Port"
        } else {
            Write-Warning -Message $_
        }
    }
    return $False
    }
}
Function Test-LDAP {
    [CmdletBinding()]
    param (
        [alias('Server', 'IpAddress')][Parameter(Mandatory = $True)][string[]]$ComputerName,
        [int] $GCPortLDAP = 3268,
        [int] $GCPortLDAPSSL = 3269,
        [int] $PortLDAP = 389,
        [int] $PortLDAPS = 636
    )
    # Checks for ServerName - Makes sure to convert IPAddress to DNS
    foreach ($Computer in $ComputerName) {
        [Array] $ADServerFQDN = (Resolve-DnsName -Name $Computer -ErrorAction SilentlyContinue)
        if ($ADServerFQDN) {
            if ($ADServerFQDN.NameHost) {
                $ServerName = $ADServerFQDN[0].NameHost
            } 
            else {
                [Array] $ADServerFQDN = (Resolve-DnsName -Name $Computer -ErrorAction SilentlyContinue)
                $FilterName = $ADServerFQDN | Where-Object { $_.QueryType -eq 'A' }
                $ServerName = $FilterName[0].Name
            }
        } 
        else {
            $ServerName = ''
        }
        $GlobalCatalogSSL = Test-LDAPPorts -ServerName $ServerName -Port $GCPortLDAPSSL
        $GlobalCatalogNonSSL = Test-LDAPPorts -ServerName $ServerName -Port $GCPortLDAP
        $ConnectionLDAPS = Test-LDAPPorts -ServerName $ServerName -Port $PortLDAPS
        $ConnectionLDAP = Test-LDAPPorts -ServerName $ServerName -Port $PortLDAP
        $PortsThatWork = @(
            if ($GlobalCatalogNonSSL) { $GCPortLDAP }
            if ($GlobalCatalogSSL) { $GCPortLDAPSSL }
            if ($ConnectionLDAP) { $PortLDAP }
            if ($ConnectionLDAPS) { $PortLDAPS }
        ) | Sort-Object
        [pscustomobject]@{
            Computer           = $Computer
            ComputerFQDN       = $ServerName
            GlobalCatalogLDAP  = $GlobalCatalogNonSSL
            GlobalCatalogLDAPS = $GlobalCatalogSSL
            LDAP               = $ConnectionLDAP
            LDAPS              = $ConnectionLDAPS
            AvailablePorts     = $PortsThatWork -join ','
        }
    }
}
 
Test-LDAP -Computername $DC_FQDN
 
Write-Host " " 
Write-Host -ForegroundColor Yellow "===================================================================================================================" 
Write-Host " " 
Write-Host -ForegroundColor Cyan "Checking all required services for $DC_FQDN"
 
$Services = @( 
    'ADWS',
    'AmazonCloudWatchAgent',
    'AppIDSvc',
    'Appinfo',
    'AppXSvc',
    'AzureNetworkWatcherAgent',
    'BDESVC',
    'BFE',
    'BrokerInfrastructure',
    'camsvc',
    'cbdhsvc_30865038',
    'cbdhsvc_57ec883c',
    'cbdhsvc_b9076e3',
    'CDPUserSvc_30865038',
    'CDPUserSvc_57ec883c',
    'CDPUserSvc_b9076e3',
    'CertPropSvc',
    'CoreMessagingRegistrar',
    'CryptSvc',
    'CSFalconService',
    'DcomLaunch',
    'Dfs',
    'DFSR',
    'Dhcp',
    'DiagTrack',
    'DispBrokerDesktopSvc',
    'dmwappushservice',
    'Dnscache',
    'DPS',
    'DsSvc',
    'EFS',
    'ErdAgent',
    'EventLog',
    'EventSystem',
    'FontCache',
    'gpsvc',
    'HealthService',
    'iphlpsvc',
    'IsmServ',
    'Kdc',
    'KeyIso',
    'LanmanServer',
    'LanmanWorkstation',
    'LicenseManager',
    'lmhosts',
    'LSM',
    'MMAExtensionHeartbeatService',
    'mpssvc',
    'MSDTC',
    'Netlogon',
    'netprofm',
    'NetSetupSvc',
    'NlaSvc',
    'NPSrvHost',
    'nsi',
    'NTDS',
    'pla',
    'PlugPlay',
    'PolicyAgent',
    'Power',
    'ProfSvc',
    'RasMan',
    'RdAgent',
    'RpcEptMapper',
    'RpcSs',
    'sacsvr',
    'SamSs',
    'Schedule',
    'SecurityHealthService',
    'SENS',
    'Sense',
    'SessionEnv',
    'SgrmBroker',
    'smphost',
    'SstpSvc',
    'StateRepository',
    'StorSvc',
    'SysMain',
    'SystemEventsBroker',
    'TermService',
    'Themes',
    'TimeBrokerSvc',
    'TokenBroker',
    'UALSVC',
    'UmRdpService',
    'UserManager',
    'UsoSvc',
    'vds',
    'vmicheartbeat',
    'vmickvpexchange',
    'vmicshutdown',
    'vmictimesync',
    'W32Time',
    'Wcmsvc',
    'WdiSystemHost',
    'WdNisSvc',
    'WinDefend',
    'WindowsAzureGuestAgent',
    'WinHttpAutoProxySvc',
    'Winmgmt',
    'WinRM',
    'WpnUserService_30865038',
    'WpnUserService_57ec883c',
    'WpnUserService_b9076e3',
    'wuauserv'       
    )
 
$Services | foreach {
 
    $Service_Status = Get-Service -Name $_ | Select Status, Name, DisplayName
 
    [int]$i= "0"
    If ($Service_Status.Status -ne "Running")
    {
        $DisplayName = $Service_Status.DisplayName
        Write-Host -f Red "Please check $DisplayName."
        $i++
    }
 
}
 
If ($i -eq "0")  
{ 
    Write-Host -f Green "All required services are running."  
}
 
Stop-Transcript
