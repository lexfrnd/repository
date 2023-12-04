<# 
.Synopsis 
    Checks the health of a specified domain controller.
.DESCRIPTION 
    This script will check the following:
    Installed Features
    NETLOGON and SYSVOL share
    C: drive free space
    Required services
    LDAP/s
    Replication
    
.PRE-REQUISITE
    Working over PSSession on a Domain Controller 
#>
Start-Transcript -path C:\temp\Scripts\Logs
$DC_FQDN = hostname

Write-Host " " 
Write-Host -ForegroundColor Yellow "=================================================================="
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
        Write-Host -ForegroundColor Red "Please check $DisplayName feature"
        $i++
    }
}
If ($i -eq "0")  
{ 
    Write-Host -ForegroundColor Green "All required features are installed."  
}
 
Write-Host " " 
Write-Host -ForegroundColor Yellow "=================================================================="
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
    } 
    
    catch {
        
        if ($_.Exception.ToString() -match "The server is not operational") {
            
            Write-Warning "Can't open $ServerName`:$Port."
        } 
        
        elseif ($_.Exception.ToString() -match "The user name or password is incorrect") {
            
            Write-Warning "Current user ($Env:USERNAME) doesn't seem to have access to to LDAP on port $Server`:$Port"
        } 
        
        else {
            
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
Write-Host -ForegroundColor Yellow "=================================================================="
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

[int]$i= "0"
$Services | foreach {
        
    $Service_Status = Get-Service -Name $_ | Select Status, Name, DisplayName
            
    If ($Service_Status.Status -ne "Running") {
            
        $Name = $Service_Status.Name
        $DisplayName = $Service_Status.DisplayName
        Write-Host -ForegroundColor Red "Please check $Name - $DisplayName."
        $i++

    }
}

If ($i -eq "0") { 

    Write-Host -ForegroundColor Green "All required services are running."  

}

Write-Host " " 
Write-Host -ForegroundColor Yellow "=================================================================="
Write-Host " " 
Write-Host -ForegroundColor Cyan "Checking for replication failures"

Repadmin /replsum

Stop-Transcript
