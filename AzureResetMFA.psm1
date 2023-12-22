Function Reset-MFA {
<#
.SYNOPSIS
    This will reset Azure MFA (stong authentication) for single or bulk users from txt file.
 
.NOTES
    Name: Reset-MFA
    Author: Lex Foronda
    Version: 1.0
    DateCreated: 2023.11.29
 
.EXAMPLE
    Reset-MFA -UserPrincipalName JuanDelaCruz@domain.com
 
.EXAMPLE
    Reset-MFA -BulkWork -Inputfile <insert file path>
    
#>
    [CmdletBinding()]
    Param
    (
        # UPN variable to reset azure mfa
        [Parameter(ParameterSetName='User')]
        [string] $UserPrincipalName,

        # TXT file requirement
        [Parameter(ParameterSetName='Bulk')]
        [switch] $BulkWork,

        # Input file
        [Parameter(ParameterSetName='Input')]
        [Parameter(ParameterSetName='Bulk')]
        [ValidateSet(
            'C:\temp\Users_UPN.txt'
        )]
        [string] $Inputfile
    )
    
    BEGIN { 
        #Check Execution policy
        $ExecutionPolicy = Get-ExecutionPolicy -ErrorAction SilentlyContinue
        if ($ExecutionPolicy -ne "RemoteSigned") {
            Write-Host -ForegroundColor Yellow "Setting execution policy from restricted to process"
            Set-ExecutionPolicy RemoteSigned -Scope Process
        }
        
        #Check msolservice module
        if (-not (Get-Module -Name MSOnline -ErrorAction SilentlyContinue)) {
            Write-Host -ForegroundColor Yellow "Importing MSOnline module."
            Import-Module -name MSOnline
        }

        #Check AzureResetMFA module
        if (-not (Get-Module -Name AzureResetMFA -ErrorAction SilentlyContinue)) {
            Write-Host -ForegroundColor Yellow "Importing AzureResetMFA module."
            Import-Module -name AzureResetMFA
        }

        #Check msolservice connection
        if (-not (Get-MsolDomain -ErrorAction SilentlyContinue)) {
            Write-Host -ForegroundColor Yellow "You're not connected to MSolService. Please sing in to your T1 - privilege account."
            Connect-MsolService
        }
    }
    
    PROCESS {
        If ($PSBoundParameters.ContainsKey("UserPrincipalName")) {
            Try {
                #Reset of MFA for a specific user
                $UPN = $UPN.trim()
                If ($UPN.Split("@")[1] -notcontains "pg.com") {
                    $UPN_Short = $UPN.Split("@")[0]
                    $UPN = $UPN_Short + "_" + $UPN.Split("@")[1] + "#EXT#@pgone.onmicrosoft.com"
                }
                Set-MsolUser -UserPrincipalName $UserPrincipalName -StrongAuthenticationMethods @() -ErrorAction Stop
                Write-Host -ForegroundColor Green "Successully reset Azure MFA for $UserPrincipalName."
            }
            Catch {
                Write-Error $_.Exception.Message
            }
        }
        
        If ($PSBoundParameters.ContainsKey("BulkWork")) {
            #Query contents of he input txt file
            $UPNS = Get-Content "C:\temp\Users_UPN.txt"
            Foreach ($UPN in $UPNS) {
                Try {
                    #Reset of MFA for a multiple user
                    $UPN = $UPN.trim()
                    If ($UPN.Split("@")[1] -notcontains "pg.com") {
                        $UPN_Short = $UPN.Split("@")[0]
                        $UPN = $UPN_Short + "_" + $UPN.Split("@")[1] + "#EXT#@pgone.onmicrosoft.com"
                    }
                    
                    If (-not(Get-MsolUser -UserPrincipalName $UPN -ErrorAction Continue)) {
                        Write-Host -ForegroundColor Red "Please verify $UPN in Entra ID."
                    } 
                    Else {
                        Set-MsolUser -UserPrincipalName $UPN -StrongAuthenticationMethods @() -ErrorAction Continue
                        Write-Host -ForegroundColor Green "Successully reset Azure MFA for $UPN."
                    }
                    
                    

                }
                Catch {
                    Write-Error $_.Exception.Message
                }
            }
        }
    }
    END {}
}
