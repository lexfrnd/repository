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
    Reset-MFA -BulkWork -Inputfile
    
#>
    [CmdletBinding(SupportsShouldProcess)]
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
        #// ValidationScript for PS version 5.1
        [ValidateScript({
            If (Test-Path C:\temp\Users_UPN.txt -PathType Leaf) {
                $true
            } Else {
                throw "Users_UPN.txt is not existing in C:\temp."
            }
            
            If (Get-Content "C:\temp\Users_UPN.txt" -ReadCount 1) {
                $true
            } Else {
                throw "Users_UPN.txt is empty."
            }

        }
        )]
        <#// ValidationScript for PS version 6 
        [ValidateScript({
            Test-Path C:\temp\Users_UPN.txt -PathType Leaf            
        },
        ErrorMessage = "Users_UPN.txt is not existing in C:\temp."
        )]#> 
        [string] $Inputfile = 'C:\temp\Users_UPN.txt'
    )
    
    BEGIN { 
        #Check msolservice module
        if (-not (Get-Module -Name MSOnline -ErrorAction Stop)) {
            Write-Host -ForegroundColor Red "Please install MSOnline module."
        }

        #Check msolservice connection
        if (-not (Get-MsolDomain -ErrorAction SilentlyContinue)) {
            Write-Host -ForegroundColor Yellow "You're not connected to MSolService. Please sing in to your T1 - privilege account."
            Connect-MsolService
        }
    }
    
    PROCESS {
        If ($PSCmdlet.ShouldProcess($UserPrincipalName)) {
            Try {
                #Reset of MFA for a specific user
                $UPN = $UPN.trim()
                If ($UPN.Split("@")[1] -notcontains "pg.com") {
                    $UPN_Short = $UPN.Split("@")[0]
                    $UPN = $UPN_Short + "_" + $UPN.Split("@")[1] + "#EXT#@pgone.onmicrosoft.com"
                }
                Set-MsolUser -UserPrincipalName $UserPrincipalName -StrongAuthenticationMethods @() -ErrorAction Stop
                Write-Host -ForegroundColor Green "Successully reset Azure MFA for $UserPrincipalName"
            }
            Catch {
                Write-Error $_.Exception.Message
            }
        }
        
        If ($PSBoundParameters.ContainsKey("Bulk") -and ($PSCmdlet.ShouldProcess($BulkWork))) {
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
                    Set-MsolUser -UserPrincipalName $UPN -StrongAuthenticationMethods @() -ErrorAction Stop
                    Write-Host -ForegroundColor Green "Successully reset Azure MFA for $UPN"
                }
                Catch {
                    Write-Error $_.Exception.Message
                }
            }
        }
    }
    END {}
}
