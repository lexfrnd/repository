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
    Reset-MFA -UserPrincipalName JuanDelaCruz@domain.com -Outputfile C:\temp\Reset_MFA_Log.txt
 
.EXAMPLE
    Reset-MFA -BulkWork -Inputfile C:\temp\Users_UPN.txt -Outputfile C:\temp\Reset_MFA_Log.txt
    
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
            If (Test-Path C:\temp\Users_UPN.txt -PathType Leaf){
                $true
            } Else {
                throw "Users_UPN.txt is not existing in C:\temp."
            }    
        }
        )]
        <#// ValidationScript for PS version 6 
        [ValidateScript({
            Test-Path C:\temp\Users_UPN.txt -PathType Leaf            
        },
        ErrorMessage = "Users_UPN.txt is not existing in C:\temp."
        )]#> 
        [string] $Inputfile = 'C:\temp\Users_UPN.txt',

        # Log file
        [string] $Outputfile = 'C:\temp\Reset_MFA_Log.txt'
    )
    
    BEGIN {     
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
                Set-MsolUser -UserPrincipalName $UserPrincipalName -StrongAuthenticationMethods @() -ErrorAction Stop
                Write-Host -ForegroundColor Green "Successully reset Azure MFA for $UserPrincipalName"
            }
            Catch {
                Write-Error $_.Exception.Message
            }
        }
        
        If ($PSBoundParameters.ContainsKey("BulkWork") -and ($PSCmdlet.ShouldProcess($BulkWork))) {
            #Query contents of he input txt file
            $UPNS = Get-Content "C:\temp\Users_UPN.txt"
            Foreach ($UPN in $UPNS) {
                Try {
                    #Reset of MFA for a multiple user
                    $UPN = $UPN.trim()
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
