Function Reset-MFA {
<#
.SYNOPSIS
    This will reset Azure MFA (stong authentication) for single or bulk users from txt file.
 
.NOTES
    Name: Get-PIMRoleAssignment
    Author: Lex Foronda
    Version: 1.0
    DateCreated: 2023.11.29
 
.EXAMPLE
    Reset-MFA -UserPrincipalName JuanDelaCruz@domain.com -Outputfile C:\temp\Reset_MFA_Log.txt
 
.EXAMPLE
    Reset-MFA -BulkWork -InputTextFile C:\temp\Users_UPN.txt -Outputfile C:\temp\Reset_MFA_Log.txt
    
#>
    [CmdletBinding()]
    Param
    (
        # UPN variable to reset azure mfa
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ParameterSetName='User'
            )]
        [string] $UserPrincipalName,

        # TXT file requirement
        [Parameter(
            Mandatory = $false,
            ParameterSetName='Bulk'
            )]
        [switch]
        $BulkWork,

        # Log file
        [Parameter(ParameterSetName='Bulk')]
        [Parameter(ParameterSetName='Input')]
        [Alias('Input')]
        [ValidateSet(
            'C:\temp\Users_UPN.txt'
        )]
        [string]
        $Inputfile,

        # Log file
        [Parameter(ParameterSetName='User')]
        [Parameter(ParameterSetName='Bulk')]
        [Parameter(ParameterSetName='Output')]
        [Alias('Output')]
        [ValidateSet(
            'C:\temp\Reset_MFA_Log.txt'
        )]
        [string]
        $Outputfile
    
    )
    
    BEGIN {     
        
        #Check msolservice connection
        if (-not (Get-MsolDomain -ErrorAction SilentlyContinue)) {

            Write-Host -ForegroundColor Yellow "You're not connected to MSolService. Please sing in to your T1 - privilege account."

            Connect-MsolService

        }

    }
    
    PROCESS {

        If ($UserPrincipalName) {

            Try {

                #Reset of MFA for a specific user
                #Set-MsolUser -UserPrincipalName $UserPrincipalName -StrongAuthenticationMethods @()
                Write-Host -ForegroundColor Green "Successully reset Azure MFA for $UserPrincipalName"

            } 
        
            Catch {
            
                Write-Error $_.Exception.Message

            }

        }

        If ($PSBoundParameters.ContainsKey('BulkWork')) {
            
            #Query contents of he input txt file
            $UPNS = Get-Content "C:\temp\Users_UPN.txt"
            Foreach ($UPN in $UPNS) {

                Try {

                    #Reset of MFA for a multiple user
                    $UPN = $UPN.trim()
                    #Set-MsolUser -UserPrincipalName $User -StrongAuthenticationMethods @()
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