<#
.SYNOPSIS
    This will reset the Azure MFA for a specific user
 
.NOTES
    Name: Azure MFA Reset
    Author: Krisarlex Foronda
    Version: 1.0
    Date Created: 11/20/2023
 
.PRE-REQUISITE
    Uninstall-Module-Name AzureAD
    Install-Module-Name AzureADPreview
    Import-ModuleAzureAD
    Connect-AzureAD -TenantId <your_tenantID> Get-Module *AzureAD*
    MSOnline Module - Install-Module MSOnline

#>

#Uninstall AzureAD Module. This will conflict with AzureADPreview
$AzureAD_Status = Get-Module -Name AzureAD
If($AzureAD_Status.Name -eq $null) { Write-Host -f Green "AzureAD module is not installed" }
Else { Uninstall-Module -Name AzureAD -Whatif }

#Query and install AzureADPreview module
$AzureADPreview_Status = Get-Module -Name AzureADPreview
If($AzureADPreview_Status.Name -eq $null) { Install-Module -Name AzureADPreview -WhatIf }
Else { Write-Host -f Green "AzureADPreview module is already installed" }

#Query and install MSOnline module
$MSOnline_Status = Get-Module -Name MSOnline
If($MSOnline_Status.Name -eq $null) { Install-Module -Name MSOnline -WhatIf }
Else { Write-Host -f Green "MSOnline module is already installed" }

Function Get-PIMRoleAssignment {
<#
.SYNOPSIS
    This will check if a user is added to PIM or standing access.
    For updated help and examples refer to -Online version.
 
.NOTES
    Name: Get-PIMRoleAssignment
    Author: theSysadminChannel
    Version: 1.0
    DateCreated: 2021-May-15
 
.EXAMPLE
    Get-PIMRoleAssignment -UserPrincipalName blightyear@thesysadminchannel.com
 
.EXAMPLE
    Get-PIMRoleAssignment -RoleName 'Global Administrator'
 
.LINK
    https://thesysadminchannel.com/get-pim-role-assignment-status-for-azure-ad-using-powershell -

.PRE-REQUISITE
    
#>
 
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ParameterSetName = 'User',
            Position  = 0
        )]
        [string[]]  $UserPrincipalName,
 
 
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ParameterSetName = 'Role',
            Position  = 1
        )]
        [Alias('DisplayName')]
        [ValidateSet(
            'Application Administrator',
            'Application Developer',
            'Attack Simulation Administrator',
            'Authentication Administrator',
            'Azure Information Protection Administrator',
            'Billing Administrator',
            'Cloud Device Administrator',
            'Compliance Administrator',
            'Conditional Access Administrator',
            'Device Managers',
            'Directory Readers',
            'Directory Writers',
            'Exchange Administrator',
            'Exchange Recipient Administrator',
            'Global Administrator',
            'Global Reader',
            'Helpdesk Administrator',
            'Intune Administrator',
            'License Administrator',
            'Message Center Privacy Reader',
            'Message Center Reader',
            'Power BI Administrator',
            'Power Platform Administrator',
            'Privileged Authentication Administrator',
            'Privileged Role Administrator',
            'Reports Reader',
            'Search Administrator',
            'Security Administrator',
            'Security Reader',
            'Service Support Administrator',
            'SharePoint Administrator',
            'Skype for Business Administrator',
            'Teams Administrator',
            'Teams Communications Administrator',
            'Teams Communications Support Engineer',
            'Teams Communications Support Specialist',
            'User Administrator'
        )]
        [string]    $RoleName,
 
 
        [string]    $TenantId
    )
 
    BEGIN {
        $SessionInfo = Get-AzureADCurrentSessionInfo -ErrorAction Stop
        if (-not ($PSBoundParameters.ContainsKey('TenantId'))) {
            $TenantId = $SessionInfo.TenantId
        }
 
        $AdminRoles = Get-AzureADMSPrivilegedRoleDefinition -ProviderId aadRoles -ResourceId $TenantId -ErrorAction Stop | select Id, DisplayName
        $RoleId = @{}
        $AdminRoles | ForEach-Object {$RoleId.Add($_.DisplayName, $_.Id)}
    }
 
    PROCESS {
        if ($PSBoundParameters.ContainsKey('UserPrincipalName')) {
            foreach ($User in $UserPrincipalName) {
                try {
                    $AzureUser = Get-AzureADUser -ObjectId $User -ErrorAction Stop | select DisplayName, UserPrincipalName, ObjectId
                    $UserRoles = Get-AzureADMSPrivilegedRoleAssignment -ProviderId aadRoles -ResourceId $TenantId -Filter "subjectId eq '$($AzureUser.ObjectId)'"
 
                    if ($UserRoles) {
                        foreach ($Role in $UserRoles) {
                            $RoleObject = $AdminRoles | Where-Object {$Role.RoleDefinitionId -eq $_.id}
 
                            [PSCustomObject]@{
								UserDisplayName   = $AzureUser.DisplayName #Added by Lex
                                UserPrincipalName = $AzureUser.UserPrincipalName
                                AzureADRole       = $RoleObject.DisplayName
                                PIMAssignment     = $Role.AssignmentState
                                MemberType        = $Role.MemberType
                            }
                        }
                    }
                } catch {
                    Write-Error $_.Exception.Message
                }
            }
        }
 
        if ($PSBoundParameters.ContainsKey('RoleName')) {
            try {
                $RoleMembers = @()
                $RoleMembers += Get-AzureADMSPrivilegedRoleAssignment -ProviderId aadRoles -ResourceId $TenantId -Filter "RoleDefinitionId eq '$($RoleId[$RoleName])'" -ErrorAction Stop | select RoleDefinitionId, SubjectId, StartDateTime, EndDateTime, AssignmentState, MemberType
 
                if ($RoleMembers) {
                    $RoleMemberList = $RoleMembers.SubjectId | select -Unique
                    $AzureUserList = foreach ($Member in $RoleMemberList) {
                        try {
                            Get-AzureADUser -ObjectId $Member | select ObjectId, UserPrincipalName, Displayname
                        } catch {
                            Get-AzureADGroup -ObjectId $Member | select ObjectId, @{Name = 'UserPrincipalName'; Expression = { "$($_.DisplayName) (Group)" }}
                            $GroupMemberList = Get-AzureADGroupMember -ObjectId $Member | select ObjectId, UserPrincipalName, Displayname
                            foreach ($GroupMember in $GroupMemberList) {
                                $RoleMembers += Get-AzureADMSPrivilegedRoleAssignment -ProviderId aadRoles -ResourceId $TenantId -Filter "RoleDefinitionId eq '$($RoleId[$RoleName])' and SubjectId eq '$($GroupMember.objectId)'" -ErrorAction Stop | select RoleDefinitionId, SubjectId, StartDateTime, EndDateTime, AssignmentState, MemberType
                            }
                            Write-Output $GroupMemberList
                        }
                    }
 
                    $AzureUserList = $AzureUserList | select ObjectId, UserPrincipalName, Displayname -Unique
                    $AzureUserHash = @{}
                    $AzureUserList | ForEach-Object {$AzureUserHash.Add($_.ObjectId, $_.UserPrincipalName)}
 
                    foreach ($Role in $RoleMembers) {
                        [PSCustomObject]@{
                            #UserDisplayname   = $AzureUserHash[$Role.SubjectId]
                            UserPrincipalName = $AzureUserHash[$Role.SubjectId]
                            AzureADRole       = $RoleName
                            PIMAssignment     = $Role.AssignmentState
                            MemberType        = $Role.MemberType
                        }
                    }
                }
            } catch {
                Write-Error $_.Exception.Message
            }
        }
    }
 
    END {}
 
}

Function Add-PIMRoleAssignment {
<#
.Synopsis
    This add a user to a PIM Role in Azure AD.
    For updated help and examples refer to -Online version.
 
.NOTES
    Name: Add-PIMRoleAssignment
    Author: theSysadminChannel
    Version: 1.0
    DateCreated: 2021-Sep-13
#>
 
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position  = 0
        )]
        [string[]]  $UserPrincipalName,
 
 
        [Parameter(
            Mandatory = $true,
            Position  = 1
        )]
        [ValidateSet(
            'Application Administrator',
            'Application Developer',
            'Attack Simulation Administrator',
            'Authentication Administrator',
            'Azure Information Protection Administrator',
            'Billing Administrator',
            'Cloud Device Administrator',
            'Compliance Administrator',
            'Conditional Access Administrator',
            'Device Managers',
            'Directory Readers',
            'Directory Writers',
            'Exchange Administrator',
            'Exchange Recipient Administrator',
            'Global Administrator',
            'Global Reader',
            'Helpdesk Administrator',
            'Intune Administrator',
            'License Administrator',
            'Message Center Privacy Reader',
            'Message Center Reader',
            'Power BI Administrator',
            'Power Platform Administrator',
            'Privileged Authentication Administrator',
            'Privileged Role Administrator',
            'Reports Reader',
            'Search Administrator',
            'Security Administrator',
            'Security Reader',
            'Service Support Administrator',
            'SharePoint Administrator',
            'Skype for Business Administrator',
            'Teams Administrator',
            'Teams Communications Administrator',
            'Teams Communications Support Engineer',
            'Teams Communications Support Specialist',
            'User Administrator'
        )]
        [string]    $RoleName,
 
 
        [Parameter(
            Mandatory = $false,
            Position  = 2
        )]
        [string]    $TenantId,
 
 
        [Parameter(
            Mandatory = $false,
            Position  = 3
        )]
        [int]   #$DurationInMonths = 48,
				$DurationInHours = 4,
 
        [Parameter(
            Mandatory = $false,
            Position  = 4
        )]
        [Alias('Justification')]
        [string]   $TicketNumber
 
    )
 
    BEGIN {
        $SessionInfo = Get-AzureADCurrentSessionInfo -ErrorAction Stop
        if (-not ($PSBoundParameters.ContainsKey('TenantId'))) {
            $TenantId = $SessionInfo.TenantId
        }
 
        $AdminRoles = Get-AzureADMSPrivilegedRoleDefinition -ProviderId aadRoles -ResourceId $TenantId -ErrorAction Stop | select Id, DisplayName
        $RoleId = @{}
        $AdminRoles | ForEach-Object {$RoleId.Add($_.DisplayName, $_.Id)}
    }
 
    PROCESS {
        $Schedule = New-Object Microsoft.Open.MSGraph.Model.AzureADMSPrivilegedSchedule
        $Schedule.Type = "Once"
        $Schedule.StartDateTime = (Get-Date)
        #$Schedule.EndDateTime = (Get-Date).AddMonths($DurationInMonths)
		$Schedule.EndDateTime = (Get-Date).AddHours($DurationInHours)
 
        foreach ($User in $UserPrincipalName) {
            try {
                $AzureADUser = Get-AzureADUser -ObjectId $User -ErrorAction Stop | select-object UserPrincipalName, ObjectId, DisplayName
                Open-AzureADMSPrivilegedRoleAssignmentRequest -ProviderId Aadroles -Schedule $Schedule -ResourceId $TenantId -RoleDefinitionId $RoleId[$RoleName] `
                    -SubjectId $AzureADUser.ObjectId -AssignmentState Active <#Eligible#> -Type AdminAdd -Reason $TicketNumber -ErrorAction Stop | Out-Null
 
                [PSCustomObject]@{
					UserDisplayName   = $AzureUser.DisplayName #Added by Lex
                    UserPrincipalName = $AzureADUser.UserPrincipalName
                    RoleName          = $RoleName
                    #DurationInMonths = $DurationInMonths
					DurationInHours   = $DurationInHours
                    Justification     = $TicketNumber
                }
 
            } catch {
                Write-Error $_.Exception.Message
            }
        }
    }
 
    END {}
 
}

#AzureAD connection verification
If($AzureConnection.Account -eq $null)
{
    
    $AzureConnection = Connect-AzureAD #-TenantId $TenantId 
    $AzureConnection_UPN = ($AzureConnection.Account).Id
    Write-Host -f Green "You're logged in using $AzureConnection_UPN"

}

Else { Write-Host -f Green "You're logged in using $AzureConnection_UPN" }

#Query current Azure AD role assignment
$PIMRoleAssignment = Get-PIMRoleAssignment -UserPrincipalName $AzureConnection_UPN
If ($PIMRoleAssignment -ne $null)
{
    $PIMRoleAssignment | % {
	    $UserDisplayName = $_ |% {$_.UserDisplayName}
        $Admin_UPN = $_ |% {$_.UserPrincipalName}
        $AzureADRole = $_ |% {$_.AzureADRole}
        $PIMAssignment = $_ |% {$_.PIMAssignment}
        $MemberType = $_ |% {$_.MemberType}
        
        #Condition if Auth Admin is assigned as eligible (L2 Access)
        If ($AzureADRole -eq 'Authentication Administrator' -and $PIMAssignment -eq 'Eligible')
        {

            Write-Host ""
            Write-Host -f Cyan "Input SNOW INC Ticket number: " -NoNewline
            $SNOW_Ticket = Read-Host
            Write-Host -f Cyan "Input Reason (max 500 caharacters): " -NoNewline
            $Reason = Read-Host

            #Activate Auth Admin role
            Add-PIMRoleAssignment -UserPrincipalName $Admin_UPN -RoleName $AzureADRole -DurationInHours 4 -Justification $SNOW_Ticket -Reason $Reason 
            Write-Host -f Green "Successully assigned $AzureADRole to $Admin_UPN active for 4 hours only. Reference ticket $SNOW_Ticket" -NoNewline

            Write-Host ""
            Write-Host -f Cyan " Input UPN of the user: " -NoNewline
            $User_UPN = Read-Host

            #Get-MGUserAuthenticationMethod -UserID $User_UPN
            #(Get-MgUserAuthenticationMethod -UserId %upn%).AdditionalProperties.values

            #Query current MFA state of a user
            Connect-MsolService 
            $ThisUser = Get-msoluser -UserPrincipalName $User_UPN | Select-Object -ExpandProperty StrongAuthenticationRequirement
            $MFA_State = $ThisUser.State

            #Condition for enabled MFA
            If ($MFA_State -eq 'Enabled')
            {
                
                #Reset of MFA for a specific user
                #Set-MsolUser -UserPrincipalName $User_UPN -StrongAuthenticationMethods @() -whatif
                #Reset-MsolStrongAuthenticationMethodByUpn -UserPrincipalName $User_UPN -Whatif
                Write-Host -f Green "Successully reset Azure MFA for $User_UPN" -NoNewline

            }

        }

        #Condition if Auth Admin or Global Admin role is assigned as active (L3 Access)
        Elseif ((($AzureADRole -eq 'Authentication Administrator') -or ($AzureADRole -eq 'Global Administrator')) -and $PIMAssignment -eq 'Active')
        {


            Write-Host ""
            Write-Host -f Cyan " Input UPN of the user: " -NoNewline
            $User_UPN = Read-Host

            #Get-MGUserAuthenticationMethod -UserID $User_UPN
            #(Get-MgUserAuthenticationMethod -UserId %upn%).AdditionalProperties.values

            #Query current MFA state of a user
            Connect-MsolService 
            $ThisUser = Get-msoluser -UserPrincipalName $User_UPN | Select-Object -ExpandProperty StrongAuthenticationRequirement
            $MFA_State = $ThisUser.State

            #Condition for enabled MFA
            If ($MFA_State -eq 'Enabled')
            {
                
                #Reset of MFA for a specific user  
                #Set-MsolUser -UserPrincipalName $User_UPN -StrongAuthenticationMethods @() -whatif
                #Reset-MsolStrongAuthenticationMethodByUpn -UserPrincipalName $User_UPN -Whatif
                Write-Host -f Green "Successully reset Azure MFA for $User_UPN" -NoNewline

            }

        }

        Else
        {

        Write-Host -f Red "$AzureConnection_UPN doesn't have active or eligible Authentication Administrator role."
        pause

        }

    }

}

Else
{

Write-Host -f Red "$AzureConnection_UPN doesn't have active or eligible role."
pause

}