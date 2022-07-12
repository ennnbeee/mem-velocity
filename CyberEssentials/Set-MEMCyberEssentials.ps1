[CmdletBinding()]
param(
    [ValidateSet('Corporate', 'BYOD', 'Both')]
    [string]$Windows,
    [ValidateSet('Corporate', 'BYOD', 'Both')]
    [string]$Android,
    [ValidateSet('Corporate', 'BYOD', 'Both')]
    [string]$iOS,
    [ValidateSet('Corporate', 'BYOD', 'Both')]
    [string]$macOS
)

## Functions
function Get-AuthToken {

    <#
    .SYNOPSIS
    This function is used to authenticate with the Graph API REST interface
    .DESCRIPTION
    The function authenticate with the Graph API Interface with the tenant name
    .EXAMPLE
    Get-AuthToken
    Authenticates you with the Graph API interface
    .NOTES
    NAME: Get-AuthToken
    #>
    
    [cmdletbinding()]
    
    param
    (
        [Parameter(Mandatory = $true)]
        $User
    )
    
    $userUpn = New-Object "System.Net.Mail.MailAddress" -ArgumentList $User
    
    $tenant = $userUpn.Host
    
    Write-Host "Checking for AzureAD module..."
    
    $AadModule = Get-Module -Name "AzureAD" -ListAvailable
    
    if ($null -eq $AadModule) {
    
        Write-Host "AzureAD PowerShell module not found, looking for AzureADPreview"
        $AadModule = Get-Module -Name "AzureADPreview" -ListAvailable
    
    }
    
    if ($null -eq $AadModule) {
        write-host
        write-host "AzureAD Powershell module not installed..." -f Red
        write-host "Install by running 'Install-Module AzureAD' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt" -f Yellow
        write-host "Script can't continue..." -f Red
        write-host
        exit
    }
    
    # Getting path to ActiveDirectory Assemblies
    # If the module count is greater than 1 find the latest version
    
    if ($AadModule.count -gt 1) {
    
        $Latest_Version = ($AadModule | Select-Object version | Sort-Object)[-1]
    
        $aadModule = $AadModule | Where-Object { $_.version -eq $Latest_Version.version }
    
        # Checking if there are multiple versions of the same module found
    
        if ($AadModule.count -gt 1) {
    
            $aadModule = $AadModule | Select-Object -Unique
    
        }
    
        $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
    
    }
    
    else {
    
        $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
    
    }
    
    [System.Reflection.Assembly]::LoadFrom($adal) | Out-Null
    
    [System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null
    
    $clientId = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547"
    
    $redirectUri = "urn:ietf:wg:oauth:2.0:oob"
    
    $resourceAppIdURI = "https://graph.microsoft.com"
    
    $authority = "https://login.microsoftonline.com/$Tenant"
    
    try {
    
        $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority
    
        # https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx
        # Change the prompt behaviour to force credentials each time: Auto, Always, Never, RefreshSession
    
        $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Auto"
    
        $userId = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList ($User, "OptionalDisplayableId")
    
        $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI, $clientId, $redirectUri, $platformParameters, $userId).Result
    
        # If the accesstoken is valid then create the authentication header
    
        if ($authResult.AccessToken) {
    
            # Creating header for Authorization token
    
            $authHeader = @{
                'Content-Type'  = 'application/json'
                'Authorization' = "Bearer " + $authResult.AccessToken
                'ExpiresOn'     = $authResult.ExpiresOn
            }
    
            return $authHeader
    
        }
    
        else {
    
            Write-Host
            Write-Host "Authorization Access Token is null, please re-run authentication..." -ForegroundColor Red
            Write-Host
            break
    
        }
    
    }
    
    catch {
    
        write-host $_.Exception.Message -f Red
        write-host $_.Exception.ItemName -f Red
        write-host
        break
    
    }
    
}
Function Test-JSON() {

    <#
        .SYNOPSIS
        This function is used to test if the JSON passed to a REST Post request is valid
        .DESCRIPTION
        The function tests if the JSON passed to the REST Post is valid
        .EXAMPLE
        Test-JSON -JSON $JSON
        Test if the JSON is valid before calling the Graph REST interface
        .NOTES
        NAME: Test-JSON
        #>
        
    param (
        
        $JSON
        
    )
        
    try {
        
        $TestJSON = ConvertFrom-Json $JSON -ErrorAction Stop
        $validJson = $true
        
    }
        
    catch {
        
        $validJson = $false
        $_.Exception
        
    }
        
    if (!$validJson) {
            
        Write-Host "Provided JSON isn't in valid JSON format" -f Red
        break
        
    }
        
}
Function Add-DeviceCompliancePolicy() {

    
    [cmdletbinding()]
    
    param
    (
        $JSON
    )
    
    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/deviceCompliancePolicies"
        
    try {
    
        if ($JSON -eq "" -or $null -eq $JSON) {
    
            write-host "No JSON specified, please specify valid JSON for the iOS Policy..." -f Red
    
        }
    
        else {
    
            Test-JSON -JSON $JSON
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"
    
        }
    
    }
        
    catch {
    
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
        break
    
    }
    
}
Function Add-IntuneFilter() {


    [cmdletbinding()]

    param
    (
        $JSON
    )

    $graphApiVersion = "beta"
    $Resource = "deviceManagement/assignmentFilters"

    try {

        if ($JSON -eq "" -or $null -eq $JSON) {

            write-host "No JSON specified, please specify valid JSON for the Device Configuration Policy..." -f Red

        }

        else {

            Test-JSON -JSON $JSON

            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"

        }

    }
    
    catch {

        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
        break

    }

}
Function Get-IntuneFilter() {

    <#
    .SYNOPSIS
    This function is used to get all filters configured from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any filters created
    .EXAMPLE
    Get-IntuneFilter
    Returns any Filters configured in Intune
    .NOTES
    NAME: Get-IntuneFilter
    #>
    
  
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/assignmentFilters"
    
    try {
    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
    
    }
    
    catch {
    
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
        break
    
    }
    
}
Function Get-DeviceCompliancePolicy() {

    <#
    .SYNOPSIS
    This function is used to get device compliance policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device compliance policies
    .EXAMPLE
    Get-DeviceCompliancePolicy
    Returns any device compliance policies configured in Intune
    .EXAMPLE
    Get-DeviceCompliancePolicy -Android
    Returns any device compliance policies for Android configured in Intune
    .EXAMPLE
    Get-DeviceCompliancePolicy -iOS
    Returns any device compliance policies for iOS configured in Intune
    .NOTES
    NAME: Get-DeviceCompliancePolicy
    #>
    
    [cmdletbinding()]
    
  
    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/deviceCompliancePolicies"
    
    try {
    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
    
    }
    
    catch {
    
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
        break
    
    }
    
}
Function Add-DeviceCompliancePolicyAssignment() {

    <#
    .SYNOPSIS
    This function is used to add a device configuration policy assignment using the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and adds a device configuration policy assignment
    .EXAMPLE
    Add-DeviceConfigurationPolicyAssignment -ConfigurationPolicyId $ConfigurationPolicyId -TargetGroupId $TargetGroupId -AssignmentType Included
    Adds a device configuration policy assignment in Intune
    .NOTES
    NAME: Add-DeviceConfigurationPolicyAssignment
    #>
    
    [cmdletbinding()]
    
    param
    (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $Id,
    
        [parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        $TargetGroupId,
    
        [parameter(Mandatory = $true)]
        [ValidateSet("Include", "Exclude")]
        [ValidateNotNullOrEmpty()]
        [string]$AssignmentType,
        $FilterID,
        $FilterMode,
        [parameter(Mandatory = $false)]
        [ValidateSet("Users", "Devices")]
        [ValidateNotNullOrEmpty()]
        [string]$All
    )
    
    $graphApiVersion = "v1.0"
    $Resource = "deviceManagement/deviceCompliancePolicies/$Id/assign"
        
    try {
    
        if (!$Id) {
    
            write-host "No Configuration Policy Id specified, specify a valid Configuration Policy Id" -f Red
            break
    
        }
    
        $TargetGroup = New-Object -TypeName psobject

        if ($TargetGroupId) {

            if ($AssignmentType -eq "Exclude") {
        
                $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.exclusionGroupAssignmentTarget'
     
            }

            elseif ($AssignmentType -eq "Include") {

                $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.groupAssignmentTarget'
            }

            $TargetGroup | Add-Member -MemberType NoteProperty -Name 'groupId' -Value "$TargetGroupId"

        }

        else {

            if ($All -eq 'Users') {
                $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.allLicensedUsersAssignmentTarget'
            }

            ElseIf ($All -eq 'Devices') {
                $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.allDevicesAssignmentTarget'
            }

        }
        
        if (($FilterMode -eq 'Include') -or ($FilterMode -eq 'Exclude')) {
            
            $TargetGroup | Add-Member -MemberType NoteProperty -Name 'deviceAndAppManagementAssignmentFilterId' -Value "$FilterID"
            $TargetGroup | Add-Member -MemberType NoteProperty -Name 'deviceAndAppManagementAssignmentFilterType' -Value "$FilterMode"
        }

        $Target = New-Object -TypeName psobject
        $Target | Add-Member -MemberType NoteProperty -Name 'target' -Value $TargetGroup
        
        $TargetGroups = $Target
        
        # Creating JSON object to pass to Graph
        $Output = New-Object -TypeName psobject
        
        $Output | Add-Member -MemberType NoteProperty -Name 'assignments' -Value @($TargetGroups)
        
        $JSON = $Output | ConvertTo-Json -Depth 3
    
        # POST to Graph Service
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"
        write-host "Successfully added compliance policy assignment" -ForegroundColor Green
    
    }
        
    catch {
    
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
        break
    
    }
    
}
Function Set-MEMCompliance {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string[]]$Path,
        [ValidateSet('Windows', 'Android', 'iOS', 'macOS')]
        [string[]]$OS,
        [ValidateSet('Corporate', 'BYOD')]
        [string]$Enrolment
    )
    

    $Files = Get-ChildItem -Path $Path -Filter *.json | Where-Object { ($_.name -like "*$OS*") -and ($_.name -like "*$Enrolment*") }

    foreach ($file in $files) {
        $ImportPath = $file.FullName
        $JSON_Data = Get-Content "$ImportPath"
        # Excluding entries that are not required - id,createdDateTime,lastModifiedDateTime,version
        $JSON_Convert = $JSON_Data | ConvertFrom-Json | Select-Object -Property * -ExcludeProperty id, createdDateTime, lastModifiedDateTime, version
        $DisplayName = $JSON_Convert.displayName

        if (Get-DeviceCompliancePolicy | Where-Object { ($_.displayName).contains($DisplayName) }) {
            Write-Host "Compliance Policy '$DisplayName' already exists" -ForegroundColor Cyan

        }
        else {
               
            # Adding Scheduled Actions Rule to JSON
            #$scheduledActionsForRule = '"scheduledActionsForRule":[{"ruleName":"PasswordRequired","scheduledActionConfigurations":[{"actionType":"block","gracePeriodHours":0,"notificationTemplateId":"","notificationMessageCCList":[]}]}]'        
            #$JSON_Output = $JSON_Output.trimend("}")
            #$JSON_Output = $JSON_Output.TrimEnd() + "," + "`r`n"
            # Joining the JSON together
            #$JSON_Output = $JSON_Output + $scheduledActionsForRule + "`r`n" + "}"

            if (-not ($JSON_Convert.scheduledActionsForRule)) {
                $scheduledActionsForRule = @(
                    @{
                        ruleName                      = "PasswordRequired"
                        scheduledActionConfigurations = @(
                            @{
                                actionType             = "block"
                                gracePeriodHours       = 0
                                notificationTemplateId = ""
                            }
                        )
                    }
                )
                $JSON_Convert | Add-Member -NotePropertyName scheduledActionsForRule -NotePropertyValue $scheduledActionsForRule
        
            }
            $JSON_Output = $JSON_Convert | ConvertTo-Json -Depth 5
            Write-Host "Adding Compliance Policy '$DisplayName'" -ForegroundColor Cyan
            Add-DeviceCompliancePolicy -JSON $JSON_Output
            Write-Host "Sucessfully Added Compliance Policy '$DisplayName'" -ForegroundColor Green
        }
    }

    

}
Function Set-MEMFilters {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string[]]$Path,
        [ValidateSet('Windows', 'Android', 'iOS', 'macOS')]
        [string[]]$OS,
        [ValidateSet('Corporate', 'BYOD')]
        [string]$Enrolment
    )
    

    $Files = Get-ChildItem -Path $Path -Filter *.json | Where-Object { ($_.name -like "*$OS*") -and ($_.name -like "*$Enrolment*") }

    foreach ($file in $files) {
        $ImportPath = $file.FullName
        $JSON_Data = Get-Content "$ImportPath"
        $JSON_Convert = $JSON_Data | ConvertFrom-Json | Select-Object -Property * -ExcludeProperty id, createdDateTime, lastModifiedDateTime, roleScopeTags
        $DisplayName = $JSON_Convert.displayName

        if (Get-IntuneFilter | Where-Object { ($_.displayName).contains($DisplayName) }) {
            Write-Host "Intune Filter '$DisplayName' already exists" -ForegroundColor Cyan

        }
        else {
            $JSON_Output = $JSON_Convert | ConvertTo-Json -Depth 5
            Write-Host "Adding Intune Filter '$DisplayName'" -ForegroundColor Cyan
            Add-IntuneFilter -JSON $JSON_Output
            Write-Host "Sucessfully Added Intune Filter '$DisplayName'" -ForegroundColor Green
        }


    }

    

}

Write-host "Starting Deployment..." -ForegroundColor Cyan
Write-Host
#region Authentication
# Checking if authToken exists before running authentication
if ($global:authToken) {

    # Setting DateTime to Universal time to work in all timezones
    $DateTime = (Get-Date).ToUniversalTime()

    # If the authToken exists checking when it expires
    $TokenExpires = ($authToken.ExpiresOn.datetime - $DateTime).Minutes

    if ($TokenExpires -le 0) {

        write-host "Authentication Token expired" $TokenExpires "minutes ago" -ForegroundColor Yellow
        write-host

        # Defining User Principal Name if not present

        if ($null -eq $User -or $User -eq "") {

            $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
            Write-Host

        }

        $global:authToken = Get-AuthToken -User $User

    }
}

# Authentication doesn't exist, calling Get-AuthToken function

else {

    if ($null -eq $User -or $User -eq "") {

        $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
        Write-Host

    }

    # Getting the authorization token
    $global:authToken = Get-AuthToken -User $User
    Write-host "Connected to Graph API" -ForegroundColor Green
    Write-Host
}

#endregion

$ScriptPath = (Get-Location).Path
$CompliancePath = $ScriptPath + "\Compliance"
$FilterPath = $ScriptPath + "\Filters"

if ($Windows) {
    Write-host "Starting Windows Deployment..." -ForegroundColor Cyan
    Write-Host
    if (($Windows -eq "Corporate") -or ($Windows -eq "Both")) {
        Set-MEMCompliance -Path $CompliancePath -OS Windows -Enrolment Corporate
        Set-MEMFilters -Path $FilterPath -OS Windows -Enrolment Corporate

        $DeviceFilterID = (Get-IntuneFilter | Where-Object { ($_.displayName).contains("Filter_Windows_Corporate_All") }).id
        $CompliancePolicies = Get-DeviceCompliancePolicy | Where-Object { ($_.'@odata.type').contains("windows10") -and ($_.displayName).contains("Windows_Corporate_") }

        foreach ($CompliancePolicy in $CompliancePolicies) {
            Add-DeviceCompliancePolicyAssignment -Id $CompliancePolicy.id -All Users -AssignmentType Include -FilterID $DeviceFilterID -FilterMode Include
        }
    }
    if (($Windows -eq "BYOD") -or ($Windows -eq "Both")) {
        Set-MEMCompliance -Path $CompliancePath -OS Windows -Enrolment BYOD
        Set-MEMFilters -Path $FilterPath -OS Windows -Enrolment BYOD

        $DeviceFilterID = (Get-IntuneFilter | Where-Object { ($_.displayName).contains("Filter_Windows_BYOD_All") }).id
        $CompliancePolicies = Get-DeviceCompliancePolicy | Where-Object { ($_.'@odata.type').contains("windows10") -and ($_.displayName).contains("Windows_BYOD_") }

        foreach ($CompliancePolicy in $CompliancePolicies) {
            Add-DeviceCompliancePolicyAssignment -Id $CompliancePolicy.id -All Users -AssignmentType Include -FilterID $DeviceFilterID -FilterMode Include
        }
    }
}
if ($Android) {
    Write-host "Starting Android Deployment..." -ForegroundColor Cyan
    Write-Host
    if (($Android -eq "Corporate") -or ($Android -eq "Both")) {
        Set-MEMCompliance -Path $CompliancePath -OS Android -Enrolment Corporate
        Set-MEMFilters -Path $FilterPath -OS Android -Enrolment Corporate

        $DeviceFilterID = (Get-IntuneFilter | Where-Object { ($_.displayName).contains("Filter_Android_Enterprise_Corporate_All") }).id
        $CompliancePolicies = Get-DeviceCompliancePolicy | Where-Object { ($_.'@odata.type').contains("android") -and ($_.displayName).contains("Android_Corporate_") }

        foreach ($CompliancePolicy in $CompliancePolicies) {
            Add-DeviceCompliancePolicyAssignment -Id $CompliancePolicy.id -All Users -AssignmentType Include -FilterID $DeviceFilterID -FilterMode Include
        }
    }
    if (($Android -eq "BYOD") -or ($Android -eq "Both")) {
        Set-MEMCompliance -Path $CompliancePath -OS Android -Enrolment BYOD
        Set-MEMFilters -Path $FilterPath -OS Android -Enrolment BYOD

        $DeviceFilterID = (Get-IntuneFilter | Where-Object { ($_.displayName).contains("Filter_Android_BYOD_Work_Profile_All") }).id
        $CompliancePolicies = Get-DeviceCompliancePolicy | Where-Object { ($_.'@odata.type').contains("android") -and ($_.displayName).contains("Android_BYOD_") }

        foreach ($CompliancePolicy in $CompliancePolicies) {
            Add-DeviceCompliancePolicyAssignment -Id $CompliancePolicy.id -All Users -AssignmentType Include -FilterID $DeviceFilterID -FilterMode Include
        }
    }
}
if ($iOS) {
    Write-host "Starting iOS/iPadOS Deployment..." -ForegroundColor Cyan
    Write-Host
    if (($iOS -eq "Corporate") -or ($iOS -eq "Both")) {
        Set-MEMCompliance -Path $CompliancePath -OS iOS -Enrolment Corporate
        Set-MEMFilters -Path $FilterPath -OS iOS -Enrolment Corporate

        $DeviceFilterID = (Get-IntuneFilter | Where-Object { ($_.displayName).contains("Filter_iOS_Corporate_All") }).id
        $CompliancePolicies = Get-DeviceCompliancePolicy | Where-Object { ($_.'@odata.type').contains("ios") -and ($_.displayName).contains("iOS_Corporate_") }

        foreach ($CompliancePolicy in $CompliancePolicies) {
            Add-DeviceCompliancePolicyAssignment -Id $CompliancePolicy.id -All Users -AssignmentType Include -FilterID $DeviceFilterID -FilterMode Include
        }
    }
    if (($iOS -eq "BYOD") -or ($iOS -eq "Both")) {
        Set-MEMCompliance -Path $CompliancePath -OS iOS -Enrolment BYOD
        Set-MEMFilters -Path $FilterPath -OS iOS -Enrolment BYOD

        $DeviceFilterID = (Get-IntuneFilter | Where-Object { ($_.displayName).contains("Filter_iOS_BYOD_All") }).id
        $CompliancePolicies = Get-DeviceCompliancePolicy | Where-Object { ($_.'@odata.type').contains("ios") -and ($_.displayName).contains("iOS_BYOD_") }

        foreach ($CompliancePolicy in $CompliancePolicies) {
            Add-DeviceCompliancePolicyAssignment -Id $CompliancePolicy.id -All Users -AssignmentType Include -FilterID $DeviceFilterID -FilterMode Include
        }
    }
}
if ($macOS) {
    Write-host "Starting macOS Deployment..." -ForegroundColor Cyan
    Write-Host
    if (($macOS -eq "Corporate") -or ($macOS -eq "Both")) {
        Set-MEMCompliance -Path $CompliancePath -OS macOS -Enrolment Corporate
        Set-MEMFilters -Path $FilterPath -OS macOS -Enrolment Corporate

        $DeviceFilterID = (Get-IntuneFilter | Where-Object { ($_.displayName).contains("Filter_Windows_Corporate_All") }).id
        $CompliancePolicies = Get-DeviceCompliancePolicy | Where-Object { ($_.'@odata.type').contains("macOS") -and ($_.displayName).contains("MacOS_Corporate_") }

        foreach ($CompliancePolicy in $CompliancePolicies) {
            Add-DeviceCompliancePolicyAssignment -Id $CompliancePolicy.id -All Users -AssignmentType Include -FilterID $DeviceFilterID -FilterMode Include
        }
    }
    if (($macOS -eq "BYOD") -or ($macOS -eq "Both")) {
        Set-MEMCompliance -Path $CompliancePath -OS macOS -Enrolment BYOD
        Set-MEMFilters -Path $FilterPath -OS macOS -Enrolment BYOD

        $DeviceFilterID = (Get-IntuneFilter | Where-Object { ($_.displayName).contains("Filter_Windows_BYOD_All") }).id
        $CompliancePolicies = Get-DeviceCompliancePolicy | Where-Object { ($_.'@odata.type').contains("macOS") -and ($_.displayName).contains("MacOS_BYOD_") }

        foreach ($CompliancePolicy in $CompliancePolicies) {
            Add-DeviceCompliancePolicyAssignment -Id $CompliancePolicy.id -All Users -AssignmentType Include -FilterID $DeviceFilterID -FilterMode Include
        }
    }
}
