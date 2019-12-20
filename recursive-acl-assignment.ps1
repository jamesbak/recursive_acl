# Parameters
# For token authN & authZ
$clientId="<enter-spn-client-id>"
$clientSecret="<enter-spn-client-secret>"
$tenant="<enter AAD tenant id or DNS name>"
# Identify location to apply ACL update from
$accountName = "<enter-account-name>"
$container = "<enter-container-name>"
$rootDir = "<enter directory name - can be $null>"
# Specify how the ACL should be updated. 2 modes:
#  1. Absolute ACL - gets applied across the entire structure - assign $absoluteAcl - including default permissions, masks, etc.
#       Eg: user::rwx,default:user::rwx,group::r-x,default:group::r-x,other::---,default:other::---,mask::rwx,default:mask::rwx,user:mary@contoso.com:rwx,default:user:mary@contoso.com:rwx,group:5117a2b0-f09b-44e9-b92a-fa91a95d5c28:rwx,default:group:5117a2b0-f09b-44e9-b92a-fa91a95d5c28:rwx
#  2. Merge an ACE with existing ACL - assign $mergePricipal, $mergeType & $mergePerms
# $absoluteAcl & $mergePrincipal are mutually exclusive - 1 of them must be $null
$absoluteAcl = "[scope:][type]:[id]:[permissions],[scope:][type]:[id]:[permissions]"
$mergePrincipal = $null
$mergeType = "group"
$mergePerms = "rwx"
# Use this variable in conjunction with $mergePrincipal & $mergeType to remove an ACE
$removeEntry = $false

# Number of parallel runspaces to execute this operation
$numRunspaces = 100
# This should always be $true. Set to $false to make the whole operation run single-threaded
$useRunspaces = $true
# Max # of items per parallel batch
$maxItemsPerBatch = 5000

# Accumulate processing stats (thread safe counters)
$itemsStats = @{
    itemsProcessed = New-Object System.Threading.SemaphoreSlim -ArgumentList @(0)
    itemsUpdated = New-Object System.Threading.SemaphoreSlim -ArgumentList @(0)
    itemsErrors = New-Object System.Threading.SemaphoreSlim -ArgumentList @(0)
}
$oldProgressPreference = $Global:ProgressPreference
$Global:ProgressPreference = "SilentlyContinue"
# Setup headers for subsequent calls to DFS REST API
$headers = @{
    "x-ms-version" = "2018-11-09"
}
$baseUri = "https://$accountName.dfs.core.windows.net/$container"
$baseListUri = $baseUri + "`?resource=filesystem&recursive=true&upn=true&maxResults=$maxItemsPerBatch"
if ($null -ne $rootDir) {
    $baseListUri = $baseListUri + "&directory=$rootDir"
}
# If we have an absolute ACL, we actually need 2 versions; 1 for directories (containing default perms) & 1 for files without default perms
if ($null -ne $absoluteAcl) {
    $entries = $absoluteAcl.Split(',') | ForEach-Object {
        $entry = $_.split(':')
        if ($entry[0] -ne "default") {
            $_
        }
    }
    $fileAbsoluteAcl = $entries -join ','
}

# Parameters shared across all workers
$itemParams = @{
    absoluteAcl = $absoluteAcl
    fileAbsoluteAcl = $fileAbsoluteAcl
    mergePrincipal = $mergePrincipal
    mergeType = $mergeType
    mergePerms = $mergePerms
    removeEntry = $removeEntry
    baseUri = $baseUri
    requestHeaders = $headers
    tokenElapseDelta = New-TimeSpan -Seconds 120
    clientId = $clientId
    clientSecret = $clientSecret
    tenant = $tenant
}
# Token acquisition - needs to be callable from background Runspaces
Function New-AccessToken($sharedParams) {
    # Acquire auth token
    $body = @{
        client_id = $sharedParams.clientId
        client_secret = $sharedParams.clientSecret
        scope = "https://storage.azure.com/.default"
        grant_type = "client_credentials"
    }
    $token = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$($sharedParams.tenant)/oauth2/v2.0/token" -Body $body
    $sharedParams.requestHeaders.Authorization = "Bearer " + $token.access_token
    $sharedParams.tokenExpiry = (Get-Date).AddSeconds($token.expires_in)
}
# Check if token needs to be renewed
Function Reset-TokenExpiry($sharedParams) {
    if ($sharedParams.tokenExpiry - (Get-Date) -le $sharedParams.tokenElapseDelta) {
        New-AccessToken $sharedParams
    }
}
# Acquire initial token
New-AccessToken $itemParams
# Worker script block
$scriptBlock = {
    Param ($items, $sharedParams)

    $Global:ProgressPreference = "SilentlyContinue"
    $items | ForEach-Object {
        #$host.UI.WriteDebugLine("Processing: " + $_.name)
        $itemsStats.itemsProcessed.Release() | Out-Null
        $item = $_
        try {
            if ($_.isDirectory) {
                $updatedAcl = $sharedParams.absoluteAcl
            } 
            else {
                $updatedAcl = $sharedParams.fileAbsoluteAcl
            }
            # If we're merging an entry into the existing file's ACL, then we need to retrieve the full ACL first
            if ($null -ne $sharedParams.mergePrincipal) {
                try {
                    Reset-TokenExpiry $sharedParams
                    $aclResp = Invoke-WebRequest -Method Head -Headers $sharedParams.requestHeaders "$($sharedParams.baseUri)/$($_.name)`?action=getAccessControl&upn=true"
                    $currentAcl = $aclResp.Headers["x-ms-acl"]
                    # Check if we need to update the ACL
                    $entryFound = $false
                    $entryModified = $false
                    # Process the ACL. Format of each entry is; [scope:][type]:[id]:[permissions]
                    $updatedEntries = $currentAcl.Split(',') | ForEach-Object { 
                        $entry = $_.split(':')
                        # handle 'default' scope
                        $doOutput = $true
                        $idxOffset = 0
                        if ($entry.Length -eq 4) {
                            $idxOffset = 1
                        }
                        if ($entry[$idxOffset + 0] -eq $sharedParams.mergeType -and $entry[$idxOffset + 1] -eq $sharedParams.mergePrincipal) {
                            $entryFound = $true
                            if ($sharedParams.removeEntry) {
                                # Remove the entry by not outputing if from this expression
                                $doOutput = $false
                                $entryModified = $true
                            }
                            elseif ($entry[$idxOffset + 2] -ne $sharedParams.mergePerms) {
                                $entry[$idxOffset + 2] = $sharedParams.mergePerms
                                $_ = $entry -join ':'
                                $entryModified = $true
                            }
                        }
                        if ($doOutput) {
                            $_
                        }
                    } 
                    if ($entryFound -eq $true -and $entryModified -eq $true) {
                        $updatedAcl = $updatedEntries -join ','
                    } elseif ($entryFound -eq $true) {
                        $updatedAcl = $null
                    } elseif ($sharedParams.removeEntry -ne $true) {
                        $updatedAcl = "$currentAcl,$($sharedParams.mergeType)`:$($sharedParams.mergePrincipal)`:$($sharedParams.mergePerms)"
                        if ($_.isDirectory) {
                            $updatedAcl = $updatedAcl + ",default`:$($sharedParams.mergeType)`:$($sharedParams.mergePrincipal)`:$($sharedParams.mergePerms)"
                        }
                    }
                }
                catch [System.Net.WebException] {
                    $host.UI.WriteErrorLine("Failed to retrieve existing ACL for $($item.name). This file will be skipped. Details: " + $_)
                    $itemsStats.itemsErrors.Release()
                    $updatedAcl = $null
                }
            }
            if ($null -ne $updatedAcl) {
                $host.UI.WriteDebugLine("Updating ACL for: $($_.name):$updatedAcl")
                try {
                    Reset-TokenExpiry $sharedParams
                    Invoke-WebRequest -Method Patch -Headers ($sharedParams.requestHeaders + @{"x-ms-acl" = $updatedAcl}) "$($sharedParams.baseUri)/$($_.name)`?action=setAccessControl" | Out-Null
                    $itemsStats.itemsUpdated.Release()
                }
                catch [System.Net.WebException] {
                    $host.UI.WriteErrorLine("Failed to update ACL for $($item.name). Details: " + $_)
                    $itemsStats.itemsErrors.Release()
                }
            }
        }
        catch {
            $host.UI.WriteErrorLine("Unknown failure processing $($item.name). Details: " + $_)
            $itemsStats.itemsErrors.Release()
        }
    }
}
# Setup our Runspace Pool
if ($useRunspaces) {
    $sessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $sessionState.ThreadOptions = [System.Management.Automation.Runspaces.PSThreadOptions]::UseNewThread
    # Marshall variables & functions over to the RunspacePool
    $sessionState.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList 'itemsStats', $itemsStats, ""))
    $sessionState.Commands.Add((New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList 'New-AccessToken', (Get-Content Function:\New-AccessToken -ErrorAction Stop)))
    $sessionState.Commands.Add((New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList 'Reset-TokenExpiry', (Get-Content Function:\Reset-TokenExpiry -ErrorAction Stop)))
    $runspacePool = [RunspaceFactory]::CreateRunspacePool(1, $numRunspaces, $sessionState, $Host)
    $runspacePool.Open()
}
$runSpaces = [System.Collections.ArrayList]@()

# Loop through the entire listing until we've processed all files & directories
$continuationToken = $null
do {
    $listUri = $baseListUri
    # Include the continuation token if we've got one
    if ($null -ne $continuationToken) {
        $listUri = $listUri + "&continuation=" + [System.Web.HttpUtility]::UrlEncode($continuationToken)
    }
    try {
        Reset-TokenExpiry $itemParams
        $listResp = Invoke-WebRequest -Method Get -Headers $itemParams.requestHeaders $listUri
        if ($useRunspaces) {
            # Dispatch this list to a new runspace
            $ps = [powershell]::Create().
                AddScript($scriptBlock).
                AddArgument(($listResp.Content | ConvertFrom-Json).paths).
                AddArgument($itemParams)
            $ps.RunspacePool = $runspacePool
            $runSpace = New-Object -TypeName psobject -Property @{
                PowerShell = $ps
                Handle = $($ps.BeginInvoke())
            }
            $runSpaces.Add($runSpace) | Out-Null
        }
        else {
            Invoke-Command -ScriptBlock $scriptBlock -ArgumentList @(($listResp.Content | ConvertFrom-Json).paths, $itemParams)
        }

        $continuationToken = $listResp.Headers["x-ms-continuation"]
    }
    catch [System.Net.WebException] {
        $host.UI.WriteErrorLine("Failed to list directories and files. Details: " + $_)
    }
} while ($listResp.StatusCode -eq 200 -and $null -ne $continuationToken)

# Cleanup
$host.UI.WriteLine("Waiting for completion & cleaning up")
while ($runSpaces.Count -gt 0) {
    $idx = [System.Threading.WaitHandle]::WaitAny($($runSpaces | Select-Object -First 64 | ForEach-Object { $_.Handle.AsyncWaitHandle }))
    $runSpace = $runSpaces.Item($idx)
    $runSpace.PowerShell.EndInvoke($runSpace.Handle) | Out-Null
    $runSpace.PowerShell.Dispose()
    $runSpaces.RemoveAt($idx)
}
$Global:ProgressPreference = $oldProgressPreference
$host.UI.WriteLine("Completed. Items processed: $($itemsStats.itemsProcessed.CurrentCount), items updated: $($itemsStats.itemsUpdated.CurrentCount), errors: $($itemsStats.itemsErrors.CurrentCount)")
