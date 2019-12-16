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
$mergeType = "user"
$mergePerms = "rwx"
# Use this variable in conjunction with $mergePrincipal & $mergeType to remove an ACE
$removeEntry = $false

# Acquire auth token
$body = @{
    client_id = $clientId
    client_secret = $clientSecret
    scope = "https://storage.azure.com/.default"
    grant_type = "client_credentials"
}
$token = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$tenant/oauth2/v2.0/token" -Body $body
# Setup headers for subsequent calls to DFS REST API
$headers = @{
    "x-ms-version" = "2018-11-09"
    Authorization = "Bearer " + $token.access_token
}
$baseUri = "https://$accountName.dfs.core.windows.net/$container"
$baseListUri = $baseUri + "`?resource=filesystem&recursive=true&upn=true"
if ($rootDir -ne $null) {
    $baseListUri = $baseListUri + "&directory=$rootDir"
}
# If we have an absolute ACL, we actually need 2 versions; 1 for directories (containing default perms) & 1 for files without default perms
if ($null -ne $absoluteAcl) {
    $entries = $absoluteAcl.Split(',') | % {
        $entry = $_.split(':')
        if ($entry[0] -ne "default") {
            $_
        }
    }
    $fileAbsoluteAcl = $entries -join ','
}
# Loop through the entire listing until we've processed all files & directories
$continuationToken = $null
do {
    $listUri = $baseListUri
    # Include the continuation token if we've got one
    if ($null -ne $continuationToken) {
        $listUri = $listUri + "&continuation=" + [System.Web.HttpUtility]::UrlEncode($continuationToken)
    }
    $listResp = Invoke-WebRequest -Method Get -Headers $headers $listUri
    if ($listResp.StatusCode -eq 200) {
        ($listResp.Content | ConvertFrom-Json).paths | % {
            Write-Output "Processing: $($_.name)" 
            if ($_.isDirectory) {
                $updatedAcl = $absoluteAcl
            } 
            else {
                $updatedAcl = $fileAbsoluteAcl
            }
            # If we're merging an entry into the existing file's ACL, then we need to retrieve the full ACL first
            if ($mergePrincipal -ne $null) {
                $aclResp = Invoke-WebRequest -Method Head -Headers $headers "$baseUri/$($_.name)`?action=getAccessControl&upn=true"
                if ($aclResp.StatusCode -eq 200) {
                    $currentAcl = $aclResp.Headers["x-ms-acl"]
                    # Check if we need to update the ACL
                    $entryFound = $false
                    $entryModified = $false
                    # Process the ACL. Format of each entry is; [scope:][type]:[id]:[permissions]
                    $updatedEntries = $currentAcl.Split(',') | % { 
                        $entry = $_.split(':')
                        # handle 'default' scope
                        $doOutput = $true
                        $idxOffset = 0
                        if ($entry.Length -eq 4) {
                            $idxOffset = 1
                        }
                        if ($entry[$idxOffset + 0] -eq $mergeType -and $entry[$idxOffset + 1] -eq $mergePrincipal) {
                            $entryFound = $true
                            if ($removeEntry) {
                                # Remove the entry by not outputing if from this expression
                                $doOutput = $false
                                $entryModified = $true
                            }
                            elseif ($entry[$idxOffset + 2] -ne $mergePerms) {
                                $entry[$idxOffset + 2] = $mergePerms
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
                    } elseif ($removeEntry -ne $true) {
                        $updatedAcl = "$currentAcl,$mergeType`:$mergePrincipal`:$mergePerms"
                        if ($_.isDirectory) {
                            $updatedAcl = $updatedAcl + ",default`:$mergeType`:$mergePrincipal`:$mergePerms"
                        }
                    }
                }
                else {
                    Write-Error "Failed to retrieve existing ACL for $($_.name). Details: " + $aclResp
                    $updatedAcl = $null
                }
            }
            if ($updatedAcl -ne $null) {
                Write-Output "Updating ACL for: $($_.name)"
                $setAclResp = Invoke-WebRequest -Method Patch -Headers ($headers + @{"x-ms-acl" = $updatedAcl}) "$baseUri/$($_.name)`?action=setAccessControl"
                if ($setAclResp.StatusCode -ge 300) {
                    Write-Error "Failed to update ACL for $($_.name). Details: " + $setAclResp
                }
            }
        }
        $continuationToken = $listResp.Headers["x-ms-continuation"]
    }
    else {
        Write-Error "Failed to list directories and files. Details: " + $listResp
    }
} while ($listResp.StatusCode -eq 200 -and $null -ne $continuationToken)
