# Recursive Access Control List (ACL) assignment for Azure Data Lake Storage Gen2

This script is designed to allow users of ADLS Gen2 to update ACL assignments in a recursive nature (ie. propogate changes down an entire container or directory branch).

The ADLS ACL mechanism is modeled after the POSIX defacto standard. This mechanism propogates default permission assignments from the containing directory to a newly created object (file or sub-directory) at creation time and thereafter no relationship exists. As a consequence, large-scale changes are difficult to apply, especially as these changes often align to directory structures. The published best practices for management of ACLs; [https://docs.microsoft.com/azure/storage/blobs/data-lake-storage-best-practices#use-security-groups-versus-individual-users](https://docs.microsoft.com/azure/storage/blobs/data-lake-storage-best-practices#use-security-groups-versus-individual-users) mitigate this situation by leveraging application of security groups rather than individual users or service principals. However, this approach does not address all requirements for ACL management and therefore this script can be used to make broader changes than can be handled by adjusting group membership.

## Dependencies
1. The script is written in PowerShell and requires PowerShell >= 5.1. 
2. A provisioned AAD Service Principal that has been assigned **[Storage Blob Data Owner](https://docs.microsoft.com/azure/role-based-access-control/built-in-roles#storage-blob-data-owner)** role on the target account or container.
3. A working understanding of how ACLs are applied and their effect in ADLS Gen2 as described here; [https://docs.microsoft.com/azure/storage/blobs/data-lake-storage-access-control](https://docs.microsoft.com/azure/storage/blobs/data-lake-storage-access-control) 

## ACL Update Modes
The script has two modes for applying ACL modifications:
1. **Absolute** ACL replacement - this mode will update the ACL of *every* file or directory to match the ACL string specified in the `$absoluteAcl` variable.
2. **Merge** a single Acess Control Entry (ACE) into the existing ACL for an object - this mode will merge the specified principal/permissions tuple (specified via the `$mergePrincipal`, `$mergeType` and `$mergePerms` variables) into the existing ACL of every file and directory.

Note that when specifying user identities in the ACL, you may specify either the user's *User Principal Name (UPN)* (eg. mary@contoso.com) or the user's *Object ID (OID)* (a guid value). When specifying a Service Principal or a Security Group, only the *OID* may be used.

## Instructions
1. Open the PowerShell script [recursive-acl-assignment.ps1](./recursive-acl-assignment.ps1) in a text editor
2. Update the `$clientId`, `$clientSecret` and `$tenant` variables with the details of the Service Principal as specified in dependency 2. above. All calls to ADLS made by the script will be authenticated using these details.
3. Update the `$accountName` and `$container` with the details of the ADLS account that you wish to update. Optionally, you can update the `$rootDir` variable with the path to the directory where you wish to start the update. If you specify a root directory, only files and sub-directories contained *below* that directory will be processed. If you wish to update the entire container, leave this variable `$null`.
4. If you intend to use **absolute** update mode, update the `$absoluteAcl` variable with the complete ACL string that you wish to apply to every object. The format of this string is defined in the `x-ms-acl` header here; [https://docs.microsoft.com/rest/api/storageservices/datalakestoragegen2/path/update](https://docs.microsoft.com/rest/api/storageservices/datalakestoragegen2/path/update). This ACL string must also include `default` permissions that will be applied to sub-directories. You can optionally include a `mask` value as well.  Additionally, you must assign `$mergePrincipal = $null` to specify that you wish to apply an absolute ACL. An example of this string is:
```
user::rwx,default:user::rwx,group::r-x,default:group::r-x,other::---,default:other::---,mask::rwx,default:mask::rwx,user:mary@contoso.com:rwx,default:user:mary@contoso.com:rwx,group:5117a2b0-f09b-44e9-b92a-fa91a95d5c28:r-x,default:group:5117a2b0-f09b-44e9-b92a-fa91a95d5c28:r-x
```
5. If you wish to merge (or optionally remove) a single ACE into the existing ACL for each object, update the `$mergePrincipal`, `$mergeType` and `$mergePerms` variables to reflect the values of the ACE you wish to merge. Optionally, assign `$removeEntry = $true` to remove any entry containing `$mergePrincipal` and `$mergeType` from the ACL.
6. Save the file.
7. Invoke the script with the following command-line:
```
powershell -ExecutionPolicy Bypass -File recursive-acl-assignment.ps1
```
8. Monitor the script's progress and any errors that are raised.
 

