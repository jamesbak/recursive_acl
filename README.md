# Recursive Access Control List (ACL) assignment for Azure Data Lake Storage Gen2

This script is designed to allow users of ADLS Gen2 to update ACL assignments in a recursive nature (ie. propogate changes down an entire container or directory branch).

The ADLS ACL mechanism is modeled after the POSIX defacto standard. This mechanism propogates default permission assignments from the containing directory to a newly created object (file or sub-directory) at creation time and thereafter no relationship exists. As a consequence, large-scale changes are difficult to apply, especially as these changes often align to directory structures. The published best practices for management of ACLs (https://docs.microsoft.com/en-us/azure/storage/blobs/data-lake-storage-best-practices#use-security-groups-versus-individual-users) mitigate this situation by leveraging application of security groups rather than individual users or service principals. However, this approach does not address all requirements for ACL management and therefore this script can be used to make more drammatic changes than can be handled by adjusting group membership.

## Dependencies
- The script is written in PowerShell and requires PowerShell >= 5.1. 
- A provisioned AAD Service Principal that has been assigned 
