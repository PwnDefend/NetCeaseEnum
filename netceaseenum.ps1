#this script will read the permissions on the reg key: HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity

$lanmanserver = get-item -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity

$lanmanserver

foreach($key in $lanmanserver)
{

write-host $key.Name
write-host $key.SubKeyCount
#get the key and value (it's a REG_BINARY)
$bytes = $key.GetValue("SrvsvcSessionInfo", $null)
write-host $bytes
#make this readible
$sec_descriptor = New-Object -TypeName System.Security.AccessControl.CommonSecurityDescriptor -ArgumentList $true, $false, $bytes, 0
$sec_descriptor

$sec_descriptor.DiscretionaryAcl

$sec_descriptor.DiscretionaryAcl| Select-Object SecurityIdentifier, ACEType | Format-Table -AutoSize
#well known sids = https://docs.microsoft.com/en-US/troubleshoot/windows-server/identity/security-identifiers-in-windows

$sec_ids = $sec_descriptor.DiscretionaryAcl

foreach($object in $sec_ids){
write-host $object.SecurityIdentifier
if($object.SecurityIdentifier -eq "S-1-5-11"){write-host "Vulnerable to recon" -ForegroundColor Red}else{write-host "NOT Vulnerable to Autheticated Users Recon" -ForegroundColor Green}



}


}
