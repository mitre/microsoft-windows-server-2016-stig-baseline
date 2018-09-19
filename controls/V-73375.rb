domain_role = command("wmic computersystem get domainrole | Findstr /v DomainRole").stdout.strip
control "V-73375" do
  title "The Active Directory Domain Controllers Organizational Unit (OU)
  object must have the proper access control permissions."
  desc  "When Active Directory objects do not have appropriate access control
  permissions, it may be possible for malicious users to create, read, update, or
  delete the objects and degrade or destroy the integrity of the data. When the
  directory service is used for identification, authentication, or authorization
  functions, a compromise of the database objects could lead to a compromise of
  all systems that rely on the directory service.

      The Domain Controllers OU object requires special attention as the Domain
  Controllers are central to the configuration and management of the domain.
  Inappropriate access permissions defined for the Domain Controllers OU could
  allow an intruder or unauthorized personnel to make changes that could lead to
  the compromise of the domain.
  "
  if domain_role == '4' || domain_role == '5'
    impact 0.7
  else
    impact 0.0
  end
  tag "gtitle": "SRG-OS-000324-GPOS-00125"
  tag "gid": "V-73375"
  tag "rid": "SV-88027r2_rule"
  tag "stig_id": "WN16-DC-000100"
  tag "fix_id": "F-84911r1_fix"
  tag "cci": ["CCI-002235"]
  tag "nist": ["AC-6 (10)", "Rev_4"]
  tag "documentable": false
  tag "check": "This applies to domain controllers. It is NA for other systems.

  Review the permissions on the Domain Controllers OU.

  Open \"Active Directory Users and Computers\" (available from various menus or
  run \"dsa.msc\").

  Select \"Advanced Features\" in the \"View\" menu if not previously selected.

  Select the \"Domain Controllers\" OU (folder in folder icon).

  Right-click and select \"Properties\".

  Select the \"Security\" tab.

  If the permissions on the Domain Controllers OU do not restrict changes to
  System, Domain Admins, Enterprise Admins and Administrators, this is a finding.

  The default permissions listed below satisfy this requirement.

  Domains supporting Microsoft Exchange will have additional Exchange related
  permissions on the Domain Controllers OU.  These may include some change
  related permissions and are not a finding.

  The permissions shown are at the summary level. More detailed permissions can
  be viewed by selecting the \"Advanced\" button, the desired Permission entry,
  and the \"View\" or \"Edit\" button.

  Except where noted otherwise, the special permissions may include a wide range
  of permissions and properties and are acceptable for this requirement.

  CREATOR OWNER - Special permissions

  SELF - Special permissions

  Authenticated Users - Read, Special permissions

  The special permissions for Authenticated Users are Read types.

  If detailed permissions include any Create, Delete, Modify, or Write
  Permissions or Properties, this is a finding.

  SYSTEM - Full Control

  Domain Admins - Read, Write, Create all child objects, Generate resultant set
  of policy (logging), Generate resultant set of policy (planning), Special
  permissions

  Enterprise Admins - Full Control

  Key Admins - Special permissions

  Enterprise Key Admins - Special permissions

  Administrators - Read, Write, Create all child objects, Generate resultant set
  of policy (logging), Generate resultant set of policy (planning), Special
  permissions

  Pre-Windows 2000 Compatible Access - Special permissions

  The Special permissions for Pre-Windows 2000 Compatible Access are Read types.

  If detailed permissions include any Create, Delete, Modify, or Write
  Permissions or Properties, this is a finding.

  ENTERPRISE DOMAIN CONTROLLERS - Read, Special permissions"
  tag "fix": "Limit the permissions on the Domain Controllers OU to restrict
  changes to System, Domain Admins, Enterprise Admins and Administrators.

  The default permissions listed below satisfy this requirement.

  Domains supporting Microsoft Exchange will have additional Exchange related
  permissions on the Domain Controllers OU.  These may include some change
  related permissions.

  CREATOR OWNER - Special permissions

  SELF - Special permissions

  Authenticated Users - Read, Special permissions

  The special permissions for Authenticated Users are Read types.

  SYSTEM - Full Control

  Domain Admins - Read, Write, Create all child objects, Generate resultant set
  of policy (logging), Generate resultant set of policy (planning), Special
  permissions

  Enterprise Admins - Full Control

  Key Admins - Special permissions

  Enterprise Key Admins - Special permissions 

  Administrators - Read, Write, Create all child objects, Generate resultant set
  of policy (logging), Generate resultant set of policy (planning), Special
  permissions

  Pre-Windows 2000 Compatible Access - Special permissions

  The special permissions for Pre-Windows 2000 Compatible Access are Read types.

  ENTERPRISE DOMAIN CONTROLLERS - Read, Special permissions"

  get_netbiosname = command("Get-ADDomain | Findstr NetBIOSName").stdout.strip
  loc_colon = get_netbiosname.index(':')
  netbiosname = get_netbiosname[37..-1]
  get_ou = command("Import-Module ActiveDirectory | Get-ADOrganizationalUnit -LDAPFilter '(name=*)' | Findstr DistinguishedName | Findstr Controllers").stdout.strip
  ou = get_ou[27..70]
  describe powershell("Import-Module ActiveDirectory; Get-Acl -Path 'AD:#{ou}' | Fl | Findstr All") do
    its('stdout') { should eq "Access : NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS Allow  \r\n         NT AUTHORITY\\Authenticated \Users Allow  \r\n         NT AUTHORITY\\SYSTEM Allow  \r\n         #{netbiosname}\\Domain Admins Allow  \r\n         BUILTIN\\Pre-Windows 2000 Compatible Access Allow  \r\n         BUILTIN\\Pre-Windows 2000 Compatible Access Allow  \r\n         BUILTIN\\Pre-Windows 2000 Compatible Access Allow  \r\n         BUILTIN\\Pre-Windows 2000 Compatible Access Allow  \r\n         BUILTIN\\Pre-Windows 2000 Compatible Access Allow  \r\n         BUILTIN\\Pre-Windows 2000 Compatible Access Allow  \r\n         BUILTIN\\Pre-Windows 2000 Compatible Access Allow  \r\n         BUILTIN\\Pre-Windows 2000 Compatible Access Allow  \r\n         BUILTIN\\Pre-Windows 2000 Compatible Access Allow  \r\n         BUILTIN\\Pre-Windows 2000 Compatible Access Allow  \r\n         #{netbiosname}\\Key Admins Allow  \r\n         #{netbiosname}\\Enterprise Key Admins Allow  \r\n         CREATOR OWNER Allow  \r\n         NT AUTHORITY\\SELF Allow  \r\n         NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS Allow  \r\n         NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS Allow  \r\n         NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS Allow  \r\n         NT AUTHORITY\\SELF Allow  \r\n         BUILTIN\\Pre-Windows 2000 Compatible Access Allow  \r\n         BUILTIN\\Pre-Windows 2000 Compatible Access Allow  \r\n         BUILTIN\\Pre-Windows 2000 Compatible Access Allow  \r\n         NT AUTHORITY\\SELF Allow  \r\n         NT AUTHORITY\\SELF Allow  \r\n         #{netbiosname}\\Enterprise Admins Allow  \r\n         BUILTIN\\Pre-Windows 2000 Compatible Access Allow  \r\n         BUILTIN\\Administrators Allow  \r\n"}
  end if domain_role == '4' || domain_role == '5'

  describe "System is not a domain controller, control not applicable" do
    skip "System is not a domain controller, control not applicable"
  end if domain_role != '4' && domain_role != '5'
end

