control 'V-73393' do
  title "The Active Directory Infrastructure object must be configured with
  proper audit settings."
  desc "When inappropriate audit settings are configured for directory service
  database objects, it may be possible for a user or process to update the data
  without generating any tracking data. The impact of missing audit data is
  related to the type of object. A failure to capture audit data for objects used
  by identification, authentication, or authorization functions could degrade or
  eliminate the ability to track changes to access policy for systems or data.

      For Active Directory (AD), there are a number of critical object types in
  the domain naming context of the AD database for which auditing is essential.
  This includes the Infrastructure object. Because changes to these objects can
  significantly impact access controls or the availability of systems, the
  absence of auditing data makes it impossible to identify the source of changes
  that impact the confidentiality, integrity, and availability of data and
  systems throughout an AD domain. The lack of proper auditing can result in
  insufficient forensic evidence needed to investigate an incident and prosecute
  the intruder.
  "
  impact 0.5
  tag "gtitle": 'SRG-OS-000327-GPOS-00127'
  tag "satisfies": ['SRG-OS-000327-GPOS-00127', 'SRG-OS-000458-GPOS-00203',
                    'SRG-OS-000463-GPOS-00207', 'SRG-OS-000468-GPOS-00212']
  tag "gid": 'V-73393'
  tag "rid": 'SV-88045r1_rule'
  tag "stig_id": 'WN16-DC-000190'
  tag "fix_id": 'F-79835r1_fix'
  tag "cci": ['CCI-000172', 'CCI-002234']
  tag "nist": ['AU-12 c', 'AC-6 (9)', 'Rev_4']
  tag "documentable": false
  tag "check": "This applies to domain controllers. It is NA for other systems.

  Review the auditing configuration for Infrastructure object.

  Open Active Directory Users and Computers (available from various menus or
  run dsa.msc).

  Ensure Advanced Features is selected in the View menu.

  Select the domain being reviewed in the left pane.

  Right-click the Infrastructure object in the right pane and select
  Properties.

  Select the Security tab.

  Select the Advanced button and then the Auditing tab.

  If the audit settings on the Infrastructure object are not at least as
  inclusive as those below, this is a finding.

  Type - Fail
  Principal - Everyone
  Access - Full Control
  Inherited from - None

  The success types listed below are defaults. Where Special is listed in the
  summary screens for Access, detailed Permissions are provided for reference.
  Various Properties selections may also exist by default.

  Type - Success
  Principal - Everyone
  Access - Special
  Inherited from - None
  (Access - Special = Permissions: Write all properties, All extended rights,
  Change infrastructure master)

  Two instances with the following summary information will be listed.
  Type - Success
  Principal - Everyone
  Access - (blank)
  Inherited from - (CN of domain)"
  tag "fix": "Open Active Directory Users and Computers (available from
  various menus or run dsa.msc).

  Ensure Advanced Features is selected in the View menu.

  Select the domain being reviewed in the left pane.

  Right-click the Infrastructure object in the right pane and select
  Properties.

  Select the Security tab.

  Select the Advanced button and then the Auditing tab.

  Configure the audit settings for Infrastructure object to include the following.

  Type - Fail
  Principal - Everyone
  Access - Full Control
  Inherited from - None

  The success types listed below are defaults. Where Special is listed in the
  summary screens for Access, detailed Permissions are provided for reference.
  Various Properties selections may also exist by default.

  Type - Success
  Principal - Everyone
  Access - Special
  Inherited from - None
  (Access - Special = Permissions: Write all properties, All extended rights,
  Change infrastructure master)

  Two instances with the following summary information will be listed.

  Type - Success
  Principal - Everyone
  Access - (blank)
  Inherited from - (CN of domain)"
  domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip
  get_netbiosname = command('Get-ADDomain | Findstr NetBIOSName').stdout.strip
  netbiosname = get_netbiosname[37..-1]
  get_distinguishedname = command('Get-ADDomain | Findstr DistinguishedName').stdout.strip
  distinguishedName = get_distinguishedname[37..-1]
  ps_output = powershell("Import-Module ActiveDirectory; Get-Acl -Path AD:'CN=Infrastructure,#{distinguishedName}' | fl | Findstr All").stdout
  if domain_role == '4' || domain_role == '5'
    describe.one do
      describe "The file permissions on 'AD:'CN=Infrastructure,#{distinguishedName}'" do
        subject { ps_output }
        it { should eq "Access : NT AUTHORITY\\Authenticated Users Allow  \r\n         NT AUTHORITY\\SYSTEM Allow  \r\n         #{netbiosname}\\Domain Admins Allow  \r\n         #{netbiosname}\\Administrator Allow  \r\n         BUILTIN\\Pre-Windows 2000 Compatible Access Allow  \r\n         BUILTIN\\Pre-Windows 2000 Compatible Access Allow  \r\n         BUILTIN\\Pre-Windows 2000 Compatible Access Allow  \r\n         BUILTIN\\Pre-Windows 2000 Compatible Access Allow  \r\n         BUILTIN\\Pre-Windows 2000 Compatible Access Allow  \r\n         BUILTIN\\Pre-Windows 2000 Compatible Access Allow  \r\n         BUILTIN\\Pre-Windows 2000 Compatible Access Allow  \r\n         BUILTIN\\Pre-Windows 2000 Compatible Access Allow  \r\n         BUILTIN\\Pre-Windows 2000 Compatible Access Allow  \r\n         BUILTIN\\Pre-Windows 2000 Compatible Access Allow  \r\n         #{netbiosname}\\Administrator Allow  \r\n         #{netbiosname}\\Administrator Allow  \r\n         #{netbiosname}\\Key Admins Allow  \r\n         #{netbiosname}\\Enterprise Key Admins Allow  \r\n         CREATOR OWNER Allow  \r\n         NT AUTHORITY\\SELF Allow  \r\n         NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS Allow  \r\n         NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS Allow  \r\n         NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS Allow  \r\n         NT AUTHORITY\\SELF Allow  \r\n         #{netbiosname}\\Administrator Allow  \r\n         BUILTIN\\Pre-Windows 2000 Compatible Access Allow  \r\n         BUILTIN\\Pre-Windows 2000 Compatible Access Allow  \r\n         BUILTIN\\Pre-Windows 2000 Compatible Access Allow  \r\n         NT AUTHORITY\\SELF Allow  \r\n         NT AUTHORITY\\SELF Allow  \r\n         #{netbiosname}\\Enterprise Admins Allow  \r\n         BUILTIN\\Pre-Windows 2000 Compatible Access Allow  \r\n         BUILTIN\\Administrators Allow  \r\n" }
      end

      describe "The file permissions on 'AD:'CN=Infrastructure,#{distinguishedName}'" do
        subject { ps_output }
        it { should eq "Access : NT AUTHORITY\\Authenticated Users Allow  \r\n         NT AUTHORITY\\SYSTEM Allow  \r\n         #{netbiosname}\\Domain Admins Allow  \r\n         BUILTIN\\Pre-Windows 2000 Compatible Access Allow  \r\n         BUILTIN\\Pre-Windows 2000 Compatible Access Allow  \r\n         BUILTIN\\Pre-Windows 2000 Compatible Access Allow  \r\n         BUILTIN\\Pre-Windows 2000 Compatible Access Allow  \r\n         BUILTIN\\Pre-Windows 2000 Compatible Access Allow  \r\n         BUILTIN\\Pre-Windows 2000 Compatible Access Allow  \r\n         BUILTIN\\Pre-Windows 2000 Compatible Access Allow  \r\n         BUILTIN\\Pre-Windows 2000 Compatible Access Allow  \r\n         BUILTIN\\Pre-Windows 2000 Compatible Access Allow  \r\n         BUILTIN\\Pre-Windows 2000 Compatible Access Allow  \r\n         #{netbiosname}\\Key Admins Allow  \r\n         #{netbiosname}\\Enterprise Key Admins Allow  \r\n         CREATOR OWNER Allow  \r\n         NT AUTHORITY\\SELF Allow  \r\n         NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS Allow  \r\n         NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS Allow  \r\n         NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS Allow  \r\n         NT AUTHORITY\\SELF Allow  \r\n         BUILTIN\\Pre-Windows 2000 Compatible Access Allow  \r\n         BUILTIN\\Pre-Windows 2000 Compatible Access Allow  \r\n         BUILTIN\\Pre-Windows 2000 Compatible Access Allow  \r\n         NT AUTHORITY\\SELF Allow  \r\n         NT AUTHORITY\\SELF Allow  \r\n         #{netbiosname}\\Enterprise Admins Allow  \r\n         BUILTIN\\Pre-Windows 2000 Compatible Access Allow  \r\n         BUILTIN\\Administrators Allow  \r\n" }
      end
    end
  end

  if !(domain_role == '4') && !(domain_role == '5')
    impact 0.0
    desc 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers'
    describe 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers' do
      skip 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers'
    end
  end
end
 