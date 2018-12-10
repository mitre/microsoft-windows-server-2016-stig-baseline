control 'V-73369' do
  title "Permissions on the Active Directory data files must only allow System
  and Administrators access."
  desc  "Improper access permissions for directory data-related files could
  allow unauthorized users to read, modify, or delete directory data or audit
  trails."
  impact 0.7
  tag "gtitle": 'SRG-OS-000324-GPOS-00125'
  tag "gid": 'V-73369'
  tag "rid": 'SV-88021r1_rule'
  tag "stig_id": 'WN16-DC-000070'
  tag "fix_id": 'F-79811r1_fix'
  tag "cci": ['CCI-002235']
  tag "nist": ['AC-6 (10)', 'Rev_4']
  tag "documentable": false
  tag "check": "This applies to domain controllers. It is NA for other systems.

  Run \"Regedit\".

  Navigate to
  \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters\".

  Note the directory locations in the values for:

  Database log files path
  DSA Database file

  By default, they will be \\Windows\\NTDS.

  If the locations are different, the following will need to be run for each.

  Open \"Command Prompt (Admin)\".

  Navigate to the NTDS directory (\\Windows\\NTDS by default).

  Run \"icacls *.*\".

  If the permissions on each file are not as restrictive as the following, this
  is a finding.

  NT AUTHORITY\\SYSTEM:(I)(F)
  BUILTIN\\Administrators:(I)(F)

  (I) - permission inherited from parent container
  (F) - full access"
  tag "fix": "Maintain the permissions on NTDS database and log files as
  follows:

  NT AUTHORITY\\SYSTEM:(I)(F)
  BUILTIN\\Administrators:(I)(F)

  (I) - permission inherited from parent container
  (F) - full access"
  domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip

  describe.one do
    describe command("Get-Acl -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters' | Format-List | Findstr All") do
      its('stdout') { should eq "Access : CREATOR OWNER Allow  268435456\r\n         NT AUTHORITY\\SYSTEM Allow  268435456\r\n         NT AUTHORITY\\SYSTEM Allow  FullControl\r\n         BUILTIN\\Administrators Allow  268435456\r\n         BUILTIN\\Administrators Allow  FullControl\r\n         BUILTIN\\Server Operators Allow  -2147483648\r\n         BUILTIN\\Server Operators Allow  ReadKey\r\n" }
    end

    describe command("Get-Acl -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters' | Format-List | Findstr All") do
      its('stdout') { should eq "Access : CREATOR OWNER Allow  268435456\r\n         NT AUTHORITY\\SYSTEM Allow  FullControl\r\n         BUILTIN\\Administrators Allow  FullControl\r\n         BUILTIN\\Administrators Allow  268435456\r\n         BUILTIN\\Server Operators Allow  ReadKey\r\n         BUILTIN\\Server Operators Allow  -2147483648\r\n" }
    end
  end if [4, 5].include? domain_role

  if ![4, 5].include? domain_role
    impact 0.0
    desc 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers'
    describe 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers' do
      skip 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers'
    end
  end
end
