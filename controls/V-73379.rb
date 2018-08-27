control "V-73379" do
  title "Data files owned by users must be on a different logical partition
from the directory server data files."
  desc  "When directory service data files, especially for directories used for
identification, authentication, or authorization, reside on the same logical
partition as user-owned files, the directory service data may be more
vulnerable to unauthorized access or other availability compromises. Directory
service and user-owned data files sharing a partition may be configured with
less restrictive permissions in order to allow access to the user data.

    The directory service may be vulnerable to a denial of service attack when
user-owned files on a common partition are expanded to an extent preventing the
directory service from acquiring more space for directory or audit data.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000138-GPOS-00069"
  tag "gid": "V-73379"
  tag "rid": "SV-88031r1_rule"
  tag "stig_id": "WN16-DC-000120"
  tag "fix_id": "F-79821r1_fix"
  tag "cci": ["CCI-001090"]
  tag "nist": ["SC-4", "Rev_4"]
  tag "documentable": false
  tag "check": "This applies to domain controllers. It is NA for other systems.

Run \"Regedit\".

Navigate to
\"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters\".

Note the directory locations in the values for \"DSA Database file\".

Open \"Command Prompt\".

Enter \"net share\".

Note the logical drive(s) or file system partition for any organization-created
data shares.

Ignore system shares (e.g., NETLOGON, SYSVOL, and administrative shares ending
in $). User shares that are hidden (ending with $) should not be ignored.

If user shares are located on the same logical partition as the directory
server data files, this is a finding."
  tag "fix": "Move shares used to store files owned by users to a different
logical partition than the directory server data files."
domain_role = command("wmic computersystem get domainrole | /v DomainRole").stdout.strip
  if domain_role != '4' || domain_role != '5'
    describe 'control' do
      skip 'This computer is not a domain controller'
    end
  end
end

