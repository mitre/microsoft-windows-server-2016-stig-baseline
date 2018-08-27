control "V-73673" do
  title "Windows Server 2016 must be configured to prevent anonymous users from
having the same permissions as the Everyone group."
  desc  "Access by anonymous users must be restricted. If this setting is
enabled, anonymous users have the same rights and permissions as the built-in
Everyone group. Anonymous users must not have these permissions or rights."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-73673"
  tag "rid": "SV-88337r1_rule"
  tag "stig_id": "WN16-SO-000290"
  tag "fix_id": "F-80123r1_fix"
  tag "cci": ["CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Lsa\\

Value Name: EveryoneIncludesAnonymous

Value Type: REG_DWORD
Value: 0x00000000 (0)"
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
Settings >> Security Settings >> Local Policies >> Security Options >>
\"Network access: Let everyone permissions apply to anonymous users\" to
\"Disabled\"."
describe registry_key("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa") do
    it { should have_property "EveryoneIncludesAnonymous" }
    its("EveryoneIncludesAnonymous") { should cmp == 0 }
  end
end

