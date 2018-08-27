control "V-73507" do
  title "Insecure logons to an SMB server must be disabled."
  desc  "Insecure guest logons allow unauthenticated access to shared folders.
Shared resources on a system must require authentication to establish proper
access."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-73507"
  tag "rid": "SV-88159r1_rule"
  tag "stig_id": "WN16-CC-000080"
  tag "fix_id": "F-79949r1_fix"
  tag "cci": ["CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\LanmanWorkstation\\

Value Name: AllowInsecureGuestAuth

Type: REG_DWORD
Value: 0x00000000 (0)"
  tag "fix": "Configure the policy value for Computer Configuration >>
Administrative Templates >> Network >> Lanman Workstation >> \"Enable insecure
guest logons\" to \"Disabled\"."
describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\LanmanWorkstation") do
    it { should have_property "AllowInsecureGuestAuth" }
    its("AllowInsecureGuestAuth") { should cmp == 0 }
  end
end

