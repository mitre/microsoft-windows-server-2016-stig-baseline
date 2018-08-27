control "V-73567" do
  title "Passwords must not be saved in the Remote Desktop Client."
  desc  "Saving passwords in the Remote Desktop Client could allow an
unauthorized user to establish a remote desktop session to another system. The
system must be configured to prevent users from saving passwords in the Remote
Desktop Client.


  "
  impact 0.5
  tag "gtitle": "SRG-OS-000373-GPOS-00157"
  tag "satisfies": ["SRG-OS-000373-GPOS-00157", "SRG-OS-000373-GPOS-00156"]
  tag "gid": "V-73567"
  tag "rid": "SV-88231r1_rule"
  tag "stig_id": "WN16-CC-000370"
  tag "fix_id": "F-80017r1_fix"
  tag "cci": ["CCI-002038"]
  tag "nist": ["IA-11", "Rev_4"]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name: DisablePasswordSaving

Type: REG_DWORD
Value: 0x00000001 (1)"
  tag "fix": "Configure the policy value for Computer Configuration >>
Administrative Templates >> Windows Components >> Remote Desktop Services >>
Remote Desktop Connection Client >> \"Do not allow passwords to be saved\" to
\"Enabled\"."
describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services") do
    it { should have_property "DisablePasswordSaving" }
    its("DisablePasswordSaving") { should cmp == 1 }
  end
end

