control "V-73597" do
  title "The Windows Remote Management (WinRM) client must not use Digest
authentication."
  desc  "Digest authentication is not as strong as other options and may be
subject to man-in-the-middle attacks. Disallowing Digest authentication will
reduce this potential."
  impact 0.5
  tag "gtitle": "SRG-OS-000125-GPOS-00065"
  tag "gid": "V-73597"
  tag "rid": "SV-88261r1_rule"
  tag "stig_id": "WN16-CC-000520"
  tag "fix_id": "F-80047r1_fix"
  tag "cci": ["CCI-000877"]
  tag "nist": ["MA-4 c", "Rev_4"]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client\\

Value Name: AllowDigest

Type: REG_DWORD
Value: 0x00000000 (0)"
  tag "fix": "Configure the policy value for Computer Configuration >>
Administrative Templates >> Windows Components >> Windows Remote Management
(WinRM) >> WinRM Client >> \"Disallow Digest authentication\" to \"Enabled\"."
describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Client") do
    it { should have_property "AllowDigest" }
    its("AllowDigest") { should cmp == 0 }
  end
end

