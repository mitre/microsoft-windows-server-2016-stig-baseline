control "V-73581" do
  title "Indexing of encrypted files must be turned off."
  desc  "Indexing of encrypted files may expose sensitive data. This setting
prevents encrypted files from being indexed."
  impact 0.5
  tag "gtitle": "SRG-OS-000095-GPOS-00049"
  tag "gid": "V-73581"
  tag "rid": "SV-88245r1_rule"
  tag "stig_id": "WN16-CC-000440"
  tag "fix_id": "F-80031r1_fix"
  tag "cci": ["CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search\\

Value Name: AllowIndexingEncryptedStoresOrItems

Value Type: REG_DWORD
Value: 0x00000000 (0)"
  tag "fix": "Configure the policy value for Computer Configuration >>
Administrative Templates >> Windows Components >> Search >> \"Allow indexing of
encrypted files\" to \"Disabled\"."
describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search") do
    it { should have_property "AllowIndexingEncryptedStoresOrItems" }
    its("AllowIndexingEncryptedStoresOrItems") { should cmp == 0 }
  end
end

