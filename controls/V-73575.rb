control "V-73575" do
  title "Remote Desktop Services must be configured with the client connection
encryption set to High Level."
  desc  "Remote connections must be encrypted to prevent interception of data
or sensitive information. Selecting \"High Level\" will ensure encryption of
Remote Desktop Services sessions in both directions."
  impact 0.5
  tag "gtitle": "SRG-OS-000250-GPOS-00093"
  tag "gid": "V-73575"
  tag "rid": "SV-88239r1_rule"
  tag "stig_id": "WN16-CC-000410"
  tag "fix_id": "F-80025r1_fix"
  tag "cci": ["CCI-001453"]
  tag "nist": ["AC-17 (2)", "Rev_4"]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name: MinEncryptionLevel

Type: REG_DWORD
Value: 0x00000003 (3)"
  tag "fix": "Configure the policy value for Computer Configuration >>
Administrative Templates >> Windows Components >> Remote Desktop Services >>
Remote Desktop Session Host >> Security >> \"Set client connection encryption
level\" to \"Enabled\" with \"High Level\" selected."
describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services") do
    it { should have_property "MinEncryptionLevel" }
    its("MinEncryptionLevel") { should cmp == 3 }
  end
end

