control "V-73685" do
  title "Kerberos encryption types must be configured to prevent the use of DES
  and RC4 encryption suites."
  desc  "Certain encryption types are no longer considered secure. The DES and
  RC4 encryption suites must not be used for Kerberos encryption."
  impact 0.5
  tag "gtitle": "SRG-OS-000120-GPOS-00061"
  tag "gid": "V-73685"
  tag "rid": "SV-88349r1_rule"
  tag "stig_id": "WN16-SO-000350"
  tag "fix_id": "F-80135r1_fix"
  tag "cci": ["CCI-000803"]
  tag "nist": ["IA-7", "Rev_4"]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding.

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path:
  \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters\\

  Value Name: SupportedEncryptionTypes

  Value Type: REG_DWORD
  Value: 0x7ffffff8 (2147483640)"
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> Security Options >>
  \"Network security: Configure encryption types allowed for Kerberos\" to
  \"Enabled\" with only the following selected:

  AES128_HMAC_SHA1
  AES256_HMAC_SHA1
  Future encryption types"
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters") do
    it { should have_property "SupportedEncryptionTypes" }
    its("SupportedEncryptionTypes") { should cmp == 2147483640 }
  end
end

