control 'V-73497' do
  title 'WDigest Authentication must be disabled.'
  desc  "When the WDigest Authentication protocol is enabled, plain-text
  passwords are stored in the Local Security Authority Subsystem Service (LSASS),
  exposing them to theft. WDigest is disabled by default in Windows 10. This
  setting ensures this is enforced."
  impact 0.5
  tag "gtitle": 'SRG-OS-000095-GPOS-00049'
  tag "gid": 'V-73497'
  tag "rid": 'SV-88149r1_rule'
  tag "stig_id": 'WN16-CC-000030'
  tag "fix_id": 'F-79939r1_fix'
  tag "cci": ['CCI-000381']
  tag "nist": ['CM-7 a', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding.

  Registry Hive:  HKEY_LOCAL_MACHINE
  Registry Path:
  \\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\Wdigest\\

  Value Name:  UseLogonCredential

  Type:  REG_DWORD
  Value:  0x00000000 (0)"
  tag "fix": "Configure the policy value for Computer Configuration >>
  Administrative Templates >> MS Security Guide >> \"WDigest Authentication
  (disabling may require KB2871997)\" to \"Disabled\".

  This policy setting requires the installation of the SecGuide custom templates
  included with the STIG package. \"SecGuide.admx\" and \" SecGuide.adml\" must
  be copied to the \\Windows\\PolicyDefinitions and
  \\Windows\\PolicyDefinitions\\en-US directories respectively."
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\Wdigest') do
    it { should have_property 'UseLogonCredential' }
    its('UseLogonCredential') { should cmp 0 }
  end
end
