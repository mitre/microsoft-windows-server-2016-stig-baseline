control 'V-73583' do
  title 'Users must be prevented from changing installation options.'
  desc  "Installation options for applications are typically controlled by
  administrators. This setting prevents users from changing installation options
  that may bypass security features."
  impact 0.5
  tag "gtitle": 'SRG-OS-000362-GPOS-00149'
  tag "gid": 'V-73583'
  tag "rid": 'SV-88247r1_rule'
  tag "stig_id": 'WN16-CC-000450'
  tag "fix_id": 'F-80033r1_fix'
  tag "cci": ['CCI-001812']
  tag "nist": ['CM-11 (2)', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding.

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\

  Value Name: EnableUserControl

  Type: REG_DWORD
  Value: 0x00000000 (0)"
  tag "fix": "Configure the policy value for Computer Configuration >>
  Administrative Templates >> Windows Components >> Windows Installer >> \"Allow
  user control over installs\" to \"Disabled\"."
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Installer') do
    it { should have_property 'EnableUserControl' }
    its('EnableUserControl') { should cmp 0 }
  end
end
