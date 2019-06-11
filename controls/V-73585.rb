control 'V-73585' do
  title "The Windows Installer Always install with elevated privileges option
  must be disabled."
  desc "Standard user accounts must not be granted elevated privileges.
  Enabling Windows Installer to elevate privileges when installing applications
  can allow malicious persons and applications to gain full control of a system."
  impact 0.7
  tag "gtitle": 'SRG-OS-000362-GPOS-00149'
  tag "gid": 'V-73585'
  tag "rid": 'SV-88249r1_rule'
  tag "stig_id": 'WN16-CC-000460'
  tag "fix_id": 'F-80035r1_fix'
  tag "cci": ['CCI-001812']
  tag "nist": ['CM-11 (2)', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding.

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\

  Value Name: AlwaysInstallElevated

  Type: REG_DWORD
  Value: 0x00000000 (0)"
  tag "fix": "Configure the policy value for Computer Configuration >>
  Administrative Templates >> Windows Components >> Windows Installer >> Always
  install with elevated privileges to Disabled."
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Installer') do
    it { should have_property 'AlwaysInstallElevated' }
    its('AlwaysInstallElevated') { should cmp 0 }
  end
end
