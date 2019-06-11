control 'V-73589' do
  title "Automatically signing in the last interactive user after a
  system-initiated restart must be disabled."
  desc "Windows can be configured to automatically sign the user back in after
  a Windows Update restart. Some protections are in place to help ensure this is
  done in a secure fashion; however, disabling this will prevent the caching of
  credentials for this purpose and also ensure the user is aware of the restart."
  impact 0.5
  tag "gtitle": 'SRG-OS-000480-GPOS-00229'
  tag "gid": 'V-73589'
  tag "rid": 'SV-88253r1_rule'
  tag "stig_id": 'WN16-CC-000480'
  tag "fix_id": 'F-80039r1_fix'
  tag "cci": ['CCI-000366']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "documentable": false
  tag "check": "Verify the registry value below. If it does not exist or is not
  configured as specified, this is a finding.

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path:
  \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

  Value Name: DisableAutomaticRestartSignOn

  Value Type: REG_DWORD
  Value: 0x00000001 (1)"
  tag "fix": "Configure the policy value for Computer Configuration >>
  Administrative Templates >> Windows Components >> Windows Logon Options >>
  Sign-in last interactive user automatically after a system-initiated
  restart to Disabled."
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should have_property 'DisableAutomaticRestartSignOn' }
    its('DisableAutomaticRestartSignOn') { should cmp 1 }
  end
end
