control 'V-73645' do
  title "The machine inactivity limit must be set to 15 minutes, locking the
  system with the screen saver."
  desc "Unattended systems are susceptible to unauthorized use and should be
  locked when unattended. The screen saver should be set at a maximum of 15
  minutes and be password protected. This protects critical and sensitive data
  from exposure to unauthorized personnel with physical access to the computer."
  impact 0.5
  tag "gtitle": 'SRG-OS-000029-GPOS-00010'
  tag "gid": 'V-73645'
  tag "rid": 'SV-88309r1_rule'
  tag "stig_id": 'WN16-SO-000140'
  tag "fix_id": 'F-80095r1_fix'
  tag "cci": ['CCI-000057']
  tag "nist": ['AC-11 a', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding.

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path:
  \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

  Value Name: InactivityTimeoutSecs

  Value Type: REG_DWORD
  Value: 0x00000384 (900) (or less)"
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> Security Options >>
  \"Interactive logon: Machine inactivity limit\" to \"900\" seconds or less."
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should have_property 'InactivityTimeoutSecs' }
    its('InactivityTimeoutSecs') { should be <= 900 }
  end
end
