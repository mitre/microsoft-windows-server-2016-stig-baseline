control 'V-73559' do
  title 'Windows SmartScreen must be enabled.'
  desc  "Windows SmartScreen helps protect systems from programs downloaded
  from the internet that may be malicious. Enabling SmartScreen will warn users
  of potentially malicious programs."
  impact 0.5
  tag "gtitle": 'SRG-OS-000095-GPOS-00049'
  tag "gid": 'V-73559'
  tag "rid": 'SV-88223r1_rule'
  tag "stig_id": 'WN16-CC-000330'
  tag "fix_id": 'F-80009r1_fix'
  tag "cci": ['CCI-000381']
  tag "nist": ['CM-7 a', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding.

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\

  Value Name: EnableSmartScreen

  Value Type: REG_DWORD
  Value: 0x00000001 (1)"
  tag "fix": "Configure the policy value for Computer Configuration >>
  Administrative Templates >> Windows Components >> File Explorer >> Configure
  Windows SmartScreen to Enabled."
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System') do
    it { should have_property 'EnableSmartScreen' }
    its('EnableSmartScreen') { should cmp 1 }
  end
end
