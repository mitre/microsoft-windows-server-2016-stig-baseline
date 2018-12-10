control 'V-73531' do
  title "The network selection user interface (UI) must not be displayed on the
  logon screen."
  desc  "Enabling interaction with the network selection UI allows users to
  change connections to available networks without signing in to Windows."
  impact 0.5
  tag "gtitle": 'SRG-OS-000095-GPOS-00049'
  tag "gid": 'V-73531'
  tag "rid": 'SV-88185r1_rule'
  tag "stig_id": 'WN16-CC-000180'
  tag "fix_id": 'F-79973r1_fix'
  tag "cci": ['CCI-000381']
  tag "nist": ['CM-7 a', 'Rev_4']
  tag "documentable": false
  tag "check": "Verify the registry value below. If it does not exist or is not
  configured as specified, this is a finding.

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\

  Value Name: DontDisplayNetworkSelectionUI

  Value Type: REG_DWORD
  Value: 0x00000001 (1)"
  tag "fix": "Configure the policy value for Computer Configuration >>
  Administrative Templates >> System >> Logon >> \"Do not display network
  selection UI\" to \"Enabled\"."
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System') do
    it { should have_property 'DontDisplayNetworkSelectionUI' }
    its('DontDisplayNetworkSelectionUI') { should cmp 1 }
  end
end
