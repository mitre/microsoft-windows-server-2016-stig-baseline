control 'V-73525' do
  title "Group Policy objects must be reprocessed even if they have not
  changed."
  desc "Registry entries for group policy settings can potentially be changed
  from the required configuration. This could occur as part of troubleshooting or
  by a malicious process on a compromised system. Enabling this setting and then
  selecting the \"Process even if the Group Policy objects have not changed\"
  option ensures the policies will be reprocessed even if none have been changed.
  This way, any unauthorized changes are forced to match the domain-based group
  policy settings again."
  impact 0.5
  tag "gtitle": 'SRG-OS-000480-GPOS-00227'
  tag "gid": 'V-73525'
  tag "rid": 'SV-88177r1_rule'
  tag "stig_id": 'WN16-CC-000150'
  tag "fix_id": 'F-79965r1_fix'
  tag "cci": ['CCI-000366']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding.

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Group
  Policy\\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\\

  Value Name: NoGPOListChanges

  Type: REG_DWORD
  Value: 0x00000000 (0)"
  tag "fix": "Configure the policy value for Computer Configuration >>
  Administrative Templates >> System >> Group Policy >> \"Configure registry
  policy processing\" to \"Enabled\" with the option \"Process even if the Group
  Policy objects have not changed\" selected."
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Group Policy\\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}') do
    it { should have_property 'NoGPOListChanges' }
    its('NoGPOListChanges') { should cmp 0 }
  end
end
