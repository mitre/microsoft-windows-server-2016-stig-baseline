control 'V-73563' do
  title "Turning off File Explorer heap termination on corruption must be
  disabled."
  desc "Legacy plug-in applications may continue to function when a File
  Explorer session has become corrupt. Disabling this feature will prevent this."
  impact 0.3
  tag "gtitle": 'SRG-OS-000480-GPOS-00227'
  tag "gid": 'V-73563'
  tag "rid": 'SV-88227r1_rule'
  tag "stig_id": 'WN16-CC-000350'
  tag "fix_id": 'F-80013r1_fix'
  tag "cci": ['CCI-000366']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "documentable": false
  desc "check", "The default behavior is for File Explorer heap termination on
  corruption to be enabled.

  If the registry Value Name below does not exist, this is not a finding.

  If it exists and is configured with a value of 0, this is not a finding.

  If it exists and is configured with a value of 1, this is a finding.

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer\\

  Value Name: NoHeapTerminationOnCorruption

  Value Type: REG_DWORD
  Value: 0x00000000 (0) (or if the Value Name does not exist)"
  desc "fix", "The default behavior is for File Explorer heap termination on
  corruption to be disabled.

  If this needs to be corrected, configure the policy value for Computer
  Configuration >> Administrative Templates >> Windows Components >> File
  Explorer >> Turn off heap termination on corruption to Not Configured
  or Disabled."
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Explorer') do
    it { should have_property 'NoHeapTerminationOnCorruption' }
    its('NoHeapTerminationOnCorruption') { should_not cmp 1 }
  end
end
