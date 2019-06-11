control 'V-73545' do
  title 'AutoPlay must be turned off for non-volume devices.'
  desc  "Allowing AutoPlay to execute may introduce malicious code to a system.
  AutoPlay begins reading from a drive as soon as media is inserted into the
  drive. As a result, the setup file of programs or music on audio media may
  start. This setting will disable AutoPlay for non-volume devices, such as Media
  Transfer Protocol (MTP) devices."
  impact 0.7
  tag "gtitle": 'SRG-OS-000368-GPOS-00154'
  tag "gid": 'V-73545'
  tag "rid": 'SV-88209r1_rule'
  tag "stig_id": 'WN16-CC-000250'
  tag "fix_id": 'F-79991r1_fix'
  tag "cci": ['CCI-001764']
  tag "nist": ['CM-7 (2)', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding.

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer\\

  Value Name: NoAutoplayfornonVolume

  Type: REG_DWORD
  Value: 0x00000001 (1)"
  tag "fix": "Configure the policy value for Computer Configuration >>
  Administrative Templates >> Windows Components >> AutoPlay Policies >>
  Disallow Autoplay for non-volume devices to Enabled."
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Explorer') do
    it { should have_property 'NoAutoplayfornonVolume' }
    its('NoAutoplayfornonVolume') { should cmp 1 }
  end
end
