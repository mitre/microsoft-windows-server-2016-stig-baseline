control 'V-73655' do
  title "The setting Microsoft network client: Digitally sign communications
  (if server agrees) must be configured to Enabled."
  desc "The server message block (SMB) protocol provides the basis for many
  network operations. If this policy is enabled, the SMB client will request
  packet signing when communicating with an SMB server that is enabled or
  required to perform SMB packet signing.
  "
  impact 0.5
  tag "gtitle": 'SRG-OS-000423-GPOS-00187'
  tag "satisfies": ['SRG-OS-000423-GPOS-00187', 'SRG-OS-000424-GPOS-00188']
  tag "gid": 'V-73655'
  tag "rid": 'SV-88319r1_rule'
  tag "stig_id": 'WN16-SO-000200'
  tag "fix_id": 'F-80105r1_fix'
  tag "cci": ['CCI-002418', 'CCI-002421']
  tag "nist": ['SC-8', 'Rev_4']
  tag "nist": ['SC-8 (1)', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding.

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path:
  \\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\\

  Value Name: EnableSecuritySignature

  Value Type: REG_DWORD
  Value: 0x00000001 (1)"
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> Security Options >>
  Microsoft network client: Digitally sign communications (if server agrees)
  to Enabled."
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters') do
    it { should have_property 'EnableSecuritySignature' }
    its('EnableSecuritySignature') { should cmp 1 }
  end
end
