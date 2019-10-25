control 'V-73653' do
  title "The setting Microsoft network client: Digitally sign communications
  (always) must be configured to Enabled."
  desc "The server message block (SMB) protocol provides the basis for many
  network operations. Digitally signed SMB packets aid in preventing
  man-in-the-middle attacks. If this policy is enabled, the SMB client will only
  communicate with an SMB server that performs SMB packet signing.
  "
  impact 0.5
  tag "gtitle": 'SRG-OS-000423-GPOS-00187'
  tag "satisfies": ['SRG-OS-000423-GPOS-00187', 'SRG-OS-000424-GPOS-00188']
  tag "gid": 'V-73653'
  tag "rid": 'SV-88317r1_rule'
  tag "stig_id": 'WN16-SO-000190'
  tag "fix_id": 'F-80103r1_fix'
  tag "cci": ['CCI-002418', 'CCI-002421']
  tag "nist": ['SC-8', 'SC-8 (1)', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding.

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path:
  \\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\\

  Value Name: RequireSecuritySignature

  Value Type: REG_DWORD
  Value: 0x00000001 (1)"
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> Security Options >>
  Microsoft network client: Digitally sign communications (always) to
  Enabled."
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters') do
    it { should have_property 'RequireSecuritySignature' }
    its('RequireSecuritySignature') { should cmp 1 }
  end
end
