control 'V-73679' do
  title "Services using Local System that use Negotiate when reverting to NTLM
  authentication must use the computer identity instead of authenticating
  anonymously."
  desc "Services using Local System that use Negotiate when reverting to NTLM
  authentication may gain unauthorized access if allowed to authenticate
  anonymously versus using the computer identity."
  impact 0.5
  tag "gtitle": 'SRG-OS-000480-GPOS-00227'
  tag "gid": 'V-73679'
  tag "rid": 'SV-88343r1_rule'
  tag "stig_id": 'WN16-SO-000320'
  tag "fix_id": 'F-80129r1_fix'
  tag "cci": ['CCI-000366']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding.

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\LSA\\

  Value Name: UseMachineId

  Type: REG_DWORD
  Value: 0x00000001 (1)"
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> Security Options >>
  Network security: Allow Local System to use computer identity for NTLM to
  Enabled."
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa') do
    it { should have_property 'UseMachineId' }
    its('UseMachineId') { should cmp 1 }
  end
end
