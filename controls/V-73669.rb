control 'V-73669' do
  title 'Anonymous enumeration of shares must not be allowed.'
  desc  "Allowing anonymous logon users (null session connections) to list all
  account names and enumerate all shared resources can provide a map of potential
  points to attack the system."
  impact 0.7
  tag "gtitle": 'SRG-OS-000138-GPOS-00069'
  tag "gid": 'V-73669'
  tag "rid": 'SV-88333r1_rule'
  tag "stig_id": 'WN16-SO-000270'
  tag "fix_id": 'F-80119r1_fix'
  tag "cci": ['CCI-001090']
  tag "nist": ['AU-10 (4) (b)', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding.

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Lsa\\

  Value Name: RestrictAnonymous

  Value Type: REG_DWORD
  Value: 0x00000001 (1)"
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> Security Options >>
  Network access: Do not allow anonymous enumeration of SAM accounts and
  shares to Enabled."
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa') do
    it { should have_property 'RestrictAnonymous' }
    its('RestrictAnonymous') { should cmp 1 }
  end
end
