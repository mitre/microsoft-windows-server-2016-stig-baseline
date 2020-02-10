control 'V-73675' do
  title 'Anonymous access to Named Pipes and Shares must be restricted.'
  desc  "Allowing anonymous access to named pipes or shares provides the
  potential for unauthorized system access. This setting restricts access to
  those defined in Network access: Named Pipes that can be accessed
  anonymously and Network access: Shares that can be accessed anonymously,
  both of which must be blank under other requirements."
  impact 0.7
  tag "gtitle": 'SRG-OS-000138-GPOS-00069'
  tag "gid": 'V-73675'
  tag "rid": 'SV-88339r1_rule'
  tag "stig_id": 'WN16-SO-000300'
  tag "fix_id": 'F-80125r1_fix'
  tag "cci": ['CCI-001090']
  tag "nist": ['SC-4', 'Rev_4']
  tag "documentable": false
  desc "check", "If the following registry value does not exist or is not
  configured as specified, this is a finding.

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters\\

  Value Name: RestrictNullSessAccess

  Value Type: REG_DWORD
  Value: 0x00000001 (1)"
  desc "fix", "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> Security Options >>
  Network access: Restrict anonymous access to Named Pipes and Shares to
  Enabled."
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters') do
    it { should have_property 'restrictnullsessaccess' }
    its('restrictnullsessaccess') { should cmp 1 }
  end
end
