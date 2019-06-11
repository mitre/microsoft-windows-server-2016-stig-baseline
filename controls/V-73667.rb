control 'V-73667' do
  title "Anonymous enumeration of Security Account Manager (SAM) accounts must
  not be allowed."
  desc  "Anonymous enumeration of SAM accounts allows anonymous logon users
  (null session connections) to list all accounts names, thus providing a list of
  potential points to attack the system."
  impact 0.7
  tag "gtitle": 'SRG-OS-000480-GPOS-00227'
  tag "gid": 'V-73667'
  tag "rid": 'SV-88331r1_rule'
  tag "stig_id": 'WN16-SO-000260'
  tag "fix_id": 'F-80117r1_fix'
  tag "cci": ['CCI-000366']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding.

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Lsa\\

  Value Name: RestrictAnonymousSAM

  Value Type: REG_DWORD
  Value: 0x00000001 (1)"
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> Security Options >>
  Network access: Do not allow anonymous enumeration of SAM accounts to
  Enabled."
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa') do
    it { should have_property 'RestrictAnonymousSAM' }
    its('RestrictAnonymousSAM') { should cmp 1 }
  end
end
