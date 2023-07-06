
control 'V-73647' do
  title "The required legal notice must be configured to display before console
  logon."
  desc  "Failure to display the logon banner prior to a logon attempt will
  negate legal proceedings resulting from unauthorized access to system resources.
  "
  impact 0.5
  tag "gtitle": 'SRG-OS-000023-GPOS-00006'
  tag "satisfies": ['SRG-OS-000023-GPOS-00006', 'SRG-OS-000024-GPOS-00007',
                    'SRG-OS-000228-GPOS-00088']
  tag "gid": 'V-73647'
  tag "rid": 'SV-88311r2_rule'
  tag "stig_id": 'WN16-SO-000150'
  tag "fix_id": 'F-80097r2_fix'
  tag "cci": ['CCI-000048', 'CCI-000050', 'CCI-001384', 'CCI-001385',
              'CCI-001386', 'CCI-001387', 'CCI-001388']
  tag "nist": ['AC-8 a', 'AC-8 b', 'AC-8 c 1', 'AC-8 c 2', 'AC-8 c 3', 'Rev_4']
  tag "documentable": false
  desc "check", "If the following registry value does not exist or is not
  configured as specified, this is a finding.

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path:
  \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

  Value Name: legal_notice_text

  Value Type: REG_SZ
  Value: See message text below

  #{input('legal_notice_text')}"

  desc "fix", "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> Security Options >>
  Interactive Logon: Message text for users attempting to log on to the
  following:

  #{input('legal_notice_text')}"

  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should have_property 'LegalNoticeText' }
  end

  key = registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System').LegalNoticeText.to_s

  k = key.gsub("\u0000", '')
  legal_notice_text = attribute('legal_notice_text')

  describe 'The required legal notice text' do
    subject { k.scan(/[\w().;,!]/).join }
    it {should cmp legal_notice_text.scan(/[\w().;,!]/).join }
  end
end
