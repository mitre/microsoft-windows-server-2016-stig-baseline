site_banner = attribute('site_banner')
is_site_banner_used = attribute('is_site_banner_used')
control 'V-73649' do
  title "The Windows dialog box title for the legal banner must be configured
  with the appropriate text."
  desc "Failure to display the logon banner prior to a logon attempt will
  negate legal proceedings resulting from unauthorized access to system resources.
  "
  impact 0.3 
  tag "gtitle": 'SRG-OS-000023-GPOS-00006'
  tag "satisfies": ['SRG-OS-000023-GPOS-00006', 'SRG-OS-000228-GPOS-00088']
  tag "gid": 'V-73649'
  tag "rid": 'SV-88313r1_rule'
  tag "stig_id": 'WN16-SO-000160'
  tag "fix_id": 'F-80099r1_fix'
  tag "cci": ['CCI-000048', 'CCI-001384', 'CCI-001385', 'CCI-001386',
              'CCI-001387', 'CCI-001388']
  tag "nist": ['AC-8 a', 'Rev_4']
  tag "nist": ['AC-8 b', 'Rev_4']
  tag "nist": ['AC-8 c 1', 'Rev_4']
  tag "nist": ['AC-8 c 2', 'Rev_4']
  tag "nist": ['AC-8 c 3', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding.

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path:
  \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

  Value Name: LegalNoticeCaption

  Value Type: REG_SZ
  Value: See message title options below

  DoD Notice and Consent Banner, US Department of Defense Warning
  Statement, or an organization-defined equivalent.

  If an organization-defined title is used, it can in no case contravene or
  modify the language of the banner text required in WN16-SO-000150.

  Automated tools may only search for the titles defined above. If an
  organization-defined title is used, a manual review will be required."
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> Security Options >>
  Interactive Logon: Message title for users attempting to log on to DoD
  Notice and Consent Banner, US Department of Defense Warning Statement, or
  an organization-defined equivalent.

  If an organization-defined title is used, it can in no case contravene or
  modify the language of the message text required in WN16-SO-000150."
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should have_property 'LegalNoticeCaption' }
  end 

  key = registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System').LegalNoticeCaption.to_s
  legal_notice_caption = attribute('LegalNoticeCaption')
  
  describe 'The required legal notice caption' do
    subject { key.scan(/[\w().;,!]/).join}
    it {should cmp legal_notice_caption.scan(/[\w().;,!]/).join }
  end

end
