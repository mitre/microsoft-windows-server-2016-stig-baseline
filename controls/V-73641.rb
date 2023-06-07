control 'V-73641' do
  title "The maximum age for machine account passwords must be configured to #{input('maximum_password_age_machine')}
  days or less."
  desc "Computer account passwords are changed automatically on a regular
  basis. This setting controls the maximum password age that a machine account
  may have. This must be set to no more than #{input('maximum_password_age_machine')} days, ensuring the machine
  changes its password #{input('maximum_password_age_machine')} days."
  impact 0.5
  tag "gtitle": 'SRG-OS-000480-GPOS-00227'
  tag "gid": 'V-73641'
  tag "rid": 'SV-88305r1_rule'
  tag "stig_id": 'WN16-SO-000120'
  tag "fix_id": 'F-80091r1_fix'
  tag "cci": ['CCI-000366']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "documentable": false
  desc "check", "This is the default configuration for this setting (#{input('maximum_password_age_machine')} days).

  If the following registry value does not exist or is not configured as
  specified, this is a finding.

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters\\

  Value Name: MaximumPasswordAge

  Value Type: REG_DWORD
  Value: 0x0000001e (#{input('maximum_password_age_machine')}) (or less, but not 0)"
  desc "fix", "This is the default configuration for this setting (#{input('maximum_password_age_machine')} days).

  Configure the policy value for Computer Configuration >> Windows Settings >>
  Security Settings >> Local Policies >> Security Options >> Domain member:
  Maximum machine account password age to #{input('maximum_password_age_machine')} or less (excluding 0,
  which is unacceptable)."
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters') do
    it { should have_property 'MaximumPasswordAge' }
    its('MaximumPasswordAge') { should be <= input('maximum_password_age_machine') }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters') do
    it { should have_property 'MaximumPasswordAge' }
    its('MaximumPasswordAge') { should be > 0 }
  end
end
