control 'V-73321' do
  title "The minimum password length must be configured to #{input('minimum_password_length')} characters."
  desc  "Information systems not protected with strong password schemes
  (including passwords of minimum length) provide the opportunity for anyone to
  crack the password, thus gaining access to the system and compromising the
  device, information, or the local network."
  impact 0.5
  tag "gtitle": 'SRG-OS-000078-GPOS-00046'
  tag "gid": 'V-73321'
  tag "rid": 'SV-87973r1_rule'
  tag "stig_id": 'WN16-AC-000070'
  tag "fix_id": 'F-79763r1_fix'
  tag "cci": ['CCI-000205']
  tag "nist": ['IA-5 (1) (a)', 'Rev_4']
  tag "documentable": false
  desc "check", "Verify the effective setting in Local Group Policy Editor.

  Run gpedit.msc.

  Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
  >> Security Settings >> Account Policies >> Password Policy.

  If the value for the Minimum password length, is less than #{input('minimum_password_length')}
  characters, this is a finding."
  desc "fix", "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Account Policies >> Password Policy >>
  Minimum password length to #{input('minimum_password_length')} characters."
  describe security_policy do
    its('MinimumPasswordLength') { should be >= input('minimum_password_length')}
  end
end
