control 'V-73319' do
  title 'The minimum password age must be configured to at least one day.'
  desc  "Permitting passwords to be changed in immediate succession within the
  same day allows users to cycle passwords through their history database. This
  enables users to effectively negate the purpose of mandating periodic password
  changes."
  impact 0.5
  tag "gtitle": 'SRG-OS-000075-GPOS-00043'
  tag "gid": 'V-73319'
  tag "rid": 'SV-87971r1_rule'
  tag "stig_id": 'WN16-AC-000060'
  tag "fix_id": 'F-79761r1_fix'
  tag "cci": ['CCI-000198']
  tag "nist": ['IA-5 (1) (d)', 'Rev_4']
  tag "documentable": false
  tag "check": "Verify the effective setting in Local Group Policy Editor.

  Run \"gpedit.msc\".

  Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
  >> Security Settings >> Account Policies >> Password Policy.

  If the value for the \"Minimum password age\" is set to \"0\" days (\"Password
  can be changed immediately\"), this is a finding."
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Account Policies >> Password Policy >>
  \"Minimum password age\" to at least \"1\" day."
  describe security_policy do
    its('MinimumPasswordAge') { should be >= 1 }
  end
end
