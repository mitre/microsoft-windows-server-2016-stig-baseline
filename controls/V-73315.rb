control 'V-73315' do
  title 'The password history must be configured to 24 passwords remembered.'
  desc  "A system is more vulnerable to unauthorized access when system users
  recycle the same password several times without being required to change to a
  unique password on a regularly scheduled basis. This enables users to
  effectively negate the purpose of mandating periodic password changes. The
  default value is 24 for Windows domain systems. DoD has decided this is the
  appropriate value for all Windows systems."
  impact 0.5
  tag "gtitle": 'SRG-OS-000077-GPOS-00045'
  tag "gid": 'V-73315'
  tag "rid": 'SV-87967r1_rule'
  tag "stig_id": 'WN16-AC-000040'
  tag "fix_id": 'F-79757r1_fix'
  tag "cci": ['CCI-000200']
  tag "nist": ['AC-4 (12)', 'Rev_4']
  tag "documentable": false
  tag "check": "Verify the effective setting in Local Group Policy Editor.

  Run gpedit.msc.

  Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
  >> Security Settings >> Account Policies >> Password Policy.

  If the value for Enforce password history is less than 24 passwords
  remembered, this is a finding."
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Account Policies >> Password Policy >>
  Enforce password history to 24 passwords remembered."
  describe security_policy do
    its('PasswordHistorySize') { should cmp >= 24 }
  end
end
