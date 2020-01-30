control 'V-73323' do
  title 'The built-in Windows password complexity policy must be enabled.'
  desc  "The use of complex passwords increases their strength against attack.
  The built-in Windows password complexity policy requires passwords to contain
  at least three of the four types of characters (numbers, upper- and lower-case
  letters, and special characters) and prevents the inclusion of user names or
  parts of user names.
  "
  impact 0.5
  tag "gtitle": 'SRG-OS-000069-GPOS-00037'
  tag "satisfies": ['SRG-OS-000069-GPOS-00037', 'SRG-OS-000070-GPOS-00038',
                    'SRG-OS-000071-GPOS-00039', 'SRG-OS-000266-GPOS-00101']
  tag "gid": 'V-73323'
  tag "rid": 'SV-87975r1_rule'
  tag "stig_id": 'WN16-AC-000080'
  tag "fix_id": 'F-79765r1_fix'
  tag "cci": ['CCI-000192', 'CCI-000193', 'CCI-000194', 'CCI-001619']
  tag "nist": ['IA-5 (1) (a)', 'Rev_4']
  tag "documentable": false
  desc "check", "Verify the effective setting in Local Group Policy Editor.

  Run gpedit.msc.

  Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
  >> Security Settings >> Account Policies >> Password Policy.

  If the value for Password must meet complexity requirements is not set to
  Enabled, this is a finding.

  Note: If an external password filter is in use that enforces all four character
  types and requires this setting to be set to Disabled, this would not be
  considered a finding. If this setting does not affect the use of an external
  password filter, it must be enabled for fallback purposes."
  desc "fix", "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Account Policies >> Password Policy >>
  Password must meet complexity requirements to Enabled."
  describe security_policy do
    its('PasswordComplexity') { should eq 1 }
  end
end
