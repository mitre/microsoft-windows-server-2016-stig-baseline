control 'V-73809' do
  title 'The built-in guest account must be disabled.'
  desc  "A system faces an increased vulnerability threat if the built-in guest
  account is not disabled. This is a known account that exists on all Windows
  systems and cannot be deleted. This account is initialized during the
  installation of the operating system with no password assigned."
  impact 0.5
  tag "gtitle": 'SRG-OS-000121-GPOS-000062'
  tag "gid": 'V-73809'
  tag "rid": 'SV-88475r1_rule'
  tag "stig_id": 'WN16-SO-000010'
  tag "fix_id": 'F-80267r1_fix'
  tag "cci": ['CCI-000804']
  tag "nist": ['IA-8', 'Rev_4']
  tag "documentable": false
  tag "check": "Verify the effective setting in Local Group Policy Editor.

  Run gpedit.msc.

  Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
  >> Security Settings >> Local Policies >> Security Options.

  If the value for Accounts: Guest account status is not set to Disabled,
  this is a finding."
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> Security Options >>
  Accounts: Guest account status to Disabled."
  describe security_policy do
    its('EnableGuestAccount') { should cmp 0 }
  end
end
