control 'V-73689' do
  title "Windows Server 2016 must be configured to force users to log off when
  their allowed logon hours expire."
  desc  "Limiting logon hours can help protect data by allowing access only
  during specified times. This setting controls whether users are forced to log
  off when their allowed logon hours expire. If logon hours are set for users,
  this must be enforced."
  impact 0.5
  tag "gtitle": 'SRG-OS-000163-GPOS-00072'
  tag "gid": 'V-73689'
  tag "rid": 'SV-88353r1_rule'
  tag "stig_id": 'WN16-SO-000370'
  tag "fix_id": 'F-80139r1_fix'
  tag "cci": ['CCI-001133']
  tag "nist": ['SC-10', 'Rev_4']
  tag "documentable": false
  tag "check": "Verify the effective setting in Local Group Policy Editor.

  Run \"gpedit.msc\".

  Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
  >> Security Settings >> Local Policies >> Security Options.

  If the value for \"Network security: Force logoff when logon hours expire\" is
  not set to \"Enabled\", this is a finding."
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> Security Options >>
  \"Network security: Force logoff when logon hours expire\" to \"Enabled\"."
  describe security_policy do
    its('ForceLogoffWhenHourExpire') { should eq 1 }
  end
end
