control 'V-73791' do
  title "The Lock pages in memory user right must not be assigned to any groups
  or accounts."
  desc "Inappropriate granting of user rights can provide system,
  administrative, and other high-level capabilities.

  The Lock pages in memory user right allows physical memory to be
  assigned to processes, which could cause performance issues or a denial of
  service.
  "
  impact 0.5
  tag "gtitle": 'SRG-OS-000324-GPOS-00125'
  tag "gid": 'V-73791'
  tag "rid": 'SV-88455r1_rule'
  tag "stig_id": 'WN16-UR-000250'
  tag "fix_id": 'F-80241r1_fix'
  tag "cci": ['CCI-002235']
  tag "nist": ['AC-6 (10)', 'Rev_4']
  tag "documentable": false
  tag "check": "Verify the effective setting in Local Group Policy Editor.

  Run gpedit.msc.

  Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
  >> Security Settings >> Local Policies >> User Rights Assignment.

  If any accounts or groups are granted the Lock pages in memory user right,
  this is a finding.

  If an application requires this user right, this would not be a finding.

  Vendor documentation must support the requirement for having the user right.

  The requirement must be documented with the ISSO.

  The application account must meet requirements for application account
  passwords, such as length (WN16-00-000060) and required frequency of changes
  (WN16-00-000070)."
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
  Lock pages in memory to be defined but containing no entries (blank)."
  describe security_policy do
    its('SeLockMemoryPrivilege') { should eq [] }
  end
end
