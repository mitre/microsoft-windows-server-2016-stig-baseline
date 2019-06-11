control 'V-73801' do
  title "The Restore files and directories user right must only be assigned to
  the Administrators group."
  desc "Inappropriate granting of user rights can provide system,
  administrative, and other high-level capabilities.

  Accounts with the Restore files and directories user right can
  circumvent file and directory permissions and could allow access to sensitive
  data. It could also be used to overwrite more current data.
  "
  impact 0.5
  tag "gtitle": 'SRG-OS-000324-GPOS-00125'
  tag "gid": 'V-73801'
  tag "rid": 'SV-88465r1_rule'
  tag "stig_id": 'WN16-UR-000300'
  tag "fix_id": 'F-80251r1_fix'
  tag "cci": ['CCI-002235']
  tag "nist": ['AC-6 (10)', 'Rev_4']
  tag "documentable": false
  tag "check": "Verify the effective setting in Local Group Policy Editor.

  Run gpedit.msc.

  Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
  >> Security Settings >> Local Policies >> User Rights Assignment.

  If any accounts or groups other than the following are granted the Restore
  files and directories user right, this is a finding.

  - Administrators

  If an application requires this user right, this would not be a finding.

  Vendor documentation must support the requirement for having the user right.

  The requirement must be documented with the ISSO.

  The application account must meet requirements for application account
  passwords, such as length (WN16-00-000060) and required frequency of changes
  (WN16-00-000070)."
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
  Restore files and directories to include only the following accounts or
  groups:

  - Administrators"
  describe.one do
    describe security_policy do
      its('SeRestorePrivilege') { should eq ['S-1-5-32-544'] }
    end
    describe security_policy do
      its('SeRestorePrivilege') { should eq [] }
    end
  end
end
