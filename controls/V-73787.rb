control 'V-73787' do
  title "The Increase scheduling priority user right must only be assigned to
  the Administrators group."
  desc "Inappropriate granting of user rights can provide system,
  administrative, and other high-level capabilities.

  Accounts with the Increase scheduling priority user right can change a
  scheduling priority, causing performance issues or a denial of service.
  "
  impact 0.5
  tag "gtitle": 'SRG-OS-000324-GPOS-00125'
  tag "gid": 'V-73787'
  tag "rid": 'SV-88451r1_rule'
  tag "stig_id": 'WN16-UR-000230'
  tag "fix_id": 'F-80237r1_fix'
  tag "cci": ['CCI-002235']
  tag "nist": ['AC-6 (10)', 'Rev_4']
  tag "documentable": false
  desc "check", "Verify the effective setting in Local Group Policy Editor.

  Run gpedit.msc.

  Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
  >> Security Settings >> Local Policies >> User Rights Assignment.

  If any accounts or groups other than the following are granted the Increase
  scheduling priority user right, this is a finding.

  - Administrators

  If an application requires this user right, this would not be a finding.

  Vendor documentation must support the requirement for having the user right.

  The requirement must be documented with the ISSO.

  The application account must meet requirements for application account
  passwords, such as length (WN16-00-000060) and required frequency of changes
  (WN16-00-000070)."
  desc "fix", "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
  Increase scheduling priority to include only the following accounts or
  groups:

  - Administrators"
  describe.one do
    describe security_policy do
      its('SeIncreaseBasePriorityPrivilege') { should eq ['S-1-5-32-544'] }
    end
    describe security_policy do
      its('SeIncreaseBasePriorityPrivilege') { should eq [] }
    end
  end
end
