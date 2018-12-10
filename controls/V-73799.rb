control 'V-73799' do
  title "The Profile single process user right must only be assigned to the
  Administrators group."
  desc "Inappropriate granting of user rights can provide system,
  administrative, and other high-level capabilities.

  Accounts with the \"Profile single process\" user right can monitor
  non-system processes performance. An attacker could use this to identify
  processes to attack.
  "
  impact 0.5
  tag "gtitle": 'SRG-OS-000324-GPOS-00125'
  tag "gid": 'V-73799'
  tag "rid": 'SV-88463r1_rule'
  tag "stig_id": 'WN16-UR-000290'
  tag "fix_id": 'F-80249r1_fix'
  tag "cci": ['CCI-002235']
  tag "nist": ['AC-6 (10)', 'Rev_4']
  tag "documentable": false
  tag "check": "Verify the effective setting in Local Group Policy Editor.

  Run \"gpedit.msc\".

  Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
  >> Security Settings >> Local Policies >> User Rights Assignment.

  If any accounts or groups other than the following are granted the \"Profile
  single process\" user right, this is a finding.

  - Administrators"
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
  \"Profile single process\" to include only the following accounts or groups:

  - Administrators"
  describe.one do
    describe security_policy do
      its('SeProfileSingleProcessPrivilege') { should eq ['S-1-5-32-544'] }
    end
    describe security_policy do
      its('SeProfileSingleProcessPrivilege') { should eq [] }
    end
  end
end
