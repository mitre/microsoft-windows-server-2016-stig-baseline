control "V-73749" do
  title "The Create global objects user right must only be assigned to
  Administrators, Service, Local Service, and Network Service."
  desc  "Inappropriate granting of user rights can provide system,
  administrative, and other high-level capabilities.

    Accounts with the \"Create global objects\" user right can create objects
  that are available to all sessions, which could affect processes in other
  users' sessions.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000324-GPOS-00125"
  tag "gid": "V-73749"
  tag "rid": "SV-88413r1_rule"
  tag "stig_id": "WN16-UR-000100"
  tag "fix_id": "F-80199r1_fix"
  tag "cci": ["CCI-002235"]
  tag "nist": ["AC-6 (10)", "Rev_4"]
  tag "documentable": false
  tag "check": "Verify the effective setting in Local Group Policy Editor.

  Run \"gpedit.msc\".

  Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
  >> Security Settings >> Local Policies >> User Rights Assignment.

  If any accounts or groups other than the following are granted the \"Create
  global objects\" user right, this is a finding.

  - Administrators
  - Service
  - Local Service
  - Network Service

  If an application requires this user right, this would not be a finding.

  Vendor documentation must support the requirement for having the user right.

  The requirement must be documented with the ISSO.

  The application account must meet requirements for application account
  passwords, such as length (WN16-00-000060) and required frequency of changes
  (WN16-00-000070)."
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
  \"Create global objects\" to include only the following accounts or groups:

  - Administrators
  - Service
  - Local Service
  - Network Service"
  describe security_policy do
    its('SeCreateGlobalPrivilege') { should eq ['S-1-5-19', 'S-1-5-20', 'S-1-5-32-544', 'S-1-5-6'] }
  ends
end

