control "V-73735" do
  title "The Act as part of the operating system user right must not be
  assigned to any groups or accounts."
  desc  "Inappropriate granting of user rights can provide system,
  administrative, and other high-level capabilities.

    Accounts with the \"Act as part of the operating system\" user right can
  assume the identity of any user and gain access to resources that the user is
  authorized to access. Any accounts with this right can take complete control of
  a system.
  "
  impact 0.7
  tag "gtitle": "SRG-OS-000324-GPOS-00125"
  tag "gid": "V-73735"
  tag "rid": "SV-88399r1_rule"
  tag "stig_id": "WN16-UR-000030"
  tag "fix_id": "F-80185r1_fix"
  tag "cci": ["CCI-002235"]
  tag "nist": ["AC-6 (10)", "Rev_4"]
  tag "documentable": false
  tag "check": "Verify the effective setting in Local Group Policy Editor.

  Run \"gpedit.msc\".

  Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
  >> Security Settings >> Local Policies >> User Rights Assignment.

  If any accounts or groups (to include administrators), are granted the \"Act as
  part of the operating system\" user right, this is a finding.

  If an application requires this user right, this would not be a finding.

  Vendor documentation must support the requirement for having the user right.

  The requirement must be documented with the ISSO.

  The application account must meet requirements for application account
  passwords, such as length (WN16-00-000060) and required frequency of changes
  (WN16-00-000070).

  Passwords for accounts with this user right must be protected as highly
  privileged accounts."
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
  \"Act as part of the operating system\" to be defined but containing no entries
  (blank)."
  describe security_policy do
    its('SeTcbPrivilege') { should eq [] }
  end
end

    
