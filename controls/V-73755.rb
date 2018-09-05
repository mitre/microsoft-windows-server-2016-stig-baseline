control "V-73755" do
  title "The Debug programs user right must only be assigned to the
  Administrators group."
  desc  "Inappropriate granting of user rights can provide system,
  administrative, and other high-level capabilities.

    Accounts with the \"Debug programs\" user right can attach a debugger to
  any process or to the kernel, providing complete access to sensitive and
  critical operating system components. This right is given to Administrators in
  the default configuration.
  "
  impact 0.7
  tag "gtitle": "SRG-OS-000324-GPOS-00125"
  tag "gid": "V-73755"
  tag "rid": "SV-88419r1_rule"
  tag "stig_id": "WN16-UR-000130"
  tag "fix_id": "F-80205r1_fix"
  tag "cci": ["CCI-002235"]
  tag "nist": ["AC-6 (10)", "Rev_4"]
  tag "documentable": false
  tag "check": "Verify the effective setting in Local Group Policy Editor.

  Run \"gpedit.msc\".

  Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
  >> Security Settings >> Local Policies >> User Rights Assignment.

  If any accounts or groups other than the following are granted the \"Debug
  programs\" user right, this is a finding.

  - Administrators

  If an application requires this user right, this would not be a finding.

  Vendor documentation must support the requirement for having the user right.

  The requirement must be documented with the ISSO.

  The application account must meet requirements for application account
  passwords, such as length (WN16-00-000060) and required frequency of changes
  (WN16-00-000070).

  Passwords for application accounts with this user right must be protected as
  highly privileged accounts."
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
  \"Debug programs\" to include only the following accounts or groups:

  - Administrators"
  describe security_policy do
    its("SeDebugPrivilege") { should eq ['S-1-5-32-544'] }
  end
end
     

