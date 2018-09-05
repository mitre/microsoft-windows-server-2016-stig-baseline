control "V-73739" do
  title "The Allow log on locally user right must only be assigned to the
  Administrators group."
  desc  "Inappropriate granting of user rights can provide system,
  administrative, and other high-level capabilities.

    Accounts with the \"Allow log on locally\" user right can log on
  interactively to a system.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000080-GPOS-00048"
  tag "gid": "V-73739"
  tag "rid": "SV-88403r1_rule"
  tag "stig_id": "WN16-UR-000050"
  tag "fix_id": "F-80189r1_fix"
  tag "cci": ["CCI-000213"]
  tag "nist": ["AC-3", "Rev_4"]
  tag "documentable": false
  tag "check": "Verify the effective setting in Local Group Policy Editor.

  Run \"gpedit.msc\".

  Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
  >> Security Settings >> Local Policies >> User Rights Assignment.

  If any accounts or groups other than the following are granted the \"Allow log
  on locally\" user right, this is a finding.

  - Administrators

  If an application requires this user right, this would not be a finding.

  Vendor documentation must support the requirement for having the user right.

  The requirement must be documented with the ISSO.

  The application account must meet requirements for application account
  passwords, such as length (WN16-00-000060) and required frequency of changes
  (WN16-00-000070)."
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
  \"Allow log on locally\" to include only the following accounts or groups:

  - Administrators"
  describe security_policy do
    its("SeInteractiveLogonRight") { should eq ['S-1-5-32-544'] }
  end
end
     
