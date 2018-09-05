control "V-73781" do
  title "The Force shutdown from a remote system user right must only be
  assigned to the Administrators group."
  desc  "Inappropriate granting of user rights can provide system,
  administrative, and other high-level capabilities.

    Accounts with the \"Force shutdown from a remote system\" user right can
  remotely shut down a system, which could result in a denial of service.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000324-GPOS-00125"
  tag "gid": "V-73781"
  tag "rid": "SV-88445r1_rule"
  tag "stig_id": "WN16-UR-000200"
  tag "fix_id": "F-80231r1_fix"
  tag "cci": ["CCI-002235"]
  tag "nist": ["AC-6 (10)", "Rev_4"]
  tag "documentable": false
  tag "check": "Verify the effective setting in Local Group Policy Editor.

  Run \"gpedit.msc\".

  Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
  >> Security Settings >> Local Policies >> User Rights Assignment.

  If any accounts or groups other than the following are granted the \"Force
  shutdown from a remote system\" user right, this is a finding.

  - Administrators"
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
  \"Force shutdown from a remote system\" to include only the following accounts
  or groups:

  - Administrators"
  describe security_policy do
    its("SeRemoteShutdownPrivilege") { should eq ['S-1-5-32-544'] }
  end
end

    
