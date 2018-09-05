control "V-73753" do
  title "The Create symbolic links user right must only be assigned to the
  Administrators group."
  desc  "Inappropriate granting of user rights can provide system,
  administrative, and other high-level capabilities.

    Accounts with the \"Create symbolic links\" user right can create pointers
  to other objects, which could expose the system to attack.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000324-GPOS-00125"
  tag "gid": "V-73753"
  tag "rid": "SV-88417r1_rule"
  tag "stig_id": "WN16-UR-000120"
  tag "fix_id": "F-80203r1_fix"
  tag "cci": ["CCI-002235"]
  tag "nist": ["AC-6 (10)", "Rev_4"]
  tag "documentable": false
  tag "check": "Verify the effective setting in Local Group Policy Editor.

  Run \"gpedit.msc\".

  Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
  >> Security Settings >> Local Policies >> User Rights Assignment.

  If any accounts or groups other than the following are granted the \"Create
  symbolic links\" user right, this is a finding.

  - Administrators

  Systems that have the Hyper-V role will also have \"Virtual Machines\" given
  this user right (this may be displayed as \"NT Virtual Machine\\Virtual
  Machines\"). This is not a finding."
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
  \"Create symbolic links\" to include only the following accounts or groups:

  - Administrators

  Systems that have the Hyper-V role will also have \"Virtual Machines\" given
  this user right. If this needs to be added manually, enter it as \"NT Virtual
  Machine\\Virtual Machines\"."
  describe security_policy do
    its("SeCreateSymbolicLinkPrivilege") { should eq ['S-1-5-32-544'] }
  end
end

     
