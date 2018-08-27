control "V-73797" do
  title "The Perform volume maintenance tasks user right must only be assigned
to the Administrators group."
  desc  "Inappropriate granting of user rights can provide system,
administrative, and other high-level capabilities.

    Accounts with the \"Perform volume maintenance tasks\" user right can
manage volume and disk configurations. This could be used to delete volumes,
resulting in data loss or a denial of service.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000324-GPOS-00125"
  tag "gid": "V-73797"
  tag "rid": "SV-88461r1_rule"
  tag "stig_id": "WN16-UR-000280"
  tag "fix_id": "F-80247r1_fix"
  tag "cci": ["CCI-002235"]
  tag "nist": ["AC-6 (10)", "Rev_4"]
  tag "documentable": false
  tag "check": "Verify the effective setting in Local Group Policy Editor.

Run \"gpedit.msc\".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
>> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the \"Perform
volume maintenance tasks\" user right, this is a finding.

- Administrators"
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
\"Perform volume maintenance tasks\" to include only the following accounts or
groups:

- Administrators"
  describe security_policy do
    its("SeManageVolumePrivilege") { should eq ['S-1-5-32-544'] }
  end
end
