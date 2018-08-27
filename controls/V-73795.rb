control "V-73795" do
  title "The Modify firmware environment values user right must only be
assigned to the Administrators group."
  desc  "Inappropriate granting of user rights can provide system,
administrative, and other high-level capabilities.

    Accounts with the \"Modify firmware environment values\" user right can
change hardware configuration environment variables. This could result in
hardware failures or a denial of service.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000324-GPOS-00125"
  tag "gid": "V-73795"
  tag "rid": "SV-88459r1_rule"
  tag "stig_id": "WN16-UR-000270"
  tag "fix_id": "F-80245r1_fix"
  tag "cci": ["CCI-002235"]
  tag "nist": ["AC-6 (10)", "Rev_4"]]
  tag "documentable": false
  tag "check": "Verify the effective setting in Local Group Policy Editor.

Run \"gpedit.msc\".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
>> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the \"Modify
firmware environment values\" user right, this is a finding.

- Administrators"
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
\"Modify firmware environment values\" to include only the following accounts
or groups:

- Administrators"
  describe security_policy do
    its("SeSystemEnvironmentPrivilege") { should eq ['S-1-5-32-544'] }
  end
end
