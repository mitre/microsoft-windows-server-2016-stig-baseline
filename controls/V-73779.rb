control "V-73779" do
  title "The Enable computer and user accounts to be trusted for delegation
user right must not be assigned to any groups or accounts on member servers."
  desc  "Inappropriate granting of user rights can provide system,
administrative, and other high-level capabilities.

    The \"Enable computer and user accounts to be trusted for delegation\" user
right allows the \"Trusted for Delegation\" setting to be changed. This could
allow unauthorized users to impersonate other users.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000324-GPOS-00125"
  tag "gid": "V-73779"
  tag "rid": "SV-88443r1_rule"
  tag "stig_id": "WN16-MS-000420"
  tag "fix_id": "F-80229r1_fix"
  tag "cci": ["CCI-002235"]
  tag "nist": ["AC-6 (10)", "Rev_4"]
  tag "documentable": false
  tag "check": "This applies to member servers and standalone systems. A
separate version applies to domain controllers.

Verify the effective setting in Local Group Policy Editor.

Run \"gpedit.msc\".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
>> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups are granted the \"Enable computer and user accounts
to be trusted for delegation\" user right, this is a finding."
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
\"Enable computer and user accounts to be trusted for delegation\" to be
defined but containing no entries (blank)."
describe security_policy do
      its("SeEnableDelegationPrivilege"){ should eq [] }
  end
end
