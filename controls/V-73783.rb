control "V-73783" do
  title "The Generate security audits user right must only be assigned to Local
Service and Network Service."
  desc  "Inappropriate granting of user rights can provide system,
administrative, and other high-level capabilities.

    The \"Generate security audits\" user right specifies users and processes
that can generate Security Log audit records, which must only be the system
service accounts defined.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000324-GPOS-00125"
  tag "gid": "V-73783"
  tag "rid": "SV-88447r1_rule"
  tag "stig_id": "WN16-UR-000210"
  tag "fix_id": "F-80233r1_fix"
  tag "cci": ["CCI-002235"]
  tag "nist": ["AC-6 (10)", "Rev_4"]
  tag "documentable": false
  tag "check": "Verify the effective setting in Local Group Policy Editor.

Run \"gpedit.msc\".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
>> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the \"Generate
security audits\" user right, this is a finding.

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
\"Generate security audits\" to include only the following accounts or groups:

- Local Service
- Network Service"
  describe security_policy do
    its('SeAuditPrivilege') { should eq ['S-1-5-19', 'S-1-5-20'] }
  end
end

