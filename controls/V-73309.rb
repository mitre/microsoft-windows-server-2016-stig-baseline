control "V-73309" do
  title "Windows 2016 account lockout duration must be configured to 15 minutes
  or greater."
  desc  "The account lockout feature, when enabled, prevents brute-force
  password attacks on the system. This parameter specifies the period of time
  that an account will remain locked after the specified number of failed logon
  attempts."
  impact 0.5
  tag "gtitle": "SRG-OS-000329-GPOS-00128"
  tag "gid": "V-73309"
  tag "rid": "SV-87961r2_rule"
  tag "stig_id": "WN16-AC-000010"
  tag "fix_id": "F-80983r1_fix"
  tag "cci": ["CCI-002238"]
  tag "nist": ["AC-7 b", "Rev_4"]
  tag "documentable": false
  tag "check": "Verify the effective setting in Local Group Policy Editor.
  Run \"gpedit.msc\".

  Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
  >> Security Settings >> Account Policies >> Account Lockout Policy.

  If the \"Account lockout duration\" is less than \"15\" minutes (excluding
  \"0\"), this is a finding.

  Configuring this to \"0\", requiring an administrator to unlock the account, is
  more restrictive and is not a finding."
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Account Policies >> Account Lockout Policy >>
  \"Account lockout duration\" to \"15\" minutes or greater.

  A value of \"0\" is also acceptable, requiring an administrator to unlock the
  account."
  describe security_policy do
    its("LockoutDuration") { should be >= 15 }
  end
  describe security_policy do
    its("LockoutDuration") { should be >= 0 }
  end
end

