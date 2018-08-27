control "V-73311" do
  title "The number of allowed bad logon attempts must be configured to three
  or less."
  desc  "The account lockout feature, when enabled, prevents brute-force
  password attacks on the system. The higher this value is, the less effective
  the account lockout feature will be in protecting the local system. The number
  of bad logon attempts must be reasonably small to minimize the possibility of a
  successful password attack while allowing for honest errors made during normal
  user logon."
  impact 0.5
  tag "gtitle": "SRG-OS-000021-GPOS-00005"
  tag "gid": "V-73311"
  tag "rid": "SV-87963r1_rule"
  tag "stig_id": "WN16-AC-000020"
  tag "fix_id": "F-79753r1_fix"
  tag "cci": ["CCI-000044"]
  tag "nist": ["AC-7 a", "Rev_4"]
  tag "documentable": false
  tag "check": "Verify the effective setting in Local Group Policy Editor.

  Run \"gpedit.msc\".

  Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
  >> Security Settings >> Account Policies >> Account Lockout Policy.

  If the \"Account lockout threshold\" is \"0\" or more than \"3\" attempts, this
  is a finding."
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Account Policies >> Account Lockout Policy >>
  \"Account lockout threshold\" to \"3\" or fewer invalid logon attempts
  (excluding \"0\", which is unacceptable)."
  describe security_policy do
    its("LockoutBadCount") { should be <= 3 }
  end
  describe security_policy do
    its("LockoutBadCount") { should be > 0 }
  end
end

