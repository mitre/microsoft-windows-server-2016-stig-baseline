control "V-73317" do
  title "The maximum password age must be configured to 60 days or less."
  desc  "The longer a password is in use, the greater the opportunity for
  someone to gain unauthorized knowledge of the passwords. Scheduled changing of
  passwords hinders the ability of unauthorized system users to crack passwords
  and gain access to a system."
  impact 0.5
  tag "gtitle": "SRG-OS-000076-GPOS-00044"
  tag "gid": "V-73317"
  tag "rid": "SV-87969r1_rule"
  tag "stig_id": "WN16-AC-000050"
  tag "fix_id": "F-79759r1_fix"
  tag "cci": ["CCI-000199"]
  tag "nist": ["IA-5 (1) (d)", "Rev_4"]
  tag "documentable": false
  tag "check": "Verify the effective setting in Local Group Policy Editor.

  Run \"gpedit.msc\".

  Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
  >> Security Settings >> Account Policies >> Password Policy.

  If the value for the \"Maximum password age\" is greater than \"60\" days, this
  is a finding.

  If the value is set to \"0\" (never expires), this is a finding."
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Account Policies >> Password Policy >>
  \"Maximum password age\" to \"60\" days or less (excluding \"0\", which is
  unacceptable)."
  describe security_policy do
    its("MaximumPasswordAge") { should be <= 60 }
  end
  describe security_policy do
    its("MaximumPasswordAge") { should be > 0 }
  end
end

