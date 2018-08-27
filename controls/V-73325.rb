control "V-73325" do
  title "Reversible password encryption must be disabled."
  desc  "Storing passwords using reversible encryption is essentially the same
  as storing clear-text versions of the passwords, which are easily compromised.
  For this reason, this policy must never be enabled."
  impact 0.7
  tag "gtitle": "SRG-OS-000073-GPOS-00041"
  tag "gid": "V-73325"
  tag "rid": "SV-87977r1_rule"
  tag "stig_id": "WN16-AC-000090"
  tag "fix_id": "F-79767r1_fix"
  tag "cci": ["CCI-000196"]
  tag "nist": ["IA-5 (1) (c)", "Rev_4"]
  tag "documentable": false
  tag "check": "Verify the effective setting in Local Group Policy Editor.

  Run \"gpedit.msc\".

  Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
  >> Security Settings >> Account Policies >> Password Policy.

  If the value for \"Store passwords using reversible encryption\" is not set to
  \"Disabled\", this is a finding."
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Account Policies >> Password Policy >> \"Store
  passwords using reversible encryption\" to \"Disabled\"."
  describe security_policy do
    its("ClearTextPassword") { should eq 0 }
  end
end

