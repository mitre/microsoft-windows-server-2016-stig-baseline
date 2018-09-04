domain_role = command("wmic computersystem get domainrole | Findstr /v DomainRole").stdout.strip
control "V-73365" do
  title "The Kerberos policy user ticket renewal maximum lifetime must be
  limited to seven days or less."
  desc  "This setting determines the period of time (in days) during which a
  user's Ticket Granting Ticket (TGT) may be renewed. This security configuration
  limits the amount of time an attacker has to crack the TGT and gain access.


  "
  if domain_role == '4' || domain_role == '5'
    impact 0.5
  else
    impact 0.0
  end
  tag "gtitle": "SRG-OS-000112-GPOS-00057"
  tag "satisfies": ["SRG-OS-000112-GPOS-00057", "SRG-OS-000113-GPOS-00058"]
  tag "gid": "V-73365"
  tag "rid": "SV-88017r1_rule"
  tag "stig_id": "WN16-DC-000050"
  tag "fix_id": "F-79807r1_fix"
  tag "cci": ["CCI-001941", "CCI-001942"]
  tag "nist": ["IA-2 (8)", "Rev_4"]
  tag "nist": ["IA-2 (9)", "Rev_4"]
  tag "documentable": false
  tag "check": "This applies to domain controllers. It is NA for other systems.

  Verify the following is configured in the Default Domain Policy.

  Open \"Group Policy Management\".

  Navigate to \"Group Policy Objects\" in the Domain being reviewed (Forest >>
  Domains >> Domain).

  Right-click on the \"Default Domain Policy\".

  Select \"Edit\".

  Navigate to Computer Configuration >> Policies >> Windows Settings >> Security
  Settings >> Account Policies >> Kerberos Policy.

  If the \"Maximum lifetime for user ticket renewal\" is greater than \"7\" days,
  this is a finding."
  tag "fix": "Configure the policy value in the Default Domain Policy for
  Computer Configuration >> Policies >> Windows Settings >> Security Settings >>
  Account Policies >> Kerberos Policy >> \"Maximum lifetime for user ticket
  renewal\" to a maximum of \"7\" days or less."
  describe.one do
    describe security_policy do
      its("MaxRenewAge") { should be > 0}
    end
    describe security_policy do
      its("MaxRenewAge") { should be <= 7}
    end
  end if domain_role == '4' || domain_role == '5'

  describe "System is not a domain controller, control not applicable" do
    skip "System is not a domain controller, control not applicable"
  end if domain_role != '4' && domain_role != '5'
end

