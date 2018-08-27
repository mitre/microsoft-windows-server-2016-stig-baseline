control "V-73263" do
  title "Passwords must be configured to expire."
  desc  "Passwords that do not expire or are reused increase the exposure of a
  password with greater probability of being discovered or cracked."
  impact 0.5
  tag "gtitle": "SRG-OS-000076-GPOS-00044"
  tag "gid": "V-73263"
  tag "rid": "SV-87915r2_rule"
  tag "stig_id": "WN16-00-000230"
  tag "fix_id": "F-79707r1_fix"
  tag "cci": ["CCI-000199"]
  tag "nist": ["IA-5 (1) (d)", "Rev_4"]
  tag "documentable": false
  tag "check": "Review the password never expires status for enabled user
  accounts.

  Open \"PowerShell\".

  Domain Controllers:

  Enter \"Search-ADAccount -PasswordNeverExpires -UsersOnly | FT Name,
  PasswordNeverExpires, Enabled\".

  Exclude application accounts, disabled accounts (e.g., DefaultAccount, Guest)
  and the krbtgt account.

  If any enabled user accounts are returned with a \"PasswordNeverExpires\"
  status of \"True\", this is a finding.

  Member servers and standalone systems:

  Enter 'Get-CimInstance -Class Win32_Useraccount -Filter \"PasswordExpires=False
  and LocalAccount=True\" | FT Name, PasswordExpires, Disabled, LocalAccount'.

  Exclude application accounts and disabled accounts (e.g., DefaultAccount,
  Guest).

  If any enabled user accounts are returned with a \"PasswordExpires\" status of
  \"False\", this is a finding."
  tag "fix": "Configure all enabled user account passwords to expire.

  Uncheck \"Password never expires\" for all enabled user accounts in Active
  Directory Users and Computers for domain accounts and Users in Computer
  Management for member servers and standalone systems. Document any exceptions
  with the ISSO."
  describe command("Get-CimInstance -Class Win32_Useraccount -Filter 'PasswordExpires=False
  and LocalAccount=True' | FT Name, PasswordExpires, Disabled, LocalAccount | Findstr /V 'Name --'") do
    its('stdout') { should eq "" }
  end
end

