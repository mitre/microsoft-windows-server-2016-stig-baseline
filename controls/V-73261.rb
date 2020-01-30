control 'V-73261' do
  title 'Accounts must require passwords.'
  desc  "The lack of password protection enables anyone to gain access to the
  information system, which opens a backdoor opportunity for intruders to
  compromise the system as well as other resources. Accounts on a system must
  require passwords."
  impact 0.5
  tag "gtitle": 'SRG-OS-000104-GPOS-00051'
  tag "gid": 'V-73261'
  tag "rid": 'SV-87913r2_rule'
  tag "stig_id": 'WN16-00-000220'
  tag "fix_id": 'F-79705r1_fix'
  tag "cci": ['CCI-000764']
  tag "nist": ['IA-2', 'Rev_4']
  tag "documentable": false
  desc "check", "Review the password required status for enabled user accounts.

  Open PowerShell.

  Domain Controllers:

  Enter Get-Aduser -Filter * -Properties Passwordnotrequired |FT Name,
  Passwordnotrequired, Enabled.

  Exclude disabled accounts (e.g., DefaultAccount, Guest) and the krbtgt account.

  If Passwordnotrequired is True or blank for any enabled user account,
  this is a finding.

  Member servers and standalone systems:

  Enter 'Get-CimInstance -Class Win32_Useraccount -Filter
  PasswordRequired=False and LocalAccount=True | FT Name, PasswordRequired,
  Disabled, LocalAccount'.

  Exclude disabled accounts (e.g., DefaultAccount, Guest).

  If any enabled user accounts are returned with a PasswordRequired status of
  False, this is a finding."
  desc "fix", "Configure all enabled accounts to require passwords.

  The password required flag can be set by entering the following on a command
  line: Net user [username] /passwordreq:yes, substituting [username] with
  the name of the user account."
  domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip
  if domain_role == '4' || domain_role == '5'
    users_with_no_password_required = command('Get-Aduser -Filter * -Properties Passwordnotrequired | Select Name, Passwordnotrequired, Enabled | Where Enabled -eq $True | Where Passwordnotrequired -eq $True | FT Name | Findstr /V \'Name --\'').stdout
  else
    users_with_no_password_required = command("Get-CimInstance -Class Win32_Useraccount -Filter 'PasswordRequired=False and LocalAccount=True and Disabled=False' | FT Name | Findstr /V 'Name --'").stdout
  end
  describe "Windows 2016 accounts configured to not require passwords" do
    subject {users_with_no_password_required}
    it { should be_empty }
  end
end 
 