control 'V-73283' do
  title "Windows Server 2016 must automatically remove or disable temporary
  user accounts after 72 hours."
  desc "If temporary user accounts remain active when no longer needed or for
  an excessive period, these accounts may be used to gain unauthorized access. To
  mitigate this risk, automated termination of all temporary accounts must be set
  upon account creation.

  Temporary accounts are established as part of normal account activation
  procedures when there is a need for short-term accounts without the demand for
  immediacy in account activation.

  If temporary accounts are used, the operating system must be configured to
  automatically terminate these types of accounts after a DoD-defined time period
  of 72 hours.

  To address access requirements, many operating systems may be integrated
  with enterprise-level authentication/access mechanisms that meet or exceed
  access control policy requirements.
  "
  impact 0.5
  tag "gtitle": 'SRG-OS-000002-GPOS-00002'
  tag "gid": 'V-73283'
  tag "rid": 'SV-87935r1_rule'
  tag "stig_id": 'WN16-00-000330'
  tag "fix_id": 'F-79727r1_fix'
  tag "cci": ['CCI-000016']
  tag "nist": ['AC-2 (2)', 'Rev_4']
  tag "documentable": false
  desc "check", "Review temporary user accounts for expiration dates.

  Determine if temporary user accounts are used and identify any that exist. If
  none exist, this is NA.

  Domain Controllers:

  Open PowerShell.

  Enter Search-ADAccount -AccountExpiring | FT Name, AccountExpirationDate.

  If AccountExpirationDate has not been defined within 72 hours for any
  temporary user account, this is a finding.

  Member servers and standalone systems:

  Open Command Prompt.

  Run Net user [username], where [username] is the name of the temporary user
  account.

  If Account expires has not been defined within 72 hours for any temporary
  user account, this is a finding."
  desc "fix", "Configure temporary user accounts to automatically expire within
  72 hours.

  Domain accounts can be configured with an account expiration date, under
  Account properties.
 
  Local accounts can be configured to expire with the command Net user
  [username] /expires:[mm/dd/yyyy], where username is the name of the temporary
  user account.

  Delete any temporary user accounts that are no longer necessary."

  temp_account = input('temp_account')
  domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip
  
  if !temp_account.empty?
    users = []
    if domain_role == '4' || domain_role == '5'
      temp_account.each do |temp_user|
        ad_user = json(command: "Get-ADUser -Filter * -Properties AccountExpirationDate | Where-Object {($_.SamAccountName -eq '#{temp_user}')} | Select-Object @{Name='Name';Expression={$_.SamAccountName}}, @{Name='TimeSpan';Expression={New-TimeSpan -Start ($_.AccountExpirationDate) -End (Get-Date) | Select Days, Hours}} | ConvertTo-JSON").params
        if ad_user['Name'] == temp_user
          users.push(ad_user)
        end
      end
    else
      temp_account.each do |temp_user|
        local_user = json(command: "Get-LocalUser #{temp_user} | Select Name, @{Name='TimeSpan';Expression={New-TimeSpan -Start ($_.AccountExpires) -End (Get-Date) | Select Days, Hours}} | ConvertTo-JSON").params
        if local_user['Name'] == temp_user
          users.push(local_user)
        end
      end
    end

    if !users.empty?
      users.each do |user|
        if user['TimeSpan'] == nil
          describe "The Account Expiration for temporary account '#{user['Name']}'" do
            subject { user['TimeSpan'] }
            it { should_not cmp nil }
          end
        else
          describe "The number of hours for account expiry for temporary account '#{user['Name']}'" do
            subject { user['TimeSpan']['Days']*24 + user['TimeSpan']['Hours'] }
            it { should_not cmp >= 72 }
          end
        end
      end
    else
      impact 0.0
      describe 'No accounts exist on this system, control not applicable' do
        skip 'No accounts exist on this system, control not applicable'
      end
    end

  else
    impact 0.0
    describe 'No temporary accounts on this system, control not applicable' do
      skip 'No temporary accounts on this system, control not applicable'
    end
  end
end
