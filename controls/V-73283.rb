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

  domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip
  temp_accounts_list = input('temporary_accounts')
  temp_accounts_data = []
  
  if temp_accounts_list == [nil]
    impact 0.0
    describe 'This control is not applicable as no temporary accounts were listed as an input' do
      skip 'This control is not applicable as no temporary accounts were listed as an input'
    end
  else
    if domain_role == '4' || domain_role == '5'
      temp_accounts_list.each do |temporary_account|
        temp_accounts_data << json({ command: "Get-ADUser -Identity #{temporary_account} -Properties WhenCreated, AccountExpirationDate | Select-Object -Property SamAccountName, @{Name='WhenCreated';Expression={$_.WhenCreated.ToString('yyyy-MM-dd')}}, @{Name='AccountExpirationDate';Expression={$_.AccountExpirationDate.ToString('yyyy-MM-dd')}}| ConvertTo-Json"}).params
      end
      if temp_accounts_data.empty?
        impact 0.0
        describe 'This control is not applicable as account information was not found for the listed temporary accounts' do
          skip 'This control is not applicable as account information was not found for the listed temporary accounts'
        end
      else
        temp_accounts_data.each do |temp_account|
          account_name = temp_account.fetch("SamAccountName")
          if temp_account.fetch("WhenCreated") == nil
            describe "#{account_name} account's creation date" do
              subject { temp_account.fetch("WhenCreated") }
              it { should_not eq nil}
            end
          elsif temp_account.fetch("AccountExpirationDate") == nil
            describe "#{account_name} account's expiration date" do
              subject { temp_account.fetch("AccountExpirationDate") }
              it { should_not eq nil}
            end
          else
            creation_date = Date.parse(temp_account.fetch("WhenCreated"))
            expiration_date = Date.parse(temp_account.fetch("AccountExpirationDate"))
            date_difference = expiration_date.mjd - creation_date.mjd
            describe "Account expiration set for #{account_name}" do
              subject { date_difference }
              it { should cmp <= input('temporary_account_period')}
            end
          end
        end
      end

    else
      temp_accounts_list.each do |temporary_account|
        temp_accounts_data << json({ command: "Get-LocalUser -Name #{temporary_account} | Select-Object -Property Name, @{Name='PasswordLastSet';Expression={$_.PasswordLastSet.ToString('yyyy-MM-dd')}}, @{Name='AccountExpires';Expression={$_.AccountExpires.ToString('yyyy-MM-dd')}} | ConvertTo-Json"}).params
      end
      if temp_accounts_data.empty?
        impact 0.0
        describe 'This control is not applicable as account information was not found for the listed temporary accounts' do
          skip 'This control is not applicable as account information was not found for the listed temporary accounts'
        end
      else
        temp_accounts_data.each do |temp_account|
          user_name = temp_account.fetch("Name")
          if temp_account.fetch("PasswordLastSet") == nil
            describe "#{user_name} account's password last set date" do
              subject { temp_account.fetch("PasswordLastSet") }
              it { should_not eq nil}
            end
          elsif temp_account.fetch("AccountExpires") == nil
            describe "#{user_name} account's expiration date" do
              subject { temp_account.fetch("AccountExpires") }
              it { should_not eq nil}
            end
          else
            password_date = Date.parse(temp_account.fetch("PasswordLastSet"))
            expiration_date = Date.parse(temp_account.fetch("AccountExpires"))
            date_difference = expiration_date.mjd - password_date.mjd
            describe "Account expiration set for #{user_name}" do
              subject { date_difference }
              it { should cmp <= input('temporary_account_period')}
            end
          end
        end
      end
    end
  end
end