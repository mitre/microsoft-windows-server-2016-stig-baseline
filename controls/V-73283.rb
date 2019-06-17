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
  tag "check": "Review temporary user accounts for expiration dates.

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
  tag "fix": "Configure temporary user accounts to automatically expire within
  72 hours.

  Domain accounts can be configured with an account expiration date, under
  Account properties.
 
  Local accounts can be configured to expire with the command Net user
  [username] /expires:[mm/dd/yyyy], where username is the name of the temporary
  user account.

  Delete any temporary user accounts that are no longer necessary."

  temp_account = attribute('temp_account')
  if temp_account.empty?
    temp_account.each do |user|

      get_account_expires = command("Net User #{user} | Findstr /i 'expires' | Findstr /v 'password'").stdout.strip

      month_account_expires = get_account_expires[28..30]
      day_account_expires = get_account_expires[32..33]
      year_account_expires = get_account_expires[35..39]

      if get_account_expires[30] == '/'
        month_account_expires = get_account_expires[28..29]
        if get_account_expires[32] == '/'
          day_account_expires = get_account_expires[31]
        end
        if get_account_expires[32] != '/'
          day_account_expires = get_account_expires[31..32]
        end
        if get_account_expires[33] == '/'
          year_account_expires = get_account_expires[34..37]
        end
        if get_account_expires[33] != '/'
          year_account_expires = get_account_expires[33..37]
        end

      end

      date_expires = day_account_expires + '/' + month_account_expires + '/' + year_account_expires

      get_password_last_set = command("Net User #{user}  | Findstr /i 'Password Last Set' | Findstr /v 'expires changeable required may logon'").stdout.strip

      month = get_password_last_set[27..29]
      day = get_password_last_set[31..32]
      year = get_password_last_set[34..38]

      if get_password_last_set[32] == '/'
        month = get_password_last_set[27..29]
        day = get_password_last_set[31]
        year = get_password_last_set[33..37]
      end
      date = day + '/' + month + '/' + year

      date_expires_minus_password_last_set = DateTime.parse(date_expires).mjd - DateTime.parse(date).mjd

      account_expires = get_account_expires[27..33]

      if account_expires == 'Never'
        describe "#{user}'s account expires" do
          describe account_expires do
            it { should_not == 'Never' }
          end
        end
      end
      next unless account_expires != 'Never'
      describe "#{user}'s account expires" do
        describe date_expires_minus_password_last_set do
          it { should cmp <= 72 }
        end
      end
    end

  else
    impact 0.0
    describe 'No temporary accounts on this system, control not applicable' do
      skip 'No temporary accounts on this system, control not applicable'
    end
  end
end
