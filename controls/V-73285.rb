EMERGENCY_ACCOUNT = attribute('emergency_account')
control 'V-73285' do
  title "Windows Server 2016 must automatically remove or disable emergency
  accounts after the crisis is resolved or within 72 hours."
  desc "Emergency administrator accounts are privileged accounts established
  in response to crisis situations where the need for rapid account activation is
  required. Therefore, emergency account activation may bypass normal account
  authorization processes. If these accounts are automatically disabled, system
  maintenance during emergencies may not be possible, thus adversely affecting
  system availability.

  Emergency administrator accounts are different from infrequently used
  accounts (i.e., local logon accounts used by system administrators when network
  or normal logon/access is not available). Infrequently used accounts are not
  subject to automatic termination dates. Emergency accounts are accounts created
  in response to crisis situations, usually for use by maintenance personnel. The
  automatic expiration or disabling time period may be extended as needed until
  the crisis is resolved; however, it must not be extended indefinitely. A
  permanent account should be established for privileged users who need long-term
  maintenance accounts.

  To address access requirements, many operating systems can be integrated
  with enterprise-level authentication/access mechanisms that meet or exceed
  access control policy requirements.
  "
  impact 0.5
  tag "gtitle": 'SRG-OS-000123-GPOS-00064'
  tag "gid": 'V-73285'
  tag "rid": 'SV-87937r1_rule'
  tag "stig_id": 'WN16-00-000340'
  tag "fix_id": 'F-79729r1_fix'
  tag "cci": ['CCI-001682']
  tag "nist": ['AC-2 (2)', 'Rev_4']
  tag "documentable": false
  tag "check": "Determine if emergency administrator accounts are used and
  identify any that exist. If none exist, this is NA.

  If emergency administrator accounts cannot be configured with an expiration
  date due to an ongoing crisis, the accounts must be disabled or removed when
  the crisis is resolved.

  If emergency administrator accounts have not been configured with an expiration
  date or have not been disabled or removed following the resolution of a crisis,
  this is a finding.

  Domain Controllers:

  Open \"PowerShell\".

  Enter \"Search-ADAccount –AccountExpiring | FT Name, AccountExpirationDate\".

  If \"AccountExpirationDate\" has been defined and is not within 72 hours for an
  emergency administrator account, this is a finding.

  Member servers and standalone systems:

  Open \"Command Prompt\".

  Run \"Net user [username]\", where [username] is the name of the emergency
  account.

  If \"Account expires\" has been defined and is not within 72 hours for an
  emergency administrator account, this is a finding."
  tag "fix": "Remove emergency administrator accounts after a crisis has been
  resolved or configure the accounts to automatically expire within 72 hours.

  Domain accounts can be configured with an account expiration date, under
  \"Account\" properties.

  Local accounts can be configured to expire with the command \"Net user
  [username] /expires:[mm/dd/yyyy]\", where username is the name of the temporary
  user account."
  emergency_accounts = EMERGENCY_ACCOUNT

  if emergency_accounts != []

    emergency_accounts.each do |user|

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
      if account_expires != 'Never'
        describe "#{user}'s account expires" do
          describe date_expires_minus_password_last_set do
            it { should cmp <= 72 }
          end
        end
      end
    end

  end
  if emergency_accounts.empty?
    impact 0.0
    desc 'There are no emergency accounts on this system, therefore this control is not applicable'
    describe 'There are no emergency accounts on this system, therefore this control is not applicable' do
      skip 'There are no emergency accounts on this system, therefore this control is not applicable'
    end
  end
end
