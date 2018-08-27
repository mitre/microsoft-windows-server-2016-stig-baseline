ADMINISTRATOR_ACCOUNT = attribute(
  'administrator_account',
  description: 'List of authorized users in the local Administrators domain group',
  default: 'Admn'
)

control "V-73223" do
  title "Passwords for the built-in Administrator account must be changed at
  least every 60 days."
  desc  "The longer a password is in use, the greater the opportunity for
  someone to gain unauthorized knowledge of the password. The built-in
  Administrator account is not generally used and its password not may be changed
  as frequently as necessary. Changing the password for the built-in
  Administrator account on a regular basis will limit its exposure.

  Organizations that use an automated tool, such Microsoft's Local
  Administrator Password Solution (LAPS), on domain-joined systems can configure
  this to occur more frequently. LAPS will change the password every \"30\" days
  by default.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000076-GPOS-00044"
  tag "gid": "V-73223"
  tag "rid": "SV-87875r2_rule"
  tag "stig_id": "WN16-00-000030"
  tag "fix_id": "F-79667r2_fix"
  tag "cci": ["CCI-000199"]
  tag "nist": ["CCI-000199"]
  tag "nist": ["IA-5 (1) (d)", "Rev_4"]
  tag "documentable": false
  tag "check": "Review the password last set date for the built-in
  Administrator account.

  Domain controllers:

  Open \"PowerShell\".

  Enter \"Get-ADUser -Filter * -Properties SID, PasswordLastSet | Where SID -Like
  \"*-500\" | Ft Name, SID, PasswordLastSet\".

  If the \"PasswordLastSet\" date is greater than \"60\" days old, this is a
  finding.

  Member servers and standalone systems:

  Open \"Command Prompt\".

  Enter 'Net User [account name] | Find /i \"Password Last Set\"', where [account
  name] is the name of the built-in administrator account.

  (The name of the built-in Administrator account must be changed to something
  other than \"Administrator\" per STIG requirements.)

  If the \"PasswordLastSet\" date is greater than \"60\" days old, this is a
  finding."
  tag "fix": "Change the built-in Administrator account password at least every
  \"60\" days.

  Automated tools, such as Microsoft's LAPS, may be used on domain-joined member
  servers to accomplish this."
  require 'date'
  get_password_last_set = command("Net User #{ADMINISTRATOR_ACCOUNT} | Findstr /i 'Password Last Set' | Findstr /v 'expires changeable required may logon'").stdout.strip
  month = get_password_last_set[27..29]
  day = get_password_last_set[31..32]
  year = get_password_last_set[34..38]

  if (get_password_last_set[32] == '/')
      month = get_password_last_set[27..29]
      day = get_password_last_set[31]
      year = get_password_last_set[33..37]
    end

  date = day +  "/" + month + "/" + year

  date_password_last_set = DateTime.now.mjd - DateTime.parse(date).mjd
  describe "Administrator account's password last set" do
    describe date_password_last_set do
      it { should cmp <= 30 }
    end 
  end
end

