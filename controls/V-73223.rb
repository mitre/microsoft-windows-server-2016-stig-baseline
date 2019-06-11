control 'V-73223' do
  title "Passwords for the built-in Administrator account must be changed at
  least every 60 days."
  desc  "The longer a password is in use, the greater the opportunity for
  someone to gain unauthorized knowledge of the password. The built-in
  Administrator account is not generally used and its password may not be changed
  as frequently as necessary. Changing the password for the built-in
  Administrator account on a regular basis will limit its exposure.

  Organizations that use an automated tool, such as Microsoft's Local
  Administrator Password Solution (LAPS), on domain-joined systems can configure
  this to occur more frequently. LAPS will change the password every 30 days
  by default.
  "
  impact 0.5
  tag "gtitle": 'SRG-OS-000076-GPOS-00044'
  tag "gid": 'V-73223'
  tag "rid": 'SV-87875r2_rule'
  tag "stig_id": 'WN16-00-000030'
  tag "fix_id": 'F-79667r2_fix'
  tag "cci": ['CCI-000199']
  tag "nist": ['IA-5 (1) (d)', 'Rev_4']
  tag "documentable": false
  tag "check": "Review the password last set date for the built-in
  Administrator account.
 
  Domain controllers:

  Open PowerShell.

  Enter Get-ADUser -Filter * -Properties SID, PasswordLastSet | Where SID -Like
  *-500 | Ft Name, SID, PasswordLastSet.

  If the PasswordLastSet date is greater than 60 days old, this is a
  finding.

  Member servers and standalone systems:

  Open Command Prompt.

  Enter 'Net User [account name] | Find /i Password Last Set', where [account
  name] is the name of the built-in administrator account.

  (The name of the built-in Administrator account must be changed to something
  other than Administrator per STIG requirements.)

  If the PasswordLastSet date is greater than 60 days old, this is a
  finding."
  tag "fix": "Change the built-in Administrator account password at least every
  60 days.

  Automated tools, such as Microsoft's LAPS, may be used on domain-joined member
  servers to accomplish this."
  require 'date'
  administrators = attribute('administrators')

  if !administrators.empty?
    administrators.each do |admin|
      password_age = json({ command:"NEW-TIMESPAN –End (GET-DATE) –Start ([datetime]((net user #{admin} | \
                        Select-String \"Password last set\").Line.Substring(29,10))) | convertto-json"}).Days

      describe "Administrator Password age for #{admin}" do
        subject { password_age }
        it { should cmp <= 60 }
      end
    end
  end

  if administrators.empty?
    describe 'There are no administrative accounts on this system' do
      skip 'There are no administrative accounts on this system'
    end
  end
end 
