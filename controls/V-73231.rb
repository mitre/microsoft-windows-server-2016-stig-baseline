control "V-73231" do
  title "Manually managed application account passwords must be changed at
  least annually or when a system administrator with knowledge of the password
  leaves the organization."
    desc  "Setting application account passwords to expire may cause applications
  to stop functioning. However, not changing them on a regular basis exposes them
  to attack. If managed service accounts are used, this alleviates the need to
  manually change application account passwords."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-73231"
  tag "rid": "SV-87883r2_rule"
  tag "stig_id": "WN16-00-000070"
  tag "fix_id": "F-79675r1_fix"
  tag "cci": ["CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "documentable": false
  tag "check": "Determine if manually managed application/service accounts
  exist. If none exist, this is NA.

  If passwords for manually managed application/service accounts are not changed
  at least annually or when an administrator with knowledge of the password
  leaves the organization, this is a finding.

  Identify manually managed application/service accounts.

  To determine the date a password was last changed:

  Domain controllers:

  Open \"PowerShell\".

  Enter \"Get-AdUser -Identity [application account name] -Properties
  PasswordLastSet | FT Name, PasswordLastSet\", where [application account name]
  is the name of the manually managed application/service account.

  If the \"PasswordLastSet\" date is more than one year old, this is a finding.

  Member servers and standalone systems:

  Open \"Command Prompt\".

  Enter 'Net User [application account name] | Find /i \"Password Last Set\"',
  where [application account name] is the name of the manually managed
  application/service account.

  If the \"Password Last Set\" date is more than one year old, this is a finding."
  tag "fix": "Change passwords for manually managed application/service
  accounts at least annually or when an administrator with knowledge of the
  password leaves the organization.

  It is recommended that system-managed service accounts be used whenever
  possible."
end

