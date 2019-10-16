control 'V-73313' do
  title "The period of time before the bad logon counter is reset must be
  configured to 15 minutes or greater."
  desc "The account lockout feature, when enabled, prevents brute-force
  password attacks on the system. This parameter specifies the period of time
  that must pass after failed logon attempts before the counter is reset to
  0. The smaller this value is, the less effective the account lockout
  feature will be in protecting the local system.
  "
  impact 0.5
  tag "gtitle": 'SRG-OS-000021-GPOS-00005'
  tag "satisfies": ['SRG-OS-000021-GPOS-00005', 'SRG-OS-000329-GPOS-00128']
  tag "gid": 'V-73313'
  tag "rid": 'SV-87965r1_rule'
  tag "stig_id": 'WN16-AC-000030'
  tag "fix_id": 'F-79755r1_fix'
  tag "cci": ['CCI-000044', 'CCI-002238']
  tag "nist": ['AC-7 a', 'Rev_4']
  tag "documentable": false
  tag "check": "Verify the effective setting in Local Group Policy Editor.

  Run gpedit.msc.

  Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
  >> Security Settings >> Account Policies >> Account Lockout Policy.

  If the Reset account lockout counter after value is less than 15
  minutes, this is a finding."
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Account Policies >> Account Lockout Policy >>
  Reset account lockout counter after to at least 15 minutes."
  describe security_policy do
    its('ResetLockoutCount') { should be >= 15 }
  end
end
