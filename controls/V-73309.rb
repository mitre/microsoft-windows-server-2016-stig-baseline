control 'V-73309' do
  title "Windows 2016 account lockout duration must be configured to #{input('pass_lock_duration') == 0? 'until the locked account is released by an administrator.' : "for #{input('pass_lock_duration')} minutes or greater."}"
  
  desc "The account lockout feature, when enabled, prevents brute-force
  password attacks on the system. This parameter specifies the period of time
  that an account will remain locked after the specified number of failed logon
  attempts."
  impact 0.5
  tag "gtitle": 'SRG-OS-000329-GPOS-00128'
  tag "gid": 'V-73309'
  tag "rid": 'SV-87961r2_rule'
  tag "stig_id": 'WN16-AC-000010'
  tag "fix_id": 'F-80983r1_fix'
  tag "cci": ['CCI-002238']
  tag "nist": ['AC-7 b', 'Rev_4']
  tag "documentable": false
  desc "check", "Verify the effective setting in Local Group Policy Editor.
  Run gpedit.msc.

  Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
  >> Security Settings >> Account Policies >> Account Lockout Policy.

  If the Account lockout duration is less than #{input('pass_lock_duration')} minutes (excluding
  0), this is a finding.

  Configuring this to 0, requiring an administrator to unlock the account, is
  more restrictive and is not a finding."
  desc "fix", "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Account Policies >> Account Lockout Policy >>
  Account lockout duration to #{input('pass_lock_duration')} minutes or greater.

  A value of 0 is also acceptable, requiring an administrator to unlock the
  account."

  pass_lock_duration = input('pass_lock_duration')
  describe.one do
    describe security_policy do
      its('LockoutDuration') { should be >= input('pass_lock_duration') }
    end
    describe security_policy do
      its('LockoutDuration') { should eq 0 }
    end
  end
end
