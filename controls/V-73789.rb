control 'V-73789' do
  title "The Load and unload device drivers user right must only be assigned to
  the Administrators group."
  desc "Inappropriate granting of user rights can provide system,
  administrative, and other high-level capabilities.

  The \"Load and unload device drivers\" user right allows a user to load
  device drivers dynamically on a system. This could be used by an attacker to
  install malicious code.
  "
  impact 0.5
  tag "gtitle": 'SRG-OS-000324-GPOS-00125'
  tag "gid": 'V-73789'
  tag "rid": 'SV-88453r1_rule'
  tag "stig_id": 'WN16-UR-000240'
  tag "fix_id": 'F-80239r1_fix'
  tag "cci": ['CCI-002235']
  tag "nist": ['AC-6 (10)', 'Rev_4']
  tag "documentable": false
  tag "check": "Verify the effective setting in Local Group Policy Editor.

  Run \"gpedit.msc\".

  Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
  >> Security Settings >> Local Policies >> User Rights Assignment.

  If any accounts or groups other than the following are granted the \"Load and
  unload device drivers\" user right, this is a finding.

  - Administrators"
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
  \"Load and unload device drivers\" to include only the following accounts or
  groups:

  - Administrators"
  describe.one do
    describe security_policy do
      its('SeLoadDriverPrivilege') { should eq ['S-1-5-32-544'] }
    end
    describe security_policy do
      its('SeLoadDriverPrivilege') { should eq [] }
    end
  end
end
