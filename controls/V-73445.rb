control 'V-73445' do
  title "Windows Server 2016 must be configured to audit Logon/Logoff - Account
  Lockout failures."
  desc "Maintaining an audit trail of system activity logs can help identify
  configuration errors, troubleshoot service disruptions, and analyze compromises
  that have occurred, as well as detect attacks. Audit logs are necessary to
  provide a trail of evidence in case the system or network is compromised.
  Collecting this data is essential for analyzing the security of information
  assets and detecting signs of suspicious and unexpected behavior.

      Account Lockout events can be used to identify potentially malicious logon
  attempts.
  "
  impact 0.5
  tag "gtitle": 'SRG-OS-000240-GPOS-00090'
  tag "satisfies": ['SRG-OS-000240-GPOS-00090', 'SRG-OS-000470-GPOS-00214']
  tag "gid": 'V-73445'
  tag "rid": 'SV-88097r2_rule'
  tag "stig_id": 'WN16-AU-000230'
  tag "fix_id": 'F-79887r1_fix'
  tag "cci": ['CCI-000172', 'CCI-001404']
  tag "nist": ['AU-12 c', 'Rev_4']
  tag "nist": ['AC-2 (4)', 'Rev_4']
  tag "documentable": false
  tag "check": "Security Option Audit: Force audit policy subcategory
  settings (Windows Vista or later) to override audit policy category settings
  must be set to Enabled (WN16-SO-000050) for the detailed auditing
  subcategories to be effective.

  Use the AuditPol tool to review the current Audit Policy configuration:

  Open an elevated Command Prompt (run as administrator).

  Enter AuditPol /get /category:*

  Compare the AuditPol settings with the following. If the system does not audit
  the following, this is a finding.

  Logon/Logoff >> Account Lockout - Failure"
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Advanced Audit Policy Configuration >> System Audit Policies >>
  Logon/Logoff >> Audit Account Lockout with Failure selected."
  describe.one do
    describe audit_policy do
      its('Account Lockout') { should eq 'Success and Failure' }
    end
    describe audit_policy do
      its('Account Lockout') { should eq 'Failure' }
    end
    describe command("AuditPol /get /category:* | Findstr /c:'Account Lockout'") do
      its('stdout') { should match /Account Lockout                    Failure/ }
    end
    describe command("AuditPol /get /category:* | Findstr /c:'Account Lockout'") do
      its('stdout') { should match /Account Lockout                    Success and Failure/ }
    end
  end
end
