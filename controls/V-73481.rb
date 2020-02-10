control 'V-73481' do
  title "Windows Server 2016 must be configured to audit System - Security
  State Change successes."
  desc  "Maintaining an audit trail of system activity logs can help identify
  configuration errors, troubleshoot service disruptions, and analyze compromises
  that have occurred, as well as detect attacks. Audit logs are necessary to
  provide a trail of evidence in case the system or network is compromised.
  Collecting this data is essential for analyzing the security of information
  assets and detecting signs of suspicious and unexpected behavior.

  Security State Change records events related to changes in the security
  state, such as startup and shutdown of the system.
  "
  impact 0.5
  tag "gtitle": 'SRG-OS-000327-GPOS-00127'
  tag "satisfies": ['SRG-OS-000327-GPOS-00127', 'SRG-OS-000458-GPOS-00203',
                    'SRG-OS-000463-GPOS-00207', 'SRG-OS-000468-GPOS-00212']
  tag "gid": 'V-73481'
  tag "rid": 'SV-88133r1_rule'
  tag "stig_id": 'WN16-AU-000410'
  tag "fix_id": 'F-79923r1_fix'
  tag "cci": ['CCI-000172', 'CCI-002234']
  tag "nist": ['AU-12 c', 'AC-6 (9)', 'Rev_4']
  tag "documentable": false
  desc "check", "Security Option Audit: Force audit policy subcategory
  settings (Windows Vista or later) to override audit policy category settings
  must be set to Enabled (WN16-SO-000050) for the detailed auditing
  subcategories to be effective.

  Use the AuditPol tool to review the current Audit Policy configuration:

  Open an elevated Command Prompt (run as administrator).

  Enter AuditPol /get /category:*.

  Compare the AuditPol settings with the following.

  If the system does not audit the following, this is a finding.

  System >> Security State Change - Success"
  desc "fix", "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Advanced Audit Policy Configuration >> System
  Audit Policies >> System >> Audit Security State Change with Success
  selected."
  describe.one do
    describe audit_policy do
      its('Security State Change') { should eq 'Success' }
    end
    describe audit_policy do
      its('Security State Change') { should eq 'Success and Failure' }
    end
    describe command("AuditPol /get /category:* | Findstr /c:'Security State Change'") do
      its('stdout') { should match /Security State Change                    Success/ }
    end
    describe command("AuditPol /get /category:* | Findstr /c:'Security State Change'") do
      its('stdout') { should match /Security State Change                    Success and Failure/ }
    end
  end
end
