control 'V-73489' do
  title "Windows Server 2016 must be configured to audit System - System
  Integrity successes."
  desc "Maintaining an audit trail of system activity logs can help identify
  configuration errors, troubleshoot service disruptions, and analyze compromises
  that have occurred, as well as detect attacks. Audit logs are necessary to
  provide a trail of evidence in case the system or network is compromised.
  Collecting this data is essential for analyzing the security of information
  assets and detecting signs of suspicious and unexpected behavior.

  System Integrity records events related to violations of integrity to the
  security subsystem.
  "
  impact 0.5
  tag "gtitle": 'SRG-OS-000327-GPOS-00127'
  tag "satisfies": ['SRG-OS-000327-GPOS-00127', 'SRG-OS-000471-GPOS-00215',
                    'SRG-OS-000471-GPOS-00216', 'SRG-OS-000477-GPOS-00222']
  tag "gid": 'V-73489'
  tag "rid": 'SV-88141r1_rule'
  tag "stig_id": 'WN16-AU-000440'
  tag "fix_id": 'F-79931r1_fix'
  tag "cci": ['CCI-000172', 'CCI-002234']
  tag "nist": ['AU-12 c', 'Rev_4']
  tag "nist": ['AC-6 (9)', 'Rev_4']
  tag "documentable": false
  tag "check": "Security Option Audit: Force audit policy subcategory
  settings (Windows Vista or later) to override audit policy category settings
  must be set to Enabled (WN16-SO-000050) for the detailed auditing
  subcategories to be effective.

  Use the AuditPol tool to review the current Audit Policy configuration:

  Open an elevated Command Prompt (run as administrator).

  Enter AuditPol /get /category:*.

  Compare the AuditPol settings with the following.

  If the system does not audit the following, this is a finding.

  System >> System Integrity - Success"
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Advanced Audit Policy Configuration >> System
  Audit Policies >> System >> Audit System Integrity with Success
  selected."
  describe.one do
    describe audit_policy do
      its('System Integrity') { should eq 'Success' }
    end
    describe audit_policy do
      its('System Integrity') { should eq 'Success and Failure' }
    end
    describe command("AuditPol /get /category:* | Findstr /c:'System Integrity'") do
      its('stdout') { should match /System Integrity                    Success/ }
    end
    describe command("AuditPol /get /category:* | Findstr /c:'System Integrity'") do
      its('stdout') { should match /System Integrity                    Success and Failure/ }
    end
  end
end
