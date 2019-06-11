control 'V-73433' do
  title "Windows Server 2016 must be configured to audit Detailed Tracking -
  Process Creation successes."
  desc "Maintaining an audit trail of system activity logs can help identify
  configuration errors, troubleshoot service disruptions, and analyze compromises
  that have occurred, as well as detect attacks. Audit logs are necessary to
  provide a trail of evidence in case the system or network is compromised.
  Collecting this data is essential for analyzing the security of information
  assets and detecting signs of suspicious and unexpected behavior.

      Process Creation records events related to the creation of a process and
  the source.
  "
  impact 0.5
  tag "gtitle": 'SRG-OS-000327-GPOS-00127'
  tag "satisfies": ['SRG-OS-000327-GPOS-00127', 'SRG-OS-000471-GPOS-00215']
  tag "gid": 'V-73433'
  tag "rid": 'SV-88085r1_rule'
  tag "stig_id": 'WN16-AU-000170'
  tag "fix_id": 'F-79875r1_fix'
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

  Detailed Tracking >> Process Creation - Success"
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Advanced Audit Policy Configuration >> System
  Audit Policies >> Detailed Tracking >> Audit Process Creation with
  Success selected."
  describe.one do
    describe audit_policy do
      its('Process Creation') { should eq 'Success' }
    end
    describe audit_policy do
      its('Process Creation') { should eq 'Success and Failure' }
    end
    describe command("AuditPol /get /category:* | Findstr /c:'Process Creation'") do
      its('stdout') { should match /Process Creation                    Success/ }
    end
    describe command("AuditPol /get /category:* | Findstr /c:'Process Creation'") do
      its('stdout') { should match /Process Creation                    Success and Failure/ }
    end
  end
end
