control 'V-73417' do
  title "Windows Server 2016 must be configured to audit Account Management -
  Computer Account Management successes."
  desc "Maintaining an audit trail of system activity logs can help identify
  configuration errors, troubleshoot service disruptions, and analyze compromises
  that have occurred, as well as detect attacks. Audit logs are necessary to
  provide a trail of evidence in case the system or network is compromised.
  Collecting this data is essential for analyzing the security of information
  assets and detecting signs of suspicious and unexpected behavior.

      Computer Account Management records events such as creating, changing,
  deleting, renaming, disabling, or enabling computer accounts.
  "
  impact 0.5
  tag "gtitle": 'SRG-OS-000004-GPOS-00004'
  tag "satisfies": ['SRG-OS-000004-GPOS-00004', 'SRG-OS-000239-GPOS-00089',
                    'SRG-OS-000240-GPOS-00090', 'SRG-OS-000241-GPOS-00091',
                    'SRG-OS-000303-GPOS-00120', 'SRG-OS-000476-GPOS-00221']
  tag "gid": 'V-73417'
  tag "rid": 'SV-88069r1_rule'
  tag "stig_id": 'WN16-DC-000230'
  tag "fix_id": 'F-79859r1_fix'
  tag "cci": ['CCI-000018', 'CCI-000172', 'CCI-001403', 'CCI-001404',
              'CCI-001405', 'CCI-002130']
  tag "nist": ['AC-2 (4)', 'Rev_4']
  tag "nist": ['AU-12 c', 'Rev_4']
  tag "documentable": false
  tag "check": "This applies to domain controllers. It is NA for other systems.

  Security Option Audit: Force audit policy subcategory settings (Windows Vista
  or later) to override audit policy category settings must be set to
  Enabled (WN16-SO-000050) for the detailed auditing subcategories to be
  effective.

  Use the AuditPol tool to review the current Audit Policy configuration:

  Open an elevated Command Prompt (run as administrator).

  Enter AuditPol /get /category:*.

  Compare the AuditPol settings with the following.

  If the system does not audit the following, this is a finding.

  Account Management >> Computer Account Management - Success"
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Advanced Audit Policy Configuration >> System
  Audit Policies >> Account Management >> Audit Computer Account Management
  with Success selected."
  describe.one do
    describe audit_policy do
      its('Computer Account Management') { should eq 'Success' }
    end
    describe audit_policy do
      its('Computer Account Management') { should eq 'Success and Failure' }
    end
    describe command("AuditPol /get /category:* | Findstr /c:'Computer Account Management'") do
      its('stdout') { should match /Computer Account Management                    Success/ }
    end
    describe command("AuditPol /get /category:* | Findstr /c:'Computer Account Management'") do
      its('stdout') { should match /Computer Account Management                    Success and Failure/ }
    end
  end
end
