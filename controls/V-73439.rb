control 'V-73439' do
  title "Windows Server 2016 must be configured to audit DS Access - Directory
  Service Changes successes."
  desc "Maintaining an audit trail of system activity logs can help identify
  configuration errors, troubleshoot service disruptions, and analyze compromises
  that have occurred, as well as detect attacks. Audit logs are necessary to
  provide a trail of evidence in case the system or network is compromised.
  Collecting this data is essential for analyzing the security of information
  assets and detecting signs of suspicious and unexpected behavior.

    Audit Directory Service Changes records events related to changes made to
  objects in Active Directory Domain Services.
  "
  impact 0.5
  tag "gtitle": 'SRG-OS-000327-GPOS-00127'
  tag "satisfies": ['SRG-OS-000327-GPOS-00127', 'SRG-OS-000458-GPOS-00203',
                    'SRG-OS-000463-GPOS-00207', 'SRG-OS-000468-GPOS-00212']
  tag "gid": 'V-73439'
  tag "rid": 'SV-88091r1_rule'
  tag "stig_id": 'WN16-DC-000260'
  tag "fix_id": 'F-79881r1_fix'
  tag "cci": ['CCI-000172', 'CCI-002234']
  tag "nist": ['AU-12 c', 'Rev_4']
  tag "nist": ['AC-6 (9)', 'Rev_4']
  tag "documentable": false
  tag "check": "This applies to domain controllers. It is NA for other systems.

  Security Option \"Audit: Force audit policy subcategory settings (Windows Vista
  or later) to override audit policy category settings\" must be set to
  \"Enabled\" (WN16-SO-000050) for the detailed auditing subcategories to be
  effective.

  Use the AuditPol tool to review the current Audit Policy configuration:

  Open an elevated \"Command Prompt\" (run as administrator).

  Enter \"AuditPol /get /category:*\".

  Compare the AuditPol settings with the following.

  If the system does not audit the following, this is a finding.

  DS Access >> Directory Service Changes - Success"
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Advanced Audit Policy Configuration >> System
  Audit Policies >> DS Access >> \"Directory Service Changes\" with \"Success\"
  selected."
  domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip

  describe.one do
    describe audit_policy do
      its('Directory Service Changes') { should eq 'Success' }
    end
    describe audit_policy do
      its('Directory Service Changes') { should eq 'Success and Failure' }
    end
    describe command("AuditPol /get /category:* | Findstr /c:'Directory Service Changes'") do
      its('stdout') { should match /Directory Service Changes                    Success/ }
    end
    describe command("AuditPol /get /category:* | Findstr /c:'Directory Service Changes'") do
      its('stdout') { should match /Directory Service Changes                    Success and Failure/ }
    end
  end if [4, 5].include? domain_role

  if ![4, 5].include? domain_role
    impact 0.0
    desc 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers'
    describe 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers' do
      skip 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers'
    end
  end
end
