control "V-73457" do
  title "Windows Server 2016 must be configured to audit Object Access -
Removable Storage successes."
  desc  "Maintaining an audit trail of system activity logs can help identify
configuration errors, troubleshoot service disruptions, and analyze compromises
that have occurred, as well as detect attacks. Audit logs are necessary to
provide a trail of evidence in case the system or network is compromised.
Collecting this data is essential for analyzing the security of information
assets and detecting signs of suspicious and unexpected behavior.

    Removable Storage auditing under Object Access records events related to
access attempts on file system objects on removable storage devices.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000474-GPOS-00219"
  tag "gid": "V-73457"
  tag "rid": "SV-88109r1_rule"
  tag "stig_id": "WN16-AU-000290"
  tag "fix_id": "F-79899r1_fix"
  tag "cci": ["CCI-000172"]
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "documentable": false
  tag "check": "Security Option \"Audit: Force audit policy subcategory
settings (Windows Vista or later) to override audit policy category settings\"
must be set to \"Enabled\" (WN16-SO-000050) for the detailed auditing
subcategories to be effective.

Use the AuditPol tool to review the current Audit Policy configuration:

Open an elevated \"Command Prompt\" (run as administrator).

Enter \"AuditPol /get /category:*\".

Compare the AuditPol settings with the following.

If the system does not audit the following, this is a finding.

Object Access >> Removable Storage - Success

Virtual machines or systems that use network attached storage may generate
excessive audit events for secondary virtual drives or the network attached
storage when this setting is enabled. This may be set to Not Configured in such
cases and would not be a finding."
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
Settings >> Security Settings >> Advanced Audit Policy Configuration >> System
Audit Policies >> Object Access >> \"Audit Removable Storage\" with \"Success\"
selected."
describe.one do
    describe audit_policy do
      its('Removable Storage') { should eq 'Success' }
    end
    describe audit_policy do
      its('Removable Storage') { should eq 'Success and Failure' }
    end
  end
end

