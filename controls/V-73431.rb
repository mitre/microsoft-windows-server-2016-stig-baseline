control "V-73431" do
  title "Windows Server 2016 must be configured to audit Detailed Tracking -
  Plug and Play Events successes."
  desc  "Maintaining an audit trail of system activity logs can help identify
  configuration errors, troubleshoot service disruptions, and analyze compromises
  that have occurred, as well as detect attacks. Audit logs are necessary to
  provide a trail of evidence in case the system or network is compromised.
  Collecting this data is essential for analyzing the security of information
  assets and detecting signs of suspicious and unexpected behavior.

      Plug and Play activity records events related to the successful connection
  of external devices.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000474-GPOS-00219"
  tag "gid": "V-73431"
  tag "rid": "SV-88083r2_rule"
  tag "stig_id": "WN16-AU-000160"
  tag "fix_id": "F-79873r1_fix"
  tag "cci": ["CCI-000172"]
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "documentable": false
  tag "check": "Security Option \"Audit: Force audit policy subcategory
  settings (Windows Vista or later) to override audit policy category settings\"
  must be set to \"Enabled\" (WN16-SO-000050) for the detailed auditing
  subcategories to be effective.

  Use the AuditPol tool to review the current Audit Policy configuration:

  Open an elevated \"Command Prompt\" (run as administrator).

  Enter \"AuditPol /get /category:*\"

  Compare the AuditPol settings with the following.

  If the system does not audit the following, this is a finding.

  Detailed Tracking >> Plug and Play Events - Success"
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Advanced Audit Policy Configuration >> System Audit Policies >>
  Detailed Tracking >> \"Audit PNP Activity\" with \"Success\" selected."
  describe command("AuditPol /get /category:* | Findstr /c:'Plug and Play Events'") do
    its('stdout') { should match /Plug and Play Events                    Success/ }
  end
end

