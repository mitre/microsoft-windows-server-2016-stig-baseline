control "V-73297" do
  title "The TFTP Client must not be installed."
  desc  "Unnecessary services increase the attack surface of a system. Some of
  these services may not support required levels of authentication or encryption
  or may provide unauthorized access to the system."
  impact 0.5
  tag "gtitle": "SRG-OS-000095-GPOS-00049"
  tag "gid": "V-73297"
  tag "rid": "SV-87949r1_rule"
  tag "stig_id": "WN16-00-000400"
  tag "fix_id": "F-79739r1_fix"
  tag "cci": ["CCI-000381"]
  tag "nist": ["CM-7", "Rev_4"]
  tag "documentable": false
  tag "check": "Open \"PowerShell\".

  Enter \"Get-WindowsFeature | Where Name -eq TFTP-Client\".

  If \"Installed State\" is \"Installed\", this is a finding.

  An Installed State of \"Available\" or \"Removed\" is not a finding."
  tag "fix": "Uninstall the \"TFTP Client\" feature.

  Start \"Server Manager\".

  Select the server with the feature.

  Scroll down to \"ROLES AND FEATURES\" in the right pane.

  Select \"Remove Roles and Features\" from the drop-down \"TASKS\" list.

  Select the appropriate server on the \"Server Selection\" page and click
  \"Next\".

  Deselect \"TFTP Client\" on the \"Features\" page.

  Click \"Next\" and \"Remove\" as prompted."
  describe command("Get-WindowsFeature TFTP-Client | Select -Expand Installed") do
    its('stdout') {should match /False/}
  end
end

