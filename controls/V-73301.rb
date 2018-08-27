control "V-73301" do
  title "Windows PowerShell 2.0 must not be installed."
  desc  "Windows PowerShell 5.0 added advanced logging features that can
  provide additional detail when malware has been run on a system. Disabling the
  Windows PowerShell 2.0 mitigates against a downgrade attack that evades the
  Windows PowerShell 5.0 script block logging feature."
  impact 0.5
  tag "gtitle": "SRG-OS-000095-GPOS-00049"
  tag "gid": "V-73301"
  tag "rid": "SV-87953r1_rule"
  tag "stig_id": "WN16-00-000420"
  tag "fix_id": "F-79743r1_fix"
  tag "cci": ["CCI-000381"]
  tag "nist": ["CM-7", "Rev_4"]
  tag "documentable": false
  tag "check": "Open \"PowerShell\".

  Enter \"Get-WindowsFeature | Where Name -eq PowerShell-v2\".

  If \"Installed State\" is \"Installed\", this is a finding.

  An Installed State of \"Available\" or \"Removed\" is not a finding."
  tag "fix": "Uninstall the \"Windows PowerShell 2.0 Engine\".

  Start \"Server Manager\".

  Select the server with the feature.

  Scroll down to \"ROLES AND FEATURES\" in the right pane.

  Select \"Remove Roles and Features\" from the drop-down \"TASKS\" list.

  Select the appropriate server on the \"Server Selection\" page and click
  \"Next\".

  Deselect \"Windows PowerShell 2.0 Engine\" under \"Windows PowerShell\" on the
  \"Features\" page.

  Click \"Next\" and \"Remove\" as prompted."
  end

