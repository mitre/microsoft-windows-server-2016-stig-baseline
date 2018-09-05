control "V-73257" do
  title "Non-administrative accounts or groups must only have print permissions
  on printer shares."
  desc  "Windows shares are a means by which files, folders, printers, and
  other resources can be published for network users to access. Improper
  configuration can permit access to devices and data beyond a user's need."
  get_printers = command("Get-Printer | Format-List | Findstr /v 'Name ---'")
  if get_printers == ''
    impact 0.0
  else
    impact 0.3
  end
  tag "gtitle": "SRG-OS-000080-GPOS-00048"
  tag "gid": "V-73257"
  tag "rid": "SV-87909r1_rule"
  tag "stig_id": "WN16-00-000200"
  tag "fix_id": "F-79701r1_fix"
  tag "cci": ["CCI-000213"]
  tag "nist": ["AC-3", "Rev_4"]
  tag "documentable": false
  tag "check": "Open \"Devices and Printers\".

  If there are no printers configured, this is NA. (Exclude Microsoft Print to
  PDF and Microsoft XPS Document Writer, which do not support sharing.)

  For each printer:

  Right-click on the printer.

  Select \"Printer Properties\".

  Select the \"Sharing\" tab.

  If \"Share this printer\" is checked, select the \"Security\" tab.

  If any standard user accounts or groups have permissions other than \"Print\",
  this is a finding.

  The default is for the \"Everyone\" group to be given \"Print\" permission.

  \"All APPLICATION PACKAGES\" and \"CREATOR OWNER\" are not standard user
  accounts."
  tag "fix": "Configure the permissions on shared printers to restrict standard
  users to only have Print permissions."
  describe "Nonadministrative user accounts or groups must only have print
  permissions on printer shares." do
    skip "This is a manual control"
  end
end

