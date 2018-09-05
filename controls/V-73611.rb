domain_role = command("wmic computersystem get domainrole | Findstr /v DomainRole").stdout.strip
control "V-73611" do
  title "Domain controllers must have a PKI server certificate."
  desc  "Domain controllers are part of the chain of trust for PKI
  authentications. Without the appropriate certificate, the authenticity of the
  domain controller cannot be verified. Domain controllers must have a server
  certificate to establish authenticity as part of PKI authentications in the
  domain."
  if domain_role == '4' || domain_role == '5'
    impact 0.5
  else
    impact 0.0
  end
  tag "gtitle": "SRG-OS-000066-GPOS-00034"
  tag "gid": "V-73611"
  tag "rid": "SV-88275r1_rule"
  tag "stig_id": "WN16-DC-000280"
  tag "fix_id": "F-80061r1_fix"
  tag "cci": ["CCI-000185"]
  tag "nist": ["IA-5 (2) (a)", "Rev_4"]
  tag "documentable": false
  tag "check": "This applies to domain controllers. It is NA for other systems.

  Run \"MMC\".

  Select \"Add/Remove Snap-in\" from the \"File\" menu.

  Select \"Certificates\" in the left pane and click the \"Add >\" button.

  Select \"Computer Account\" and click \"Next\".

  Select the appropriate option for \"Select the computer you want this snap-in
  to manage\" and click \"Finish\".

  Click \"OK\".

  Select and expand the Certificates (Local Computer) entry in the left pane.

  Select and expand the Personal entry in the left pane.

  Select the Certificates entry in the left pane.

  If no certificate for the domain controller exists in the right pane, this is a
  finding."
  tag "fix": "Obtain a server certificate for the domain controller."
  describe command("Get-ChildItem -Path Cert:\\LocalMachine\\My | Findstr /v 'Thumbprint -- PSParentPath'") do
    its('stdout') { should_not eq ' ' }
  end if domain_role == '4' || domain_role == '5'

  describe "System is not a domain controller, control not applicable" do
    skip "System is not a domain controller, control not applicable"
  end if domain_role != '4' && domain_role != '5'
  
end

