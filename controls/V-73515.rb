control "V-73515" do
  title "Credential Guard must be running on domain-joined systems."
  desc  "Credential Guard uses virtualization-based security to protect data
that could be used in credential theft attacks if compromised. This
authentication information, which was stored in the Local Security Authority
(LSA) in previous versions of Windows, is isolated from the rest of operating
system and can only be accessed by privileged system software."
  impact 0.3
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-73515"
  tag "rid": "SV-88167r1_rule"
  tag "stig_id": "WN16-CC-000120"
  tag "fix_id": "F-79957r1_fix"
  tag "cci": ["CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "documentable": false
  tag "check": "For standalone systems, this is NA.

Current hardware and virtual environments may not support virtualization-based
security features, including Credential Guard, due to specific supporting
requirements, including a TPM, UEFI with Secure Boot, and the capability to run
the Hyper-V feature within a virtual machine.

Open \"PowerShell\" with elevated privileges (run as administrator).

Enter the following:

\"Get-CimInstance -ClassName Win32_DeviceGuard -Namespace
root\\Microsoft\\Windows\\DeviceGuard\"

If \"SecurityServicesRunning\" does not include a value of \"1\" (e.g., \"{1,
2}\"), this is a finding.

Alternately:

Run \"System Information\".

Under \"System Summary\", verify the following:

If \"Device Guard Security Services Running\" does not list \"Credential
Guard\", this is finding.

The policy settings referenced in the Fix section will configure the following
registry value. However due to hardware requirements, the registry value alone
does not ensure proper function.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard\\

Value Name: LsaCfgFlags
Value Type: REG_DWORD
Value: 0x00000001 (1) (Enabled with UEFI lock), or 0x00000002 (2) (Enabled
without lock)

A Microsoft TechNet article on Credential Guard, including system requirement
details, can be found at the following link:

https://technet.microsoft.com/itpro/windows/keep-secure/credential-guard"
  tag "fix": "Configure the policy value for Computer Configuration >>
Administrative Templates >> System >> Device Guard >> \"Turn On Virtualization
Based Security\" to \"Enabled\" with \"Enabled with UEFI lock\" or \"Enabled
without lock\" selected for \"Credential Guard Configuration\".

\"Enabled with UEFI lock\" is preferred as more secure; however, it cannot be
turned off remotely through a group policy change if there is an issue.
\"Enabled without lock\" will allow this to be turned off remotely while
testing for issues.

A Microsoft TechNet article on Credential Guard, including system requirement
details, can be found at the following link:

https://technet.microsoft.com/itpro/windows/keep-secure/credential-guard"
  is_domain = command("wmic computersystem get domain | FINDSTR /V Domain").stdout.strip
  describe.one do
    describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard") do
      it { should have_property "LsaCfgFlags" }
      its("LsaCfgFlags") { should cmp == 1 }
    end
    describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard") do
      it { should have_property "LsaCfgFlags" }
      its("LsaCfgFlags") { should cmp == 2 }
    end
  end
  only_if {is_domain != "WORKGROUP"}
end

