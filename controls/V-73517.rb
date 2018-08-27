control "V-73517" do
  title "Virtualization-based protection of code integrity must be enabled on
domain-joined systems."
  desc  "Virtualization-based protection of code integrity enforces kernel mode
memory protections as well as protecting Code Integrity validation paths. This
isolates the processes from the rest of the operating system and can only be
accessed by privileged system software."
  impact 0.3
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-73517"
  tag "rid": "SV-88169r1_rule"
  tag "stig_id": "WN16-CC-000130"
  tag "fix_id": "F-79959r1_fix"
  tag "cci": ["CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "documentable": false
  tag "check": "For standalone systems, this is NA.

Current hardware and virtual environments may not support virtualization-based
security features, including Credential Guard, due to specific supporting
requirements including a TPM, UEFI with Secure Boot, and the capability to run
the Hyper-V feature within a virtual machine.

Open \"PowerShell\" with elevated privileges (run as administrator).

Enter the following:

\"Get-CimInstance -ClassName Win32_DeviceGuard -Namespace
root\\Microsoft\\Windows\\DeviceGuard\"

If \"SecurityServicesRunning\" does not include a value of \"2\" (e.g., \"{1,
2}\"), this is a finding.

Alternately:

Run \"System Information\".

Under \"System Summary\", verify the following:

If \"Device Guard Security Services Running\" does not list \"Hypervisor
enforced Code Integrity\", this is a finding.

The policy settings referenced in the Fix section will configure the following
registry value. However due to hardware requirements, the registry value alone
does not ensure proper function.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard\\

Value Name: HypervisorEnforcedCodeIntegrity
Value Type: REG_DWORD
Value: 0x00000001 (1) (Enabled with UEFI lock), or 0x00000002 (2) (Enabled
without lock)"
  tag "fix": "Configure the policy value for Computer Configuration >>
Administrative Templates >> System >> Device Guard >> \"Turn On Virtualization
Based Security\" to \"Enabled\" with \"Enabled with UEFI lock\" or \"Enabled
without lock\" selected for \"Virtualization Based Protection for Code
Integrity\".

\"Enabled with UEFI lock\" is preferred as more secure; however, it cannot be
turned off remotely through a group policy change if there is an issue.
\"Enabled without lock\" will allow this to be turned off remotely while
testing for issues."
  is_domain = command("wmic computersystem get domain | FINDSTR /V Domain").stdout.strip
  describe.one do
    describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard") do
      it { should have_property "HypervisorEnforcedCodeIntegrity" }
      its("HypervisorEnforcedCodeIntegrity") { should cmp == 1 }
    end
    describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard") do
      it { should have_property "HypervisorEnforcedCodeIntegrity" }
      its("HypervisorEnforcedCodeIntegrity") { should cmp == 2 }
    end
  end
  only_if {is_domain != "WORKGROUP"}
end

