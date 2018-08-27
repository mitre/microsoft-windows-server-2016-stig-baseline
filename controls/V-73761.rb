control "V-73761" do
  title "The Deny log on as a batch job user right on domain controllers must
be configured to prevent unauthenticated access."
  desc  "Inappropriate granting of user rights can provide system,
administrative, and other high-level capabilities.

    The \"Deny log on as a batch job\" user right defines accounts that are
prevented from logging on to the system as a batch job, such as Task Scheduler.

    The Guests group must be assigned to prevent unauthenticated access.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000080-GPOS-00048"
  tag "gid": "V-73761"
  tag "rid": "SV-88425r1_rule"
  tag "stig_id": "WN16-DC-000380"
  tag "fix_id": "F-80211r1_fix"
  tag "cci": ["CCI-000213"]
  tag "nist": ["AC-3", "Rev_4"]
  tag "documentable": false
  tag "check": "This applies to domain controllers. A separate version applies
to other systems.

Verify the effective setting in Local Group Policy Editor.

Run \"gpedit.msc\".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
>> Security Settings >> Local Policies >> User Rights Assignment.

If the following accounts or groups are not defined for the \"Deny log on as a
batch job\" user right, this is a finding.

- Guests Group"
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
\"Deny log on as a batch job\" to include the following:

- Guests Group"
  domain_role = command("wmic computersystem get domainrole /v DomainRole").stdout.strip
  if domain_role < 4
    describe 'control' do
      skip 'no domain role'
    end
  end
  else
    describe security_policy do
      its('SeDenyBatchLogonRight') { should eq ['S-1-5-32-546'] }
    end  
  end
end

