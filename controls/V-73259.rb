control 'V-73259' do
  title "Outdated or unused accounts must be removed from the system or
  disabled."
  desc "Outdated or unused accounts provide penetration points that may go
  undetected. Inactive accounts must be deleted if no longer necessary or, if
  still required, disabled until needed.
  "
  impact 0.5
  tag "gtitle": 'SRG-OS-000104-GPOS-00051'
  tag "satisfies": ['SRG-OS-000104-GPOS-00051', 'SRG-OS-000118-GPOS-00060']
  tag "gid": 'V-73259'
  tag "rid": 'SV-87911r2_rule'
  tag "stig_id": 'WN16-00-000210'
  tag "fix_id": 'F-79703r1_fix'
  tag "cci": ['CCI-000764', 'CCI-000795']
  tag "nist": ['IA-2', 'IA-5 e', 'Rev_4']
  tag "documentable": false
  desc "check", "Open Windows PowerShell.

  Domain Controllers:

  Enter Search-ADAccount -AccountInactive -UsersOnly -TimeSpan 35.00:00:00

  This will return accounts that have not been logged on to for 35 days, along
  with various attributes such as the Enabled status and LastLogonDate.

  Member servers and standalone systems:

  Copy or enter the lines below to the PowerShell window and enter. (Entering
  twice may be required. Do not include the quotes at the beginning and end of
  the query.)

  ([ADSI]('WinNT://{0}' -f $env:COMPUTERNAME)).Children | Where {
  $_.SchemaClassName -eq 'user' } | ForEach {
   $user = ([ADSI]$_.Path)
   $lastLogin = $user.Properties.LastLogin.Value
   $enabled = ($user.Properties.UserFlags.Value -band 0x2) -ne 0x2
   if ($lastLogin -eq $null) {
   $lastLogin = 'Never'
   }
   Write-Host $user.Name $lastLogin $enabled
  }

  This will return a list of local accounts with the account name, last logon,
  and if the account is enabled (True/False).
  For example: User1 10/31/2015 5:49:56 AM True

  Review the list of accounts returned by the above queries to determine the
  finding validity for each account reported.

  Exclude the following accounts:

  - Built-in administrator account (Renamed, SID ending in 500)
  - Built-in guest account (Renamed, Disabled, SID ending in 501)
  - Built-in default account (Renamed, Disabled, SID ending in 503)
  - Application accounts

  If any enabled accounts have not been logged on to within the past 35 days,
  this is a finding.

  Inactive accounts that have been reviewed and deemed to be required must be
  documented with the ISSO."
  desc "fix", "Regularly review accounts to determine if they are still active.
  Remove or disable accounts that have not been used in the last 35 days."
  
  domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip
  
  if domain_role == '4' || domain_role == '5'
    user_query = "Search-ADAccount -AccountInactive -UsersOnly -TimeSpan 35.00:00:00 | Where-Object { ($_.SID -notlike '*500') -and ($_.SID -notlike '*501') -and ($_.SID -notlike '*503')  -and ($_.Enabled -eq $true) } | Select-Object @{Name=\"name\";Expression={$_.SamAccountName}}, @{Name=\"lastLogin\";Expression={$_.LastLogonDate}} | ConvertTo-Json"
  else
    user_query = <<-FOO
      $users = @() 
        ([ADSI]('WinNT://{0}' -f $env:COMPUTERNAME)).Children | Where {
        $_.SchemaClassName -eq 'user' } | ForEach {
        $user = ([ADSI]$_.Path)
        $lastLogin = $user.Properties.LastLogin.Value

        $enabled = ($user.Properties.UserFlags.Value -band 0x2) -ne 0x2
        if ($lastLogin -eq $null) {
        $lastLogin = 'Never'
        }
        else {
        $today = Get-Date
        $diff = New-TimeSpan -Start "$lastLogin" -End $today
        $lastLogin = $diff.Days
        }

        $sid = Get-LocalUser -Name $user.Name.Value | foreach { $_.SID.Value }

        if (($enabled -eq 'True') -and ($sid -notlike '*500') -and ($sid -notlike '*501')) {
          $users += (@{ name = $user.Name.Value; lastLogin = $lastLogin; enabled = $enabled; sid= $sid})
        }
        }
      $users | ConvertTo-Json
      FOO
  end

  users = json(command: user_query).params
  
  if users.empty?
    impact 0.0
    describe 'The system does not have any inactive accounts, control is NA' do
      skip 'The system does not have any inactive accounts, controls is NA'
    end
  else
    if users.is_a?(Hash)
      users = [JSON.parse(users.to_json)]        
    end
    users.each do |account|
      describe "Last login for user: #{account['name']}" do
        subject { account['lastLogin'] }
        it "should not be nil" do
          expect(subject).not_to(cmp nil)
        end
        subject { account['lastLogin'] }
        it "should not be more than 35 days" do
          expect(subject).to(be <= 35)
        end
      end
    end
  end
end