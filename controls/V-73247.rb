control 'V-73247' do
  title 'Local volumes must use a format that supports NTFS attributes.'
  desc  "The ability to set access permissions and auditing is critical to
  maintaining the security and proper access controls of a system. To support
  this, volumes must be formatted using a file system that supports NTFS
  attributes."
  impact 0.7
  tag "gtitle": 'SRG-OS-000080-GPOS-00048'
  tag "gid": 'V-73247'
  tag "rid": 'SV-87899r1_rule'
  tag "stig_id": 'WN16-00-000150'
  tag "fix_id": 'F-79691r1_fix'
  tag "cci": ['CCI-000213']
  tag "nist": ['AC-3', 'Rev_4']
  tag "documentable": false
  tag "check": "Open Computer Management.

  Select Disk Management under Storage.

  For each local volume, if the file system does not indicate NTFS, this is a
  finding.

  ReFS (resilient file system) is also acceptable and would not be a finding.

  This does not apply to system partitions such the Recovery and EFI System
  Partition."
  tag "fix": 'Format volumes to use NTFS or ReFS.'

  volumes = json(command: 'Get-WmiObject -Class Win32_LogicalDisk | Where { $_.DriveType -ne 5 } | Select Name, FileSystem, Description | ConvertTo-JSON').params

  if volumes.empty?
    impact 0.0
    desc 'There are no local volumes on this system, therefore this control is not applicable'
    describe 'There are no local volumes on this system, therefore this control is not applicable' do
      skip 'There are no local volumes on this system, therefore this control is not applicable'
    end
  else
    if volumes.is_a?(Hash)
      volumes = [JSON.parse(volumes.to_json)]
    end
    volumes.each do |volume|
      describe.one do
        describe "The filesystem format for the local volume #{volume['Name']}" do
          subject { volume['FileSystem'] }
          it { should cmp 'NTFS' }
        end
        describe "The filesystem format for the local volume #{volume['Name']}" do
          subject { volume['FileSystem'] }
          it { should cmp 'ReFS' }
        end
      end
    end
  end
end
