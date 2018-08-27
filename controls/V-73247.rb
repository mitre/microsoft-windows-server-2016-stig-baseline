control "V-73247" do
  title "Local volumes must use a format that supports NTFS attributes."
  desc  "The ability to set access permissions and auditing is critical to
  maintaining the security and proper access controls of a system. To support
  this, volumes must be formatted using a file system that supports NTFS
  attributes."
  impact 0.7
  tag "gtitle": "SRG-OS-000080-GPOS-00048"
  tag "gid": "V-73247"
  tag "rid": "SV-87899r1_rule"
  tag "stig_id": "WN16-00-000150"
  tag "fix_id": "F-79691r1_fix"
  tag "cci": ["CCI-000213"]
  tag "nist": ["AC-3", "Rev_4"]
  tag "documentable": false
  tag "check": "Open \"Computer Management\".

  Select \"Disk Management\" under \"Storage\".

  For each local volume, if the file system does not indicate \"NTFS\", this is a
  finding.

  \"ReFS\" (resilient file system) is also acceptable and would not be a finding.

  This does not apply to system partitions such the Recovery and EFI System
  Partition."
  tag "fix": "Format volumes to use NTFS or ReFS."
  get_volumes = command("wmic logicaldisk list /format:list | Findstr FileSystem=").stdout.strip.split("\n")
  
  get_volumes.each do |volume|
      describe.one do
      describe "#{volume}" do
        it { should eq "FileSystem=NTFS\r"}
      end  
      describe "#{volume}" do
        it { should eq "FileSystem=ReFS\r"}
      end
    end
  end
end

