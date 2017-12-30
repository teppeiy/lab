Configuration DSCBlockTest
{
    Import-DSCResource -ModuleName xNetworking
    Node "localhost"
    {
        xFirewall FwInboundHTTP {
            Name        = 'Allow Inbound HTTP/S'
            DisplayName = 'Allow Inbound HTTP/S'
            Group       = 'WAP'
            Ensure      = 'Present'
            Enabled     = 'True'
            Profile     = ('Domain', 'Private', 'Public')
            Direction   = 'InBound'
            RemotePort  = ('80', '443')
            LocalPort   = ('80', '443')
            Protocol    = 'TCP'
            Description = 'Firewall Rule for WAP'
            Service     = 'HTTP'
        }
    }
}

$outputPath = "C:\DSC\DSCBlockTest"
DSCBlockTest -OutputPath $outputPath 

Start-DscConfiguration -Path $outputPath -Wait -Verbose
