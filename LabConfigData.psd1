@{
    ResoruceGroupNameParameter = @( 
        @{ 
            ResourceGroupName = "Default" 
            VirtualNetworkName = "default"
            SubnetName = ""
            VmBaseName = ""
            DomainName = "teppeiy.local"
            ClientPcOuPath = "OU=Clients,DC=teppeiy,DC=local"
        }, 
        @{
            ResourceGroupName = "lab1" 
            DefaultVirtualNetworkName     = "default"
            DefaultSubnetName = ""
            DefaultVmBaseName = ""
            DomainName = ""
            OuPath = ""
        }
    )
    Common = @{
        ArmTemplatePath = ""
    }
}