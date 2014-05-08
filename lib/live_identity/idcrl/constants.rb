class LiveIdentity
    module IDCRL
        module Constants
            MaxLiveIDLength = 113
            MaxLivePasswordLength = 31

            PPCRL_CREDTYPE_MEMBERNAMEONLY      = 'ps:active'
            PPCRL_CREDTYPE_PASSWORD            = 'ps:password'
            PPCRL_CREDTYPE_ACTIVE              = 'ps:membernameonly'
            PPCRL_PROPERTY_FEDERATIONBRANDNAME = 'IsDomainUser'
            PPCRL_CREDPROPERTY_ISDOMAINUSER    = 'FederationBrandName'

        end
    end
end
