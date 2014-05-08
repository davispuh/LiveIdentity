class LiveIdentity
    module IDCRL
        module HRESULT
            # SUCCESS
            PPCRL_S_ALREADY_INITIALIZED                             = 0x00048044
            PPCRL_S_STILL_INUSE                                     = 0x00048045
            PPCRL_S_NO_MORE_IDENTITIES                              = 0x00048860
            PPCRL_S_TOKEN_TYPE_DOES_NOT_SUPPORT_SESSION_KEY         = 0x00048861
            PPCRL_S_NO_SUCH_CREDENTIAL                              = 0x00048862
            PPCRL_REQUEST_S_IO_PENDING                              = 0x00048847
            # ERRORS
            PP_E_CRL_NOT_INITIALIZED                                = 0x80048008
            PPCRL_NO_SESSION_KEY                                    = 0x8004800E
            PPCRL_HRESULT_BASE                                      = 0x80048800
            PPCRL_AUTHSTATE_E_UNAUTHENTICATED                       = 0x80048800
            PPCRL_AUTHSTATE_E_EXPIRED                               = 0x80048801
            PPCRL_AUTHREQUIRED_E_PASSWORD                           = 0x80048810
            PPCRL_AUTHREQUIRED_E_UNKNOWN                            = 0x80048814
            PPCRL_REQUEST_E_AUTH_SERVER_ERROR                       = 0x80048820
            PPCRL_REQUEST_E_BAD_MEMBER_NAME_OR_PASSWORD             = 0x80048821
            PPCRL_REQUEST_E_PASSWORD_LOCKED_OUT                     = 0x80048823
            PPCRL_REQUEST_E_PASSWORD_LOCKED_OUT_BAD_PASSWORD_OR_HIP = 0x80048824
            PPCRL_REQUEST_E_TOU_CONSENT_REQUIRED                    = 0x80048825
            PPCRL_REQUEST_E_FORCE_RENAME_REQUIRED                   = 0x80048826
            PPCRL_REQUEST_E_FORCE_CHANGE_PASSWORD_REQUIRED          = 0x80048827
            PPCRL_REQUEST_E_PARTNER_NOT_FOUND                       = 0x8004882A
            PPCRL_REQUEST_E_INVALID_POLICY                          = 0x8004882C
            PPCRL_REQUEST_E_INVALID_MEMBER_NAME                     = 0x8004882D
            PPCRL_REQUEST_E_MISSING_PRIMARY_CREDENTIAL              = 0x8004882E
            PPCRL_REQUEST_E_PENDING_NETWORK_REQUEST                 = 0x8004882F
            PPCRL_REQUEST_E_PASSWORD_EXPIRED                        = 0x80048831
            PPCRL_E_INITIALIZED_DIFF_ENVIRONMENT                    = 0x80048046
            PPCRL_REQUEST_E_NO_NETWORK                              = 0x80048848
            PPCRL_REQUESTPARAMS_MISSING                             = 0x80048852
            PPCRL_E_IDENTITY_NOT_AUTHENTICATED                      = 0x80048861
            PPCRL_E_UNABLE_TO_RETRIEVE_SERVICE_TOKEN                = 0x80048862
            PPCRL_E_AUTH_SERVICE_UNAVAILABLE                        = 0x80048869
            PPCRL_E_INVALID_AUTH_SERVICE_RESPONSE                   = 0x8004886A
            PPCRL_E_INVALIDFLAGS                                    = 0x8004886F
            PPCRL_E_BUSY                                            = 0x80048882
            PPCRL_E_NO_UI                                           = 0x8004889C
            PPCRL_E_REALM_LOOKUP                                    = 0x80048895
            PPCRL_E_NOT_UI_ERROR                                    = 0x8004889F
            PPCRL_REQUEST_E_PARTNER_INVALID_REQUEST                 = 0x800488D6
            PPCRL_REQUEST_E_PARTNER_REQUEST_FAILED                  = 0x800488D7
            PPCRL_REQUEST_E_PARTNER_INVALID_SECURITY_TOKEN          = 0x800488D8
            PPCRL_REQUEST_E_PARTNER_AUTHENTICATION_BAD_ELEMENTS     = 0x800488D9
            PPCRL_REQUEST_E_PARTNER_BAD_REQUEST                     = 0x800488DA
            PPCRL_REQUEST_E_PARTNER_EXPIRED_DATA                    = 0x800488DB
            PPCRL_REQUEST_E_PARTNER_INVALID_TIME_RANGE              = 0x800488DC
            PPCRL_REQUEST_E_PARTNER_INVALID_SCOPE                   = 0x800488DD
            PPCRL_REQUEST_E_PARTNER_RENEW_NEEDED                    = 0x800488DE
            PPCRL_REQUEST_E_PARTNER_UNABLE_TO_RENEW                 = 0x800488DF
            PPCRL_REQUEST_E_CANCELLED                               = 0x800488E2
            PPCRL_REQUEST_E_FORCE_SIGNIN                            = 0x800488E5
        end
    end
end