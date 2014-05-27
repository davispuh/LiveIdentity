class LiveIdentity
    module IDCRL
        module HRESULT
            PP_E_CRL_NOT_INITIALIZED                                = 0x80048008
            PPCRL_NO_SESSION_KEY                                    = 0x8004800E
            PPCRL_S_ALREADY_INITIALIZED                             = 0x00048044
            PPCRL_S_STILL_INUSE                                     = 0x00048045
            PP_E_CRL_REG_OPEN_FAILED                                = 0x80048251
            PP_E_NOTCONNECTED                                       = 0x80048265
            PPCRL_E_SQM_UNKNOWN                                     = 0x80048401
            PPCRL_E_SQM_REQUEST_CANCELLED                           = 0x80048402
            PPCRL_E_SQM_QUERY_STATUSCODE                            = 0x80048403
            PPCRL_E_SQM_OUTOFMEMORY                                 = 0x80048404
            PPCRL_E_SQM_READRESPONSE                                = 0x80048405
            PPCRL_E_SQM_RESPONSE_BADXML                             = 0x80048406
            PPCRL_E_SQM_INTERNET_OTHER                              = 0x80048407
            PPCRL_E_SQM_INTERNET_UI                                 = 0x80048408
            PPCRL_E_SQM_INTERNET_SYNTAX                             = 0x80048409
            PPCRL_E_SQM_INTERNET_NAME_NOT_RESOLVED                  = 0x8004840A
            PPCRL_E_SQM_INTERNET_LOGIN                              = 0x8004840B
            PPCRL_E_SQM_INTERNET_PROXY                              = 0x8004840C
            PPCRL_E_SQM_INTERNET_OPERATION_CANCELLED                = 0x8004840D
            PPCRL_E_SQM_INTERNET_INCORRECT_HANDLE_STATE             = 0x8004840E
            PPCRL_E_SQM_INTERNET_CANNOT_CONNECT                     = 0x8004840F
            PPCRL_E_SQM_INTERNET_CONNECTION_ABORTED                 = 0x80048410
            PPCRL_E_SQM_INTERNET_CONNECTION_RESET                   = 0x80048411
            PPCRL_E_SQM_INTERNET_SEC_CERT_DATE_INVALID              = 0x80048412
            PPCRL_E_SQM_INTERNET_SEC_CERT_CN_INVALID                = 0x80048413
            PPCRL_E_SQM_INTERNET_SEC_CERT_ERRORS                    = 0x80048414
            PPCRL_E_SQM_INTERNET_SEC_CERT_NO_REV                    = 0x80048415
            PPCRL_E_SQM_INTERNET_SEC_CERT_REV_FAILED                = 0x80048416
            PPCRL_E_SQM_INTERNET_CLIENT_AUTH_CERT_NEEDED            = 0x80048417
            PPCRL_E_SQM_INTERNET_INVALID_CA                         = 0x80048418
            PPCRL_E_SQM_INTERNET_SECURITY_WARNING                   = 0x80048419
            PPCRL_E_SQM_INTERNET_POST_IS_NON_SECURE                 = 0x8004841A
            PPCRL_E_SQM_FTP                                         = 0x8004841B
            PPCRL_E_SQM_GOPHER                                      = 0x8004841C
            PPCRL_E_SQM_HTTP_HEADER                                 = 0x8004841D
            PPCRL_E_SQM_HTTP_DOWNLEVEL_SERVER                       = 0x8004841E
            PPCRL_E_SQM_HTTP_INVALID_SERVER_RESPONSE                = 0x8004841F
            PPCRL_E_SQM_HTTP_INVALID_QUERY_REQUEST                  = 0x80048420
            PPCRL_E_SQM_HTTP_REDIRECT                               = 0x80048421
            PPCRL_E_SQM_HTTP_COOKIE                                 = 0x80048422
            PPCRL_E_SQM_INTERNET_SECURITY_CHANNEL_ERROR             = 0x80048423
            PPCRL_E_SQM_INTERNET_DISCONNECTED                       = 0x80048424
            PPCRL_E_SQM_INTERNET_SERVER_UNREACHABLE                 = 0x80048425
            PPCRL_E_SQM_INTERNET_PROXY_SERVER_UNREACHABLE           = 0x80048426
            PPCRL_E_SQM_INTERNET_PROXYSCRIPT                        = 0x80048427
            PPCRL_E_SQM_INTERNET_SEC_INVALID_CERT                   = 0x80048428
            PPCRL_E_SQM_INTERNET_SEC_CERT_REVOKED                   = 0x80048429
            PPCRL_E_SQM_INTERNET_AUTODIAL                           = 0x8004842A
            PPCRL_E_SQM_INTERNET_NOT_INITIALIZED                    = 0x8004842B
            PPCRL_E_SQM_LOCK                                        = 0x8004842C
            PPCRL_E_SQM_SYNC_NOLOCK                                 = 0x8004842D
            PPCRL_E_SQM_HTTP_QUERYINFO                              = 0x8004842E
            PPCRL_E_SQM_RESPONSE_TOO_LARGE                          = 0x8004842F
            PPCRL_E_SQM_INVALID_AUTH_SERVICE_RESPONSE               = 0x80048430
            PPCRL_E_SQM_NO_TOKENBAG                                 = 0x80048431
            PPCRL_E_SQM_RESPONSE_NOTIMESTAMPORRSTR                  = 0x80048432
            PPCRL_E_SQM_RESPONSE_NOSIGNATUREELEMENT                 = 0x80048433
            PPCRL_E_SQM_RESPONSE_NOCIPHERELEMENT                    = 0x80048434
            PPCRL_E_SQM_REQUEST_E_RSTR_MISSING_REFERENCE_URI        = 0x80048435
            PPCRL_E_SQM_REQUEST_E_RSTR_MISSING_REFERENCED_TOKEN     = 0x80048436
            PPCRL_E_SQM_WAIT_ABANDONED                              = 0x80048437
            PPCRL_E_SQM_WAIT_TIMEOUT                                = 0x80048438
            PPCRL_E_SQM_INTERNET_TIMEOUT                            = 0x80048439
            PPCRL_HRESULT_BASE_SUCCESS                              = 0x00048800
            PPCRL_HRESULT_BASE_ERROR                                = 0x80048800
            PPCRL_AUTHSTATE_E_UNAUTHENTICATED                       = 0x80048800
            PPCRL_AUTHSTATE_E_EXPIRED                               = 0x80048801
            PPCRL_AUTHSTATE_S_AUTHENTICATED_OFFLINE                 = 0x00048802
            PPCRL_AUTHSTATE_S_AUTHENTICATED_PASSWORD                = 0x00048803
            PPCRL_AUTHSTATE_S_AUTHENTICATED_PARTNER                 = 0x00048804
            PPCRL_AUTHREQUIRED_E_PASSWORD                           = 0x80048810
            PPCRL_AUTHREQUIRED_E_CERTIFICATE                        = 0x80048813
            PPCRL_AUTHREQUIRED_E_UNKNOWN                            = 0x80048814
            PPCRL_REQUEST_E_AUTH_SERVER_ERROR                       = 0x80048820
            PPCRL_REQUEST_E_BAD_MEMBER_NAME_OR_PASSWORD             = 0x80048821
            PPCRL_REQUEST_E_PASSWORD_LOCKED_OUT                     = 0x80048823
            PPCRL_REQUEST_E_PASSWORD_LOCKED_OUT_BAD_PASSWORD_OR_HIP = 0x80048824
            PPCRL_REQUEST_E_TOU_CONSENT_REQUIRED                    = 0x80048825
            PPCRL_REQUEST_E_FORCE_RENAME_REQUIRED                   = 0x80048826
            PPCRL_REQUEST_E_FORCE_CHANGE_PASSWORD_REQUIRED          = 0x80048827
            PPCRL_REQUEST_E_STRONG_PASSWORD_REQUIRED                = 0x80048828
            PPCRL_REQUEST_E_NO_CERTIFICATES_AVAILABLE               = 0x80048829
            PPCRL_REQUEST_E_PARTNER_NOT_FOUND                       = 0x8004882A
            PPCRL_REQUEST_E_PARTNER_HAS_NO_ASYMMETRIC_KEY           = 0x8004882B
            PPCRL_REQUEST_E_INVALID_POLICY                          = 0x8004882C
            PPCRL_REQUEST_E_INVALID_MEMBER_NAME                     = 0x8004882D
            PPCRL_REQUEST_E_MISSING_PRIMARY_CREDENTIAL              = 0x8004882E
            PPCRL_REQUEST_E_PENDING_NETWORK_REQUEST                 = 0x8004882F
            PPCRL_REQUEST_E_FORCE_CHANGE_SQSA                       = 0x80048830
            PPCRL_REQUEST_E_PASSWORD_EXPIRED                        = 0x80048831
            PPCRL_REQUEST_E_PENDING_USER_INPUT                      = 0x80048832
            PPCRL_REQUEST_E_MISSING_HIP_SOLUTION                    = 0x80048833
            PPCRL_REQUEST_E_PROFILE_ACCRUE_REQUIRED                 = 0x80048834
            PPCRL_REQUEST_S_PROFILE_ACCRUE_DONE                     = 0x00048835
            PPCRL_REQUEST_E_EMAIL_VALIDATION_REQUIRED               = 0x80048836
            PPCRL_REQUEST_E_PARTNER_NEED_STRONGPW                   = 0x80048837
            PPCRL_REQUEST_E_PARTNER_NEED_STRONGPW_EXPIRY            = 0x80048838
            PPCRL_REQUEST_E_AUTH_EXPIRED                            = 0x80048839
            PPCRL_REQUEST_E_USER_FORGOT_PASSWORD                    = 0x80048841
            PPCRL_REQUEST_E_USER_CANCELED                           = 0x80048842
            PPCRL_E_INITIALIZED_DIFF_ENVIRONMENT                    = 0x80048046
            PPCRL_REQUEST_S_IO_PENDING                              = 0x00048847
            PPCRL_REQUEST_E_NO_NETWORK                              = 0x80048848
            PPCRL_REQUEST_E_UNKNOWN                                 = 0x80048849
            PPCRL_REQUESTPARAMS_MISSING                             = 0x80048852
            PPCRL_REQUEST_E_WRONG_DA                                = 0x80048852
            PPCRL_REQUEST_E_KID_HAS_NO_CONSENT                      = 0x80048853
            PPCRL_REQUEST_E_RSTR_MISSING_REFERENCE_URI              = 0x80048854
            PPCRL_REQUEST_E_RSTR_FAULT                              = 0x80048855
            PPCRL_REQUEST_E_RSTR_MISSING_REFERENCED_TOKEN           = 0x80048856
            PPCRL_REQUEST_E_RSTR_MISSING_BASE64CERT                 = 0x80048857
            PPCRL_REQUEST_E_RSTR_MISSING_TOKENTYPE                  = 0x80048858
            PPCRL_REQUEST_E_RSTR_MISSING_SERVICENAME                = 0x80048859
            PPCRL_REQUEST_E_RSTR_INVALID_TOKENTYPE                  = 0x8004885A
            PPCRL_REQUEST_E_RSTR_MISSING_PRIVATE_KEY                = 0x8004885B
            PPCRL_REQUEST_E_INVALID_SERVICE_TIMESTAMP               = 0x8004885C
            PPCRL_REQUEST_E_INVALID_PKCS10_TIMESTAMP                = 0x8004885D
            PPCRL_REQUEST_E_INVALID_PKCS10                          = 0x8004885E
            PPCRL_S_NO_MORE_IDENTITIES                              = 0x00048860
            PPCRL_S_TOKEN_TYPE_DOES_NOT_SUPPORT_SESSION_KEY         = 0x00048861
            PPCRL_E_IDENTITY_NOT_AUTHENTICATED                      = 0x80048861
            PPCRL_S_NO_SUCH_CREDENTIAL                              = 0x00048862
            PPCRL_E_UNABLE_TO_RETRIEVE_SERVICE_TOKEN                = 0x80048862
            PPCRL_S_NO_AUTHENTICATION_REQUIRED                      = 0x00048863
            PPCRL_E_INVALID_DERIVATION_METHOD                       = 0x80048863
            PPCRL_E_INVALID_DERIVATION_PARAMS                       = 0x80048864
            PPCRL_E_INVALID_DERIVATION_ITERATIONS_PARAM             = 0x80048865
            PPCRL_E_INVALID_DERIVATION_SALT_PARAM                   = 0x80048866
            PPCRL_E_INVALID_DERIVED_KEY_LENGTH                      = 0x80048867
            PPCRL_E_CERTIFICATE_AUTHENTICATION_NOT_SUPPORTED        = 0x80048868
            PPCRL_E_AUTH_SERVICE_UNAVAILABLE                        = 0x80048869
            PPCRL_E_INVALID_AUTH_SERVICE_RESPONSE                   = 0x8004886A
            PPCRL_E_UNABLE_TO_INITIALIZE_CRYPTO_PROVIDER            = 0x8004886B
            PPCRL_E_NO_MEMBER_NAME_SET                              = 0x8004886C
            PPCRL_E_CALLBACK_REQUIRED                               = 0x8004886D
            PPCRL_E_DISCONTINUE_AUTHENTICATION                      = 0x8004886E
            PPCRL_E_INVALIDFLAGS                                    = 0x8004886F
            PPCRL_E_UNABLE_TO_RETRIEVE_CERT                         = 0x80048870
            PPCRL_E_INVALID_RSTPARAMS                               = 0x80048871
            PPCRL_E_MISSING_FILE                                    = 0x80048872
            PPCRL_E_ILLEGAL_LOGONIDENTITY_FLAG                      = 0x80048873
            PPCRL_E_CERT_NOT_VALID_FOR_MINTTL                       = 0x80048874
            PPCRL_S_OK_CLIENTTIME                                   = 0x00048875
            PPCRL_E_CERT_INVALID_ISSUER                             = 0x80048876
            PPCRL_E_NO_CERTSTORE_FOR_ISSUERS                        = 0x80048877
            PPCRL_E_OFFLINE_AUTH                                    = 0x80048878
            PPCRL_E_SIGN_POP_FAILED                                 = 0x80048879
            PPCRL_E_CERT_INVALID_POP                                = 0x80048880
            PPCRL_E_CALLER_NOT_SIGNED                               = 0x80048881
            PPCRL_E_BUSY                                            = 0x80048882
            PPCRL_E_DOWNLOAD_FILE_FAILED                            = 0x80048883
            PPCRL_E_BUILD_CERT_REQUEST_FAILED                       = 0x80048884
            PPCRL_E_CERTIFICATE_NOT_FOUND                           = 0x80048885
            PPCRL_E_AUTHBLOB_TOO_LARGE                              = 0x80048886
            PPCRL_E_AUTHBLOB_NOT_FOUND                              = 0x80048887
            PPCRL_E_AUTHBLOB_INVALID                                = 0x80048888
            PPCRL_E_EXTPROP_NOTFOUND                                = 0x80048889
            PPCRL_E_RESPONSE_TOO_LARGE                              = 0x8004888A
            PPCRL_E_USER_NOTFOUND                                   = 0x8004888C
            PPCRL_E_SIGCHECK_FAILED                                 = 0x8004888D
            PPCRL_E_CREDTARGETNAME_INVALID                          = 0x8004888F
            PPCRL_E_CREDINFO_CORRUPTED                              = 0x80048890
            PPCRL_E_CREDPROP_NOTFOUND                               = 0x80048891
            PPCRL_E_NO_LINKEDACCOUNTS                               = 0x80048892
            PPCRL_E_NO_LINKEDHANDLE                                 = 0x80048893
            PPCRL_E_CERT_CA_ROLLOVER                                = 0x80048894
            PPCRL_E_REALM_LOOKUP                                    = 0x80048895
            PPCRL_E_FORBIDDEN_NAMESPACE                             = 0x80048897
            PPCRL_E_IDENTITY_NOCID                                  = 0x80048899
            PPCRL_E_IE_MISCONFIGURED                                = 0x8004889A
            PPCRL_E_NO_UI                                           = 0x8004889C
            PPCRL_E_INVALID_RPS_TOKEN                               = 0x8004889E
            PPCRL_E_NOT_UI_ERROR                                    = 0x8004889F
            PPCRL_E_INVALID_URL                                     = 0x800488A0
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
            PPCRL_REQUEST_E_MISSING_HASHED_PASSWORD                 = 0x800488E0
            PPCRL_REQUEST_E_CLIENT_DEPRECATED                       = 0x800488E1
            PPCRL_REQUEST_E_CANCELLED                               = 0x800488E2
            PPCRL_REQUEST_E_INVALID_PKCS10_KEYLEN                   = 0x800488E3
            PPCRL_REQUEST_E_DUPLICATE_SERVICETARGET                 = 0x800488E4
            PPCRL_REQUEST_E_FORCE_SIGNIN                            = 0x800488E5
            PPCRL_REQUEST_E_PARTNER_NEED_CERTIFICATE                = 0x800488E6
            PPCRL_REQUEST_E_PARTNER_NEED_PIN                        = 0x800488E7
            PPCRL_REQUEST_E_PARTNER_NEED_PASSWORD                   = 0x800488E8
            PPCRL_REQUEST_S_OK_NO_SLC                               = 0x000488E9
            PPCRL_REQUEST_S_IO_PENDING_NO_SLC                       = 0x000488EA
            PPCRL_REQUEST_E_SCHANNEL_ERROR                          = 0x800488EB
            PPCRL_REQUEST_E_CERT_PARSE_ERROR                        = 0x800488EC
            PPCRL_REQUEST_E_PARTNER_SERVER_ERROR                    = 0x800488ED
            PPCRL_REQUEST_E_PARTNER_LOGIN                           = 0x800488EE
            PPCRL_REQUEST_E_FLOWDISABLED                            = 0x800488EF
            PPCRL_REQUEST_E_USER_NOT_LINKED                         = 0x800488F0
            PPCRL_REQUEST_E_ACCOUNT_CONVERSION_NEEDED               = 0x800488F1
            PPCRL_REQUEST_E_PARTNER_BAD_MEMBER_NAME_OR_PASSWORD     = 0x800488F2
            PPCRL_REQUEST_E_BAD_MEMBER_NAME_OR_PASSWORD_FED         = 0x800488F3
            PPCRL_REQUEST_E_HIP_ON_FIRST_LOGIN                      = 0x800488F4
            PPCRL_REQUEST_E_INVALID_CARDSPACE_TOKEN                 = 0x800488F5
        end
    end
end