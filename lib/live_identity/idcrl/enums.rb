class LiveIdentity
    module IDCRL
        module Enums
            def self.included(base)

                base.const_set(:UPDATE_FLAG, base.enum(
                :DEFAULT_UPDATE_POLICY,      0x00000000,
                :UPDATE_DEFAULT,             0x00000000,
                :OFFLINE_MODE_ALLOWED,       0x00000001,
                :NO_UI,                      0x00000002,
                :SKIP_CONNECTION_CHECK,      0x00000004,
                :SET_EXTENDED_ERROR,         0x00000008,
                :SET_INITIALIZATION_COOKIES, 0x00000010,
                :UPDATE_FLAG_ALL_BIT,        0x0000001F))

                base.const_set(:WLIDUI_FLAG, base.enum(
                :WLIDUI_DEFAULT,               0x0000,
                :WLIDUI_DISABLE_REMEBERME,     0x0001,
                :WLIDUI_DISABLE_SAVEPASSWORD,  0x0002,
                :WLIDUI_DISABLE_DIFFERENTUSER, 0x0004,
                :WLIDUI_DISABLE_EID,           0x0020,
                :WLIDUI_DISABLE_SIGNUPLINK,    0x0040,
                :WLIDUI_DISABLE_SAVEDUSERS,    0x0080,
                :WLIDUI_FORCE_SAVEPASSWORD,    0x0100,
                :WLIDUI_FORCE_SMARTCARD,       0x0200,
                :WLIDUI_ALL_BIT,               0x03FF))

                base.const_set(:SERVICETOKENFLAGS, base.enum(
                :SERVICE_TOKEN_TYPE_LEGACY_PASSPORT,       0x00000001,
                :SERVICE_TOKEN_TYPE_WEBSSO,                0x00000002,
                :SERVICE_TOKEN_TYPE_SAML,                  0x00000002,
                :SERVICE_TOKEN_TYPE_COMPACT_WEBSSO,        0x00000004,
                :SERVICE_TOKEN_TYPE_X509V3,                0x00000008,
                :SERVICE_TOKEN_CERT_IN_MEMORY_PRIVATE_KEY, 0x00000010,
                :SERVICE_TOKEN_TYPE_ANY,                   0x000000FF,
                :SERVICE_TOKEN_FROM_CACHE,                 0x00010000))

                base.const_set(:IDCRL_OPTION_ID, base.enum(
                :IDCRL_OPTION_PROXY,            0x00000001,
                :IDCRL_OPTION_CONNECT_TIMEOUT,  0x00000002,
                :IDCRL_OPTION_SEND_TIMEOUT,     0x00000004,
                :IDCRL_OPTION_RECEIVE_TIMEOUT,  0x00000008,
                :IDCRL_OPTION_PROXY_PASSWORD,   0x00000010,
                :IDCRL_OPTION_PROXY_USERNAME,   0x00000020,
                :IDCRL_OPTION_ENVIRONMENT,      0x00000040,
                :IDCRL_OPTION_ALL_BIT,          0x0000007F,
                :IDCRL_OPTION_MSC_TIMEOUT,      0x00000080))

                base.const_set(:IDCRL_DEVICE_CONSENT_OPTIONS, base.enum(
                :IDCRL_DEVICE_ID_CONSENT_MIN,    0,
                :IDCRL_DEVICE_ID_CONSENT_GRANT,  1,
                :IDCRL_DEVICE_ID_CONSENT_REVOKE, 2,
                :IDCRL_DEVICE_ID_CONSENT_REMOVE, 3,
                :IDCRL_DEVICE_ID_CONSENT_MAX,    4))

                base.const_set(:IDCRL_DEVICE_ID_OPTIONS, base.enum(
                :IDCRL_DEVICE_ID_PHYSICAL,    0x0008,
                :IDCRL_DEVICE_ID_FROMCACHE,   0x0010,
                :IDCRL_DEVICE_ID_ACCESSCHECK, 0x0020,
                :IDCRL_DEVICE_ID_NO_SIGNUP,   0x0100,
                :IDCRL_DEVICE_ID_RENEW_CERT,  0x0200))

                base.const_set(:LOGON_FLAG, base.enum(
                :LOGONIDENTITY_DEFAULT,                  0x0000,
                :LOGONIDENTITY_ALLOW_OFFLINE,            0x0001,
                :LOGONIDENTITY_FORCE_OFFLINE,            0x0002,
                :LOGONIDENTITY_CREATE_OFFLINE_HASH,      0x0004,
                :LOGONIDENTITY_ALLOW_PERSISTENT_COOKIES, 0x0008,
                :LOGONIDENTITY_USE_EID_AUTH,             0x0010,
                :LOGONIDENTITY_USE_LINKED_ACCOUNTS,      0x0020,
                :LOGONIDENTITY_FEDERATED,                0x0040,
                :LOGONIDENTITY_WLID,                     0x0080,
                :LOGONIDENTITY_AUTO_PARTNER_REDIRECT,    0x0100,
                :LOGONIDENTITY_IGNORE_CACHED_TOKENS,     0x0200,
                :LOGONIDENTITY_RESERVED_1,               0x0400,
                :LOGONIDENTITY_ALL_BIT,                  0x07FF,
                :LOGONIDENTITY_USE_SINGLEUSECODE,        0x0800))

                base.const_set(:IDCRL_ERROR_CATEGORY, base.enum(
                :IDCRL_UNKNOWN_ERROR_CATEGORY,       0x00000000,
                :IDCRL_REQUEST_BUILD_ERROR,          0x00000001,
                :IDCRL_REQUEST_SEND_ERROR,           0x00000002,
                :IDCRL_RESPONSE_RECEIVE_ERROR,       0x00000003,
                :IDCRL_RESPONSE_READ_ERROR,          0x00000004,
                :IDCRL_REPSONSE_PARSE_ERROR,         0x00000005,
                :IDCRL_RESPONSE_SIG_DECRYPT_ERROR,   0x00000006,
                :IDCRL_RESPONSE_PARSE_HEADER_ERROR,  0x00000007,
                :IDCRL_RESPONSE_PARSE_TOKEN_ERROR,   0x00000008,
                :IDCRL_RESPONSE_PUTCERT_ERROR,       0x00000009))

                base.const_set(:PASSPORTIDENTITYPROPERTY, base.enum(
                :IDENTITY_MEMBER_NAME, 1,
                :IDENTITY_PUIDSTR,     2))

                base.const_set(:SSO_FLAG, base.enum(
                :SSO_DEFAULT,         0x00,
                :SSO_NO_UI,           0x01,
                :SSO_NO_AUTO_SIGNIN,  0x02,
                :SSO_NO_HANDLE_ERROR, 0x04,
                :SSO_ALL_BIT,         0x0F))

                base.const_set(:IDCRL_SETOPTIONS_FLAG, base.enum(
                :IDCRL_SETOPTIONS_SET,     0x00,
                :IDCRL_SETOPTIONS_DEFAULT, 0x00,
                :IDCRL_SETOPTIONS_RESET,   0x01))

                base.const_set(:IDCRL_USER_DEVICE_ASSOCIATION_TYPE, base.enum(
                :IDCRL_USER_DEVICE_SYSTEM, 0,
                :IDCRL_USER_DEVICE_APP,    1))

                base.const_set(:CERTREQUESTFLAGS, base.enum(
                :CERT_FROM_CACHE,  0x00010000,
                :CERT_FROM_SERVER, 0x00020000))

                base.const_set(:IDENTITY_FLAG, base.enum(
                :IDENTITY_SHARE_ALL,                 0x000000FF,
                :IDENTITY_LOAD_FROM_PERSISTED_STORE, 0x00000100,
                :IDENTITY_AUTHSTATE_ENCRYPTED,       0x00000200,
                :IDENTITY_FAST_CLOSE,                0x00000400,
                :IDENTITY_DEVICEID_LOGICAL,          0x00001000,
                :IDENTITY_ALL_BIT,                   0x00001FFF))

                base.const_set(:IDCRL_WEBAUTHOPTION, base.enum(
                :IDCRL_WEBAUTH_NONE,       0,
                :IDCRL_WEBAUTH_REAUTH,     1,
                :IDCRL_WEBAUTH_PERSISTENT, 2))

                base.const_set(:SERVICETOKEN_REQUEST_FLAGS, base.enum(
                :SERVICE_TOKEN_REQUEST_TYPE_NONE,   0x00,
                :SERVICE_TOKEN_REQUEST_TYPE_X509V3, 0x08))

            end
        end
    end
end
