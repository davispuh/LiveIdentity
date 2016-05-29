require 'ffi'
require 'win_common/typedefs'
require 'win_common/structs_ffi'
require 'win_common/crypt/structs'

require_relative 'idcrl/constants'
require_relative 'idcrl/enums'
require_relative 'idcrl/hresult'

def getStringLength(data)
    length = 0
    count = 0
    offset = 0
    previous = nil
    while count < 2
        data.get_bytes(offset, 100).each_byte do |byte|
            length = length + 1
            count = count + 1 if byte.zero? and previous.zero?
            previous = byte
            return length - 2 if count >= 2
        end
        offset += 100
        break if offset >= 100000
    end
    length
end

def StringToWSTR(str, encoding = 'UTF-16LE')
    [str.encode('UTF-16LE')].pack('a*xx')
end

def read_wide_string(data, encoding = 'UTF-16LE')
    data.read_bytes(getStringLength(data)).force_encoding(encoding).encode('UTF-8')
end

module WinCommon::Errors::HRESULT
    include LiveIdentity::IDCRL::HRESULT
end

class LiveIdentity
    include IDCRL::Constants
    module IDCRL

        extend FFI::Library

        include WinCommon::Structs
        include WinCommon::Crypt::Structs
        include Enums

        if defined?(WinCommon::Functions)
            IsWin8 = WinCommon::Functions::IsWindows8OrGreater?
            if not defined?(LibIDCRL)
                #if IsWin8
                  LibIDCRL = 'msidcrl40'
                #else
                #    LibIDCRL = 'msidcrl30'
                #end
            end

            # http://msdn.microsoft.com/en-us/library/hh472108.aspx
            ffi_lib LibIDCRL
            ffi_convention :stdcall

            require_relative 'idcrl/structs'
            include Structs

            FFI::typedef :pointer, :PassportIdentityHandlePointer
            FFI::typedef :size_t,  :PassportIdentityHandle
            FFI::typedef :pointer, :PassportEnumIdentitiesHandlePointer
            FFI::typedef :size_t,  :PassportEnumIdentitiesHandle
            FFI::typedef :pointer, :PassportUIAuthContextHandlePointer
            FFI::typedef :size_t,  :PassportUIAuthContextHandle
            FFI::typedef :pointer, :PIDCRL_OPTION
            FFI::typedef :pointer, :PCRSTParams

            callback :cbIdentityChangedCallback,  [:PassportIdentityHandle, :LPVOID, :BOOL], :HRESULT
            callback :cbUserStateChangedCallback, [:DWORD, :LPVOID ], :VOID

            attach_function :Initialize,                              [ :REFGUID, :LONG, UPDATE_FLAG ], :HRESULT
            attach_function :Uninitialize,                            [],  :HRESULT
            attach_function :PassportFreeMemory,                      [ :LPVOID ], :HRESULT
            attach_function :CreateIdentityHandle,                    [ :LPCWSTR, IDENTITY_FLAG, :PassportIdentityHandlePointer ], :HRESULT
            attach_function :SetCredential,                           [ :PassportIdentityHandle, :LPCWSTR, :LPCWSTR ], :HRESULT
            attach_function :GetIdentityProperty,                     [ :PassportIdentityHandle, PASSPORTIDENTITYPROPERTY, :PLPWSTR ], :HRESULT
            attach_function :SetIdentityProperty,                     [ :PassportIdentityHandle, PASSPORTIDENTITYPROPERTY, :LPCWSTR ], :HRESULT
            attach_function :CloseIdentityHandle,                     [ :PassportIdentityHandle ], :HRESULT
            if (LibIDCRL == 'msidcrl30')
                attach_function :CreatePassportAuthUIContext,             [ PassportCredUIInfo, PASSPORTCREDCUSTOMUI, :PassportUIAuthContextHandlePointer ], :HRESULT
                attach_function :GetPreferredAuthUIContextSize,           [ :PassportIdentityHandle, :PSIZE ], :HRESULT
                attach_function :MoveAuthUIContext,                       [ :PassportUIAuthContextHandle, POINT, SIZE ], :HRESULT
                attach_function :DestroyPassportAuthUIContext,            [ :PassportUIAuthContextHandle ], :HRESULT
            end
            attach_function :AuthIdentityToService,                   [ :PassportIdentityHandle, :LPCWSTR, :LPCWSTR, SERVICETOKENFLAGS, :PLPWSTR, :PDWORD, :PLPWSTR, :PDWORD ], :HRESULT
            attach_function :PersistCredential,                       [ :PassportIdentityHandle, :LPCWSTR ], :HRESULT
            attach_function :RemovePersistedCredential,               [ :PassportIdentityHandle, :LPCWSTR ], :HRESULT
            attach_function :EnumIdentitiesWithCachedCredentials,     [ :LPCWSTR, :PassportEnumIdentitiesHandlePointer ], :HRESULT
            attach_function :NextIdentity,                            [ :PassportEnumIdentitiesHandle, :PLPWSTR ], :HRESULT
            attach_function :CloseEnumIdentitiesHandle,               [ :PassportEnumIdentitiesHandle ], :HRESULT
            attach_function :GetAuthState,                            [ :PassportIdentityHandle, :PHRESULT, :PHRESULT, :PHRESULT, :LPWSTR ], :HRESULT
            attach_function :LogonIdentity,                           [ :PassportIdentityHandle, :LPCWSTR, LOGON_FLAG ], :HRESULT
            #if (LibIDCRL == 'msidcrl30')
            #    attach_function :LogonIdentityWithUI                      [ :PassportUIAuthContextHandle, LOGON_FLAG ], :HRESULT
            #elsif (LibIDCRL == '')
            #    attach_function :LogonIdentityWithUI                      [ :PassportUIAuthContextHandle, :PassportIdentityHandle, :LPCWSTR, LOGON_FLAG ], :HRESULT
            #end
            attach_function :HasPersistedCredential,                  [ :PassportIdentityHandle, :LPCWSTR, :PLONG ], :HRESULT
            attach_function :SetIdentityCallback,                     [ :PassportIdentityHandle, :cbIdentityChangedCallback, :LPVOID ], :HRESULT
            if (LibIDCRL == 'msidcrl30')
                attach_function :BuildAuthTokenRequest,                   [ :PassportIdentityHandle, :LPCWSTR, :DWORD, :PLPWSTR ], :HRESULT
                attach_function :BuildServiceTokenRequest,                [ :PassportIdentityHandle, :LPCWSTR, :LPCWSTR, :DWORD, :LPWSTR ], :HRESULT
                attach_function :PutTokenResponse,                        [ ], :HRESULT # TODO
            end
            attach_function :InitializeEx,                            [ :REFGUID, :LONG, UPDATE_FLAG, :PIDCRL_OPTION, :DWORD ], :HRESULT
            attach_function :GetWebAuthUrl,                           [ :PassportIdentityHandle, :LPCWSTR, :LPCWSTR, :LPCWSTR, :LPCWSTR, :PLPWSTR, :PLPWSTR ], :HRESULT
            attach_function :LogonIdentityEx,                         [ :PassportIdentityHandle, :LPCWSTR, LOGON_FLAG, :PCRSTParams, :DWORD ], :HRESULT
            attach_function :AuthIdentityToServiceEx,                 [ :PassportIdentityHandle, :DWORD, :PCRSTParams, :DWORD ], :HRESULT
            attach_function :GetAuthStateEx,                          [ :PassportIdentityHandle, :LPCWSTR, :PHRESULT, :PHRESULT, :PHRESULT, :LPWSTR ], :HRESULT
            attach_function :GetCertificate,                          [ :PassportIdentityHandle, RSTParams, :PDWORD, :DWORD, :PCERT_CONTEXT, :LPVOID, :PDWORD, :PCERT_CONTEXT ], :HRESULT
            if (LibIDCRL == 'msidcrl30')
                attach_function :BuildServiceTokenRequestEx,              [ ], :HRESULT # TODO
                attach_function :BuildAuthTokenRequestEx,                 [ ], :HRESULT # TODO
            end
            attach_function :CancelPendingRequest,                    [ :PassportIdentityHandle ], :HRESULT
            attach_function :PutTokenResponseEx,                      [ :PassportIdentityHandle, :DWORD, :LPCWSTR ], :HRESULT if (LibIDCRL == 'msidcrl30')
            attach_function :VerifyCertificate,                       [ CERT_CONTEXT, :PDWORD, :PBYTE, :DWORD, :PCERT_CONTEXT ], :HRESULT
            attach_function :GetIdentityPropertyByName,               [ :PassportIdentityHandle, :LPWSTR, :PLPWSTR ], :HRESULT
            #if (LibIDCRL == '')
                #attach_function :CreateIdentityHandleFromAuthState,       [ :LPCWSTR, IDENTITY_FLAG, :PassportIdentityHandlePointer ], :HRESULT
                #attach_function :ExportAuthState,                         [ :PassportIdentityHandle, :DWORD, :PLPWSTR ], :HRESULT
                #attach_function :CacheAuthState,                          [ :PassportIdentityHandle, :LPCWSTR, :DWORD ], :HRESULT
                #attach_function :RemoveAuthStateFromCache,                [ :LPCWSTR, :LPCWSTR, :DWORD ], :HRESULT
                #attach_function :CreateIdentityHandleFromCachedAuthState, [ :LPCWSTR, :LPCWSTR, IDENTITY_FLAG, :PassportIdentityHandlePointer ], :HRESULT
            #end
            if (LibIDCRL == 'msidcrl40')
                attach_function :SetExtendedProperty,                     [ :LPCWSTR, :LPCWSTR ], :HRESULT
                attach_function :GetExtendedProperty,                     [ :LPCWSTR, :PLPWSTR ], :HRESULT
                attach_function :GetServiceConfig,                        [ :LPCWSTR, :PLPWSTR ], :HRESULT
                #attach_function :MigratePersistedCredentials,             [ :REFGUID, :BOOL, :PDWORD ], :HRESULT if (LibIDCRL == '')
                attach_function :SetIdcrlOptions,                         [ :PIDCRL_OPTION, :DWORD, UPDATE_FLAG ], :HRESULT
                attach_function :GetWebAuthUrlEx,                         [ :PassportIdentityHandle, IDCRL_WEBAUTHOPTION, :LPCWSTR, :LPCWSTR, :LPCWSTR, :PLPWSTR, :PLPWSTR ], :HRESULT
                attach_function :EncryptWithSessionKey,                   [ :PassportIdentityHandle, :LPCWSTR, :DWORD, :DWORD, :LPVOID, :DWORD, :PBYTE, :PDWORD ], :HRESULT
                attach_function :DecryptWithSessionKey,                   [ :PassportIdentityHandle, :LPCWSTR, :DWORD, :DWORD, :PBYTE, :DWORD, :LPVOID, :PDWORD ], :HRESULT
                attach_function :SetUserExtendedProperty,                 [ :LPCWSTR, :LPCWSTR, :LPCWSTR ], :HRESULT
                attach_function :GetUserExtendedProperty,                 [ :LPCWSTR, :LPCWSTR, :PLPWSTR ], :HRESULT
                attach_function :SetChangeNotificationCallback,           [ :LPCWSTR, :DWORD, :cbUserStateChangedCallback ], :HRESULT
                attach_function :RemoveChangeNotificationCallback,        [], :HRESULT
                attach_function :GetExtendedError,                        [ :PassportIdentityHandle, :LPVOID, :PDWORD, :PDWORD, :LPWSTR ], :HRESULT
                attach_function :InitializeApp,                           [ ], :HRESULT # TODO
                attach_function :EnumerateCertificates,                   [ ], :HRESULT # TODO
                attach_function :GenerateCertToken,                       [ ], :HRESULT # TODO
                attach_function :GetDeviceId,                             [ ], :HRESULT # TODO
                attach_function :SetDeviceConsent,                        [ ], :HRESULT # TODO
                attach_function :GenerateDeviceToken,                     [ ], :HRESULT # TODO
                attach_function :CreateLinkedIdentityHandle,              [ ], :HRESULT # TODO
                attach_function :IsDeviceIDAdmin,                         [ ], :HRESULT # TODO
                attach_function :EnumerateDeviceID,                       [ ], :HRESULT # TODO
                attach_function :GetAssertion,                            [ ], :HRESULT # TODO
                attach_function :VerifyAssertion,                         [ ], :HRESULT # TODO
                attach_function :OpenAuthenticatedBrowser,                [ ], :HRESULT # TODO
                attach_function :LogonIdentityExWithUI,                   [ ], :HRESULT # TODO
                attach_function :GetResponseForHttpChallenge,             [ ], :HRESULT # TODO
                attach_function :GetDeviceShortLivedToken,                [ ], :HRESULT # TODO
                attach_function :GetHIPChallenge,                         [ ], :HRESULT # TODO
                attach_function :SetHIPSolution,                          [ ], :HRESULT # TODO
                attach_function :SetDefaultUserForTarget,                 [ ], :HRESULT # TODO
                attach_function :GetDefaultUserForTarget,                 [ ], :HRESULT # TODO
                attach_function :UICollectCredential,                     [ ], :HRESULT # TODO
                attach_function :AssociateDeviceToUser,                   [ ], :HRESULT # TODO
                attach_function :DisassociateDeviceFromUser,              [ ], :HRESULT # TODO
                attach_function :EnumerateUserAssociatedDevices,          [ ], :HRESULT # TODO
                attach_function :UpdateUserAssociatedDeviceProperties,    [ ], :HRESULT # TODO
                attach_function :UIShowWaitDialog,                        [ ], :HRESULT # TODO
                attach_function :UIEndWaitDialog,                         [ ], :HRESULT # TODO
                attach_function :InitializeIDCRLTraceBuffer,              [ ], :HRESULT # TODO
                attach_function :FlushIDCRLTraceBuffer,                   [ ], :HRESULT # TODO
                attach_function :IsMappedError,                           [ ], :HRESULT # TODO
                attach_function :GetAuthenticationStatus,                 [ :PassportIdentityHandle, :LPCWSTR, :DWORD, :LPVOID ], :HRESULT
                attach_function :GetConfigDWORDValue,                     [ ], :HRESULT # TODO
                if IsWin8
                    attach_function :ProvisionDeviceId,                       [ ], :HRESULT # TODO
                    attach_function :GetDeviceIdEx,                           [ ], :HRESULT # TODO
                    attach_function :RenewDeviceId,                           [ ], :HRESULT # TODO
                    attach_function :DeProvisionDeviceId,                     [ ], :HRESULT # TODO
                    attach_function :UnPackErrorBlob,                         [ ], :HRESULT # TODO
                    attach_function :GetDefaultNoUISSOUser,                   [ ], :HRESULT # TODO
                    attach_function :LogonIdentityExSSO,                      [ :PassportIdentityHandle, :LPCWSTR, LOGON_FLAG, :DWORD, SSO_UIParam, :PCRSTParams, :DWORD ], :HRESULT
                    attach_function :StartTracing,                            [ ], :HRESULT # TODO
                    attach_function :StopTracing,                             [ ], :HRESULT # TODO
                    attach_function :GetRealmInfo,                            [ ], :HRESULT # TODO
                    attach_function :CreateIdentityHandleEx,                  [ :LPCWSTR, IDENTITY_FLAG, :DWORD, :PassportIdentityHandlePointer ], :HRESULT
                    attach_function :AddUserToSsoGroup,                       [ ], :HRESULT # TODO
                    attach_function :GetUsersFromSsoGroup,                    [ ], :HRESULT # TODO
                    attach_function :RemoveUserFromSsoGroup,                  [ ], :HRESULT # TODO
                    attach_function :SendOneTimeCode,                         [ ], :HRESULT # TODO
                end
            end
        end
    end
end

