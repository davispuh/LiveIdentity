require 'ffi'
require 'win_common/typedefs'
require 'win_common/structs'

require_relative 'idcrl/constants'
require_relative 'idcrl/enums'
require_relative 'idcrl/hresult'

module WinCommon::Errors::HRESULT
    include LiveIdentity::IDCRL::HRESULT
end

class LiveIdentity
    include IDCRL::Constants
    module IDCRL
        extend FFI::Library
        # http://msdn.microsoft.com/en-us/library/hh472108.aspx
        ffi_lib 'msidcrl40'
        ffi_convention :stdcall

        include WinCommon::Structs
        include Enums

        require_relative 'idcrl/structs'
        include Structs

        typedef :pointer, :PassportIdentityHandlePointer
        typedef :size_t,  :PassportIdentityHandle
        typedef :pointer, :PassportEnumIdentitiesHandlePointer
        typedef :size_t,  :PassportEnumIdentitiesHandle
        typedef :pointer, :PIDCRL_OPTION

        callback :cbIdentityChangedCallback, [:PassportEnumIdentitiesHandle, :pointer, :char], :uint

        attach_function :Initialize,                           [ ], :HRESULT # TODO
        attach_function :Uninitialize,                         [],  :HRESULT
        attach_function :PassportFreeMemory,                   [ :pointer ], :HRESULT
        attach_function :CreateIdentityHandle,                 [ :LPCWSTR, IDENTITY_FLAG, :PassportIdentityHandlePointer ], :HRESULT
        attach_function :SetCredential,                        [ :PassportIdentityHandle, :LPCWSTR, :LPCWSTR ], :HRESULT
        attach_function :GetIdentityProperty,                  [ ], :HRESULT # TODO
        attach_function :SetIdentityProperty,                  [ :PassportIdentityHandle, :uint, :LPCWSTR ], :HRESULT
        attach_function :CloseIdentityHandle,                  [ :PassportIdentityHandle ], :HRESULT
        attach_function :AuthIdentityToService,                [ :PassportIdentityHandle, :LPCWSTR, :LPCWSTR, SERVICETOKENFLAGS, :PLPWSTR, :PDWORD, :PPBYTE, :PDWORD ], :HRESULT
        attach_function :PersistCredential,                    [ ], :HRESULT # TODO
        attach_function :RemovePersistedCredential,            [ ], :HRESULT # TODO
        attach_function :EnumIdentitiesWithCachedCredentials,  [ :LPCWSTR, :PassportEnumIdentitiesHandlePointer ], :HRESULT
        attach_function :NextIdentity,                         [ :PassportEnumIdentitiesHandle, :PLPWSTR ], :HRESULT
        attach_function :CloseEnumIdentitiesHandle,            [ :PassportEnumIdentitiesHandle ], :HRESULT
        attach_function :GetAuthState,                         [ ], :HRESULT # TODO
        attach_function :LogonIdentity,                        [ ], :HRESULT # TODO
        attach_function :HasPersistedCredential,               [ ], :HRESULT # TODO
        attach_function :SetIdentityCallback,                  [ :PassportEnumIdentitiesHandle, :cbIdentityChangedCallback, :pointer ], :HRESULT
        attach_function :InitializeEx,                         [ :REFGUID, :LONG, UPDATE_FLAG, :PIDCRL_OPTION, :DWORD ], :HRESULT
        attach_function :GetWebAuthUrl,                        [ ], :HRESULT # TODO
        attach_function :LogonIdentityEx,                      [ ], :HRESULT # TODO
        attach_function :AuthIdentityToServiceEx,              [ ], :HRESULT # TODO
        attach_function :GetAuthStateEx,                       [ ], :HRESULT # TODO
        attach_function :GetCertificate,                       [ ], :HRESULT # TODO
        attach_function :CancelPendingRequest,                 [ ], :HRESULT # TODO
        attach_function :VerifyCertificate,                    [ ], :HRESULT # TODO
        attach_function :GetIdentityPropertyByName,            [ :PassportIdentityHandle, :LPWSTR, :PLPWSTR ], :HRESULT
        attach_function :SetExtendedProperty,                  [ ], :HRESULT # TODO
        attach_function :GetExtendedProperty,                  [ ], :HRESULT # TODO
        attach_function :GetServiceConfig,                     [ ], :HRESULT # TODO
        attach_function :SetIdcrlOptions,                      [ ], :HRESULT # TODO
        attach_function :GetWebAuthUrlEx,                      [ ], :HRESULT # TODO
        attach_function :EncryptWithSessionKey,                [ ], :HRESULT # TODO
        attach_function :DecryptWithSessionKey,                [ ], :HRESULT # TODO
        attach_function :SetUserExtendedProperty,              [ ], :HRESULT # TODO
        attach_function :GetUserExtendedProperty,              [ ], :HRESULT # TODO
        attach_function :SetChangeNotificationCallback,        [ ], :HRESULT # TODO
        attach_function :RemoveChangeNotificationCallback,     [ ], :HRESULT # TODO
        attach_function :GetExtendedError,                     [ :PassportIdentityHandle, :LPVOID, :PDWORD, :PDWORD, :LPWSTR ], :HRESULT
        attach_function :InitializeApp,                        [ ], :HRESULT # TODO
        attach_function :EnumerateCertificates,                [ ], :HRESULT # TODO
        attach_function :GenerateCertToken,                    [ ], :HRESULT # TODO
        attach_function :GetDeviceId,                          [ ], :HRESULT # TODO
        attach_function :SetDeviceConsent,                     [ ], :HRESULT # TODO
        attach_function :GenerateDeviceToken,                  [ ], :HRESULT # TODO
        attach_function :CreateLinkedIdentityHandle,           [ ], :HRESULT # TODO
        attach_function :IsDeviceIDAdmin,                      [ ], :HRESULT # TODO
        attach_function :EnumerateDeviceID,                    [ ], :HRESULT # TODO
        attach_function :GetAssertion,                         [ ], :HRESULT # TODO
        attach_function :VerifyAssertion,                      [ ], :HRESULT # TODO
        attach_function :OpenAuthenticatedBrowser,             [ ], :HRESULT # TODO
        attach_function :LogonIdentityExWithUI,                [ ], :HRESULT # TODO
        attach_function :GetResponseForHttpChallenge,          [ ], :HRESULT # TODO
        attach_function :GetDeviceShortLivedToken,             [ ], :HRESULT # TODO
        attach_function :GetHIPChallenge,                      [ ], :HRESULT # TODO
        attach_function :SetHIPSolution,                       [ ], :HRESULT # TODO
        attach_function :SetDefaultUserForTarget,              [ ], :HRESULT # TODO
        attach_function :GetDefaultUserForTarget,              [ ], :HRESULT # TODO
        attach_function :UICollectCredential,                  [ ], :HRESULT # TODO
        attach_function :AssociateDeviceToUser,                [ ], :HRESULT # TODO
        attach_function :DisassociateDeviceFromUser,           [ ], :HRESULT # TODO
        attach_function :EnumerateUserAssociatedDevices,       [ ], :HRESULT # TODO
        attach_function :UpdateUserAssociatedDeviceProperties, [ ], :HRESULT # TODO
        attach_function :UIShowWaitDialog,                     [ ], :HRESULT # TODO
        attach_function :UIEndWaitDialog,                      [ ], :HRESULT # TODO
        attach_function :InitializeIDCRLTraceBuffer,           [ ], :HRESULT # TODO
        attach_function :FlushIDCRLTraceBuffer,                [ ], :HRESULT # TODO
        attach_function :IsMappedError,                        [ ], :HRESULT # TODO
        attach_function :GetAuthenticationStatus,              [ ], :HRESULT # TODO
        attach_function :GetConfigDWORDValue,                  [ ], :HRESULT # TODO
        attach_function :ProvisionDeviceId,                    [ ], :HRESULT # TODO
        attach_function :GetDeviceIdEx,                        [ ], :HRESULT # TODO
        attach_function :RenewDeviceId,                        [ ], :HRESULT # TODO
        attach_function :DeProvisionDeviceId,                  [ ], :HRESULT # TODO
        attach_function :UnPackErrorBlob,                      [ ], :HRESULT # TODO
        attach_function :GetDefaultNoUISSOUser,                [ ], :HRESULT # TODO
        attach_function :LogonIdentityExSSO,                   [ ], :HRESULT # TODO
        attach_function :StartTracing,                         [ ], :HRESULT # TODO
        attach_function :StopTracing,                          [ ], :HRESULT # TODO
        attach_function :GetRealmInfo,                         [ ], :HRESULT # TODO
        attach_function :CreateIdentityHandleEx,               [ ], :HRESULT # TODO
        attach_function :AddUserToSsoGroup,                    [ ], :HRESULT # TODO
        attach_function :GetUsersFromSsoGroup,                 [ ], :HRESULT # TODO
        attach_function :RemoveUserFromSsoGroup,               [ ], :HRESULT # TODO
        attach_function :SendOneTimeCode,                      [ ], :HRESULT # TODO
    end
end
