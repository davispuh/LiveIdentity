class LiveIdentity
    module IDCRL
        module Structs
            class IDCRL_OPTION < FFI::Struct
                layout({
                    :dwId    => IDCRL_OPTION_ID,
                    :pValue  => :PBYTE,
                    :cbValue => :size_t
                })
            end

            class IDCRL_OPTIONS < FFI::Struct
                layout({
                    :dwCount    => :DWORD,
                    :arrOptions => :pointer # *IDCRL_OPTION[]
                })
            end

            class IDCRL_STATUS_V1 < FFI::Struct
                layout({
                    :hrAuthState     => :HRESULT,
                    :hrAuthRequired  => :HRESULT,
                    :hrRequestStatus => :HRESULT,
                    :hrUIError       => :HRESULT,
                    :wszWebFlowUrl   => :LPWSTR
                })

                def AuthState
                    self[:hrAuthState]
                end

                def AuthRequired
                    self[:hrAuthRequired]
                end

                def RequestStatus
                    self[:hrRequestStatus]
                end

                def WebFlowUrl
                    @WebFlowUrl ||= read_wide_string(self[:wszWebFlowUrl])
                end

                def WebFlowUrl= (webFlowUrl)
                    @WebFlowUrl = webFlowUrl
                    self[:wszWebFlowUrl] = StringToWSTR(webFlowUrl)
                end

                def to_s
                    "AuthState:     #{WinCommon::Errors::HRESULT::GetNameCode(AuthState())}\n" +
                    "AuthRequired:  #{WinCommon::Errors::HRESULT::GetNameCode(AuthRequired())}\n" +
                    "RequestStatus: #{WinCommon::Errors::HRESULT::GetNameCode(RequestStatus())}"
                end

                def IsAuthenticated?
                    RequestStatus() >= 0 && AuthState() >= 0
                end
            end

            class PASSPORT_NAME_VALUE_PAIR < FFI::Struct
                layout({
                    :szName  => :LPWSTR,
                    :szValue => :LPWSTR
                })
            end

            class IDCRL::UIParam < FFI::Struct
                layout({
                    :dwFlags               => :DWORD,
                    :hwndParent            => :HANDLE,
                    :wszCobrandingText     => :LPWSTR,
                    :wszAppName            => :LPWSTR,
                    :wszSignupText         => :LPWSTR,
                    :wszSignupText         => :LPWSTR,
                    :wszCobrandingLogoPath => :LPWSTR,
                    :wszHeaderBgImage      => :LPWSTR,
                    :dwBgColor             => :DWORD,
                    :dwURLColor            => :DWORD,
                    :dwTileBgColor         => :DWORD,
                    :dwTileBdColor         => :DWORD,
                    :dwFieldBdColor        => :DWORD,
                    :dwCheckboxLbColor     => :DWORD,
                    :dwBtTxtColor          => :DWORD,
                    :dwTileLbColor         => :DWORD,
                    :lWinLeft              => :LONG,
                    :lWinTop               => :LONG,
                    :wszSignupUrl          => :LPWSTR
                })
            end

            class RSTParams < FFI::Struct
                layout({
                    :cbSize          => :DWORD,
                    :wzServiceTarget => :LPCWSTR,
                    :wzServicePolicy => :LPCWSTR,
                    :dwTokenFlags    => :DWORD,
                    :dwTokenParam    => :DWORD
                })

                def self.build(data, address = nil)
                    param = IDCRL::RSTParams.new(address)
                    param[:cbSize] = self.size
                    param[:wzServiceTarget] = FFI::MemoryPointer.from_string(StringToWSTR(data[:ServiceTarget].to_s))
                    param[:wzServicePolicy] = FFI::MemoryPointer.from_string(StringToWSTR(data[:ServicePolicy].to_s))
                    param[:dwTokenFlags]    = 0
                    param[:dwTokenParam]    = 0
                    param[:dwTokenFlags]    = data[:TokenFlags] if data.has_key?(:TokenFlags)
                    param[:dwTokenParam]    = data[:TokenParam] if data.has_key?(:TokenParam)
                    param
                end
            end

            class PASSPORTCREDCUSTOMUI < FFI::Struct
                layout({
                    :cElements    => :LONG,
                    :customValues => :LPWSTR
                })
            end

            class MultiRSTParams < FFI::Struct
                layout({
                    :dwRSTParamsCount      => :DWORD,
                    :pRSTParams            => :pointer, # *RSTParams[]
                    :dwMultiRSTParamsFlags => :DWORD
                })
            end

            class PassportCredUIInfo < FFI::Struct
                layout({
                    :hwndParent => :HWND,
                    :ptPosition => IDCRL::POINT,
                    :szSize     => IDCRL::SIZE,
                    :bShow      => :BOOL
                })
            end

            class SSO_UIParam < FFI::Struct
                layout({
                    :cbsize         => :DWORD,
                    :dwReserved     => :DWORD,
                    :hwndParent     => :HWND,
                    :pReserved      => :UINT_PTR,
                    :wszServiceName => :LPCWSTR,
                    :rgbReserved    => [:BYTE, 16],
                    :rghReserved    => [:UINT_PTR, 45]
                })
            end

            class CertSet < FFI::Struct
                layout({
                    :pCertContext   => :PCERT_CONTEXT,
                    :pCACertContext => :PCERT_CONTEXT,
                    :cbPOP          => :DWORD,
                    :pbPOP          => :PBYTE
                })

                def self.build
                    certSet = CertSet.new
                    certSet[:pCertContext]   = FFI::MemoryPointer.new(:pointer)
                    certSet[:pCACertContext] = FFI::MemoryPointer.new(:pointer)
                    certSet[:cbPOP] = 0
                    certSet[:pbPOP] = FFI::MemoryPointer.new(:PBYTE)
                    certSet
                end

                def CertContext
                    @CertContext ||= CERT_CONTEXT.new(self[:pCertContext])
                end

                def CertContext= (certContext)
                    @CertContext = certContext
                    self[:pCertContext] = FFI::MemoryPointer.new(certContext)
                end

                def CACertContext
                    @CertContext ||= CERT_CONTEXT.new(self[:pCACertContext])
                end

                def CACertContext= (caCertContext)
                    @CACertContext = caCertContext
                    self[:pCACertContext] = FFI::MemoryPointer.new(caCertContext)
                end

                def POP
                    @POP ||= self[:pbPOP].read_string(self[:cbPOP])
                end

                def POP= (pop)
                    @POP = pop
                    self[:cbPOP] = pop.bytesize
                    self[:pbPOP] = FFI::MemoryPointer.from_string(pop)
                end

            end

            class MD5Data < FFI::Struct
                layout({
                    :szMD5Url   => :LPWSTR,
                    :szPostData => :LPWSTR
                })

                def MD5Url
                    @MD5Url ||= read_wide_string(self[:szMD5Url])
                end

                def MD5Url= (md5Url)
                    @MD5Url = md5Url
                    self[:szMD5Url] = StringToWSTR(md5Url)
                end

                def PostData
                    @PostData ||= read_wide_string(self[:szPostData])
                end

                def PostData= (postData)
                    @PostData = postData
                    self[:szPostData] = StringToWSTR(postData)
                end
            end

            class SHA1 < FFI::Struct
                layout({
                    :szSHA1Url      => :LPWSTR,
                    :szSHA1PostData => :LPWSTR
                })

                def SHA1Url
                    @SHA1Url ||= read_wide_string(self[:szSHA1Url])
                end

                def SHA1Url= (sha1Url)
                    @SHA1Url = sha1Url
                    self[:szSHA1Url] = StringToWSTR(sha1Url)
                end

                def SHA1PostData
                    @SHA1PostData ||= read_wide_string(self[:szPostData])
                end

                def SHA1PostData= (sha1PostData)
                    @SHA1PostData = sha1PostData
                    self[:szSHA1PostData] = StringToWSTR(sha1PostData)
                end
            end

        end
    end
end
