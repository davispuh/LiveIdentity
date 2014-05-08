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
                    :wszWebFlowUrl   => :LPWSTR,
                })
            end

            class PASSPORT_NAME_VALUE_PAIR < FFI::Struct
                layout({
                    :szName  => :LPWSTR,
                    :szValue => :LPWSTR,
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
                    :cbSize => :DWORD,
                    :wzServiceTarget => :LPCWSTR,
                    :wzServicePolicy => :LPCWSTR,
                    :dwTokenFlags => :DWORD,
                    :dwTokenParam => :DWORD
                })
            end

            class PASSPORTCREDCUSTOMUI < FFI::Struct
                layout({
                    :cElements => :LONG,
                    :customValues => :LPWSTR
                })
            end

            class MultiRSTParams < FFI::Struct
                layout({
                    :dwRSTParamsCount => :DWORD,
                    :pRSTParams => :pointer, # *RSTParams[]
                    :dwMultiRSTParamsFlags => :DWORD
                })
            end
        end
    end
end
