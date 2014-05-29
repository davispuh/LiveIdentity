require 'win_common'

require_relative 'live_identity/version'
require_relative 'live_identity/idcrl'

class LiveIdentity
    class LiveIdentityError < WinCommon::Errors::HRESULTError; end

    def self.IsError?(hr)
        WinCommon::Errors::HRESULT::IsError?(hr)
    end

    def initialize(guid, version, flags, options)
        guidClientApplication = IDCRL::GUID.new
        guidClientApplication.from_str(guid)
        lPPCRLVersion = version
        dwFlags = flags
        dwOptions = options.count
        pOptions = nil
        if dwOptions > 0
            pOptions = FFI::MemoryPointer.new(IDCRL::IDCRL_OPTION, dwOptions)
            i = 0
            options.each do |id, value|
                option = IDCRL::IDCRL_OPTION.new(pOptions + i * IDCRL::IDCRL_OPTION.size)
                option[:dwId] = id
                option[:pValue] = FFI::MemoryPointer.new(:pointer)
                if value.is_a?(String)
                    data = StringToWSTR(value)
                    option[:pValue].write_string(data)
                    option[:cbValue] = data.bytesize
                elsif value.is_a?(Fixnum)
                    option[:pValue].write_int(data)
                    option[:cbValue] = 4
                else
                    raise "Uknown value type #{value.inspect}"
                end
                i += 1
            end
        end

        hr = IDCRL.InitializeEx(guidClientApplication, lPPCRLVersion, dwFlags, pOptions, dwOptions)
        raise LiveIdentityError.new(hr) if LiveIdentity::IsError?(hr)
        ObjectSpace.define_finalizer( self, self.class.finalize() )
    end

    def self.finalize()
        Proc.new { IDCRL.Uninitialize() }
    end

    def GetIdentity(memberName, flags)
        Identity.new(memberName, flags)
    end

    class Identity
        attr_reader :hIdentity
        def initialize(memberName, flags)
            @hIdentity = nil
            wszMemberName = StringToWSTR(memberName)
            dwflags = flags
            pihIdentity = FFI::MemoryPointer.new(:PassportIdentityHandlePointer)
            hr = IDCRL.CreateIdentityHandle(wszMemberName, dwflags, pihIdentity)
            raise LiveIdentityError.new(hr) if LiveIdentity::IsError?(hr)
            @hIdentity = pihIdentity.read_ulong
            ObjectSpace.define_finalizer(self, self.class.finalize(@hIdentity))
        end

        def self.finalize(hIdentity)
            Proc.new do
                hr = IDCRL.CloseIdentityHandle(hIdentity)
                raise LiveIdentityError.new(hr) if LiveIdentity::IsError?(hr)
            end
        end

        def SetProperty(property, value)
            ipProperty = property
            wszPropertyValue = StringToWSTR(value)
            hr = IDCRL.SetIdentityProperty(@hIdentity, ipProperty, wszPropertyValue)
            raise LiveIdentityError.new(hr) if LiveIdentity::IsError?(hr)
        end

        def GetPropertyByName(name)
            wszPropertyName = StringToWSTR(name)
            pwszPropertyValue = FFI::MemoryPointer.new(:pointer)
            hr = IDCRL.GetIdentityPropertyByName(@hIdentity, wszPropertyName, pwszPropertyValue)
            raise LiveIdentityError.new(hr) if LiveIdentity::IsError?(hr)
            propertyValue = read_wide_string(pwszPropertyValue.read_pointer)
            LiveIdentity::FreeMemory(pwszPropertyValue.read_pointer)
            propertyValue
        end

        def SetCredential(type, value)
            wszCredType = [type.encode('UTF-16LE')].pack('a*xx')
            wszCredValue = [value.encode('UTF-16LE')].pack('a*xx')
            hr = IDCRL.SetCredential(@hIdentity, wszCredType, wszCredValue)
            raise LiveIdentityError.new(hr) if LiveIdentity::IsError?(hr)
        end

        def AuthToService(target, policy, flags)
            Service.new(self, target, policy, flags)
        end

        class ExtendedError
            attr_reader :Category
            attr_reader :Error
            attr_reader :ErrorBlob
            def initialize(identity)
                @Category = nil
                @Error = nil
                @ErrorBlob = nil

                hIdentity = identity.hIdentity
                pdwCategory = FFI::MemoryPointer.new(:pointer)
                pdwError = FFI::MemoryPointer.new(:pointer)
                pszErrorBlob = FFI::MemoryPointer.new(:pointer)

                hr = IDCRL.GetExtendedError(hIdentity, nil, pdwCategory, pdwError, pszErrorBlob)
                raise LiveIdentityError.new(hr) if LiveIdentity::IsError?(hr)
            end
        end

        def GetExtendedError
            ExtendedError.new
        end

        class Service
            attr_reader :Token
            attr_reader :ResultFlags
            attr_reader :SessionKey
            def initialize(identity, target, policy, flags, sessionKey = false)
                @Token = nil
                @ResultFlags = nil
                @SessionKey = nil

                hIdentity = identity.hIdentity
                szServiceTarget = StringToWSTR(target.to_s)
                szServicePolicy = StringToWSTR(policy.to_s)
                dwTokenRequestFlags = flags

                szToken = FFI::MemoryPointer.new(:pointer)
                pdwResultFlags = FFI::MemoryPointer.new(:pointer)
                ppbSessionKey = nil
                pcbSessionKeyLength = nil
                if sessionKey
                    ppbSessionKey = FFI::MemoryPointer.new(:pointer)
                    pcbSessionKeyLength = FFI::MemoryPointer.new(:pointer)
                end

                hr = IDCRL.AuthIdentityToService(hIdentity, szServiceTarget, szServicePolicy, dwTokenRequestFlags, szToken, pdwResultFlags, ppbSessionKey, pcbSessionKeyLength)
                raise LiveIdentityError.new(hr) if LiveIdentity::IsError?(hr)
                @Token = read_wide_string(szToken.read_pointer)
            end
        end
    end
end
