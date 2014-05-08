require 'win_common'

require_relative 'live_identity/version'
require_relative 'live_identity/idcrl'

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
        break if offset >= 10000
    end
    length
end

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
                    data = [value.encode('UTF-16LE')].pack('a*xx')
                    option[:pValue].write_string(data)
                    option[:cbValue] = data.bytesize
                else
                    # TODO
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
            wszMemberName = [memberName.encode('UTF-16LE')].pack('a*xx')
            dwflags = flags

            pihIdentity = FFI::MemoryPointer.new(:pointer)
            hr = IDCRL.CreateIdentityHandle(wszMemberName, dwflags, pihIdentity)
            raise LiveIdentityError.new(hr) if LiveIdentity::IsError?(hr)
            @hIdentity = pihIdentity.read_ulong
            ObjectSpace.define_finalizer( self, self.class.finalize(@hIdentity) )
        end

        def self.finalize(hIdentity)
            Proc.new do
                hr = IDCRL.CloseIdentityHandle(hIdentity)
                raise LiveIdentityError.new(hr) if LiveIdentity::IsError?(hr)
            end
        end

        def SetProperty(property, value)
            ipProperty = property
            wszPropertyValue = [value.encode('UTF-16LE')].pack('a*xx')
            hr = IDCRL.SetIdentityProperty(@hIdentity, ipProperty, wszPropertyValue)
            raise LiveIdentityError.new(hr) if LiveIdentity::IsError?(hr)
        end

        def GetPropertyByName(name)
            wszPropertyName = [name.encode('UTF-16LE')].pack('a*xx')
            pwszPropertyValue = FFI::MemoryPointer.new(:pointer)
            hr = IDCRL.GetIdentityPropertyByName(@hIdentity, wszPropertyName, pwszPropertyValue)
            raise LiveIdentityError.new(hr) if LiveIdentity::IsError?(hr)
            pwszPropertyValue = pwszPropertyValue.read_pointer.read_bytes(getStringLength(pwszPropertyValue.read_pointer))
            pwszPropertyValue.force_encoding('UTF-16LE').encode('UTF-8')
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
                szServiceTarget = [target.to_s.encode('UTF-16LE')].pack('a*xx')
                szServicePolicy = [policy.to_s.encode('UTF-16LE')].pack('a*xx')
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
                szToken = szToken.read_pointer.read_bytes(getStringLength(szToken.read_pointer))
                @Token = szToken.force_encoding('UTF-16LE').encode('UTF-8')
            end
        end
    end
end
