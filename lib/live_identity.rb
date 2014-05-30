require 'win_common'
require 'timeout'
require 'nokogiri'

require_relative 'live_identity/version'
require_relative 'live_identity/idcrl'

class LiveIdentity
    class LiveIdentityError < WinCommon::Errors::HRESULTError; end

    def self.IsError?(hr)
        WinCommon::Errors::HRESULT::IsError?(hr)
    end

    def self.processOptions(options)
        pOptions = nil
        if options.count > 0
            pOptions = FFI::MemoryPointer.new(IDCRL::IDCRL_OPTION, options.count)
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
        pOptions
    end

    def self.processRSTParams(params)
        pRSTParams = nil
        if params.count > 0
            pRSTParams = FFI::MemoryPointer.new(IDCRL::RSTParams, params.count)
            params.each_index do |i|
                IDCRL::RSTParams.build(params[i], pRSTParams + i * IDCRL::RSTParams.size)
            end
        end
        pRSTParams
    end

    def self.waitFor(pr, errorText, time = 20, wait = 0.2)
        Timeout::timeout(time) do
            while !pr.call do sleep(wait) end
        end
    rescue Timeout::Error
        yield
        raise errorText
    end

    def initialize(guid, version, flags, options)
        guidClientApplication = IDCRL::GUID.new
        guidClientApplication.from_str(guid)
        lPPCRLVersion = version
        dwFlags = flags
        dwOptions = options.count
        pOptions = LiveIdentity::processOptions(options)
        hr = IDCRL.InitializeEx(guidClientApplication, lPPCRLVersion, dwFlags, pOptions, dwOptions)
        raise LiveIdentityError.new(hr) if LiveIdentity::IsError?(hr)
        ObjectSpace.define_finalizer( self, self.class.finalize() )
    end

    def self.finalize()
        Proc.new { IDCRL.Uninitialize() }
    end

    def self.FreeMemory(pMemoryToFree)
        hr = IDCRL.PassportFreeMemory(pMemoryToFree)
        raise LiveIdentityError.new(hr) if LiveIdentity::IsError?(hr)
    end

    def self.VerifyCertificate(certSet, minTTL)
        dwMinTTL = FFI::MemoryPointer.new(:DWORD)
        dwMinTTL.write_uint(minTTL)
        pCACertContext = FFI::MemoryPointer.new(:PCERT_CONTEXT)
        hr = IDCRL.VerifyCertificate(certSet[:pCertContext], dwMinTTL, certSet[:pbPOP], certSet[:cbPOP], pCACertContext)
        certSet[:pCACertContext] = pCACertContext.read_pointer
        certSet.CACertContext
        raise LiveIdentityError.new(hr) if LiveIdentity::IsError?(hr)
    end

    def SetExtendedProperty(property, value)
        wszPropertyName = StringToWSTR(property)
        wszPropertyValue = StringToWSTR(value)
        hr = IDCRL.SetExtendedProperty(wszPropertyName, wszPropertyValue)
        raise LiveIdentityError.new(hr) if LiveIdentity::IsError?(hr)
    end

    def GetExtendedProperty(property)
        wszPropertyName = StringToWSTR(property)
        wszPropertyValue = FFI::MemoryPointer.new(:PLPWSTR)
        hr = IDCRL.GetExtendedProperty(wszPropertyName, wszPropertyValue)
        raise LiveIdentityError.new(hr) if LiveIdentity::IsError?(hr)
        propertyValue = read_wide_string(wszPropertyValue.read_pointer)
        LiveIdentity::FreeMemory(wszPropertyValue.read_pointer)
        propertyValue
    end

    def self.GetServiceConfig(valueName)
        wszValueName = StringToWSTR(valueName)
        szUrlValue = FFI::MemoryPointer.new(:PLPWSTR)
        hr = IDCRL.GetServiceConfig(wszValueName, szUrlValue)
        raise LiveIdentityError.new(hr) if LiveIdentity::IsError?(hr)
        return nil if szUrlValue.read_pointer.null?
        urlValue = read_wide_string(szUrlValue.read_pointer)
        LiveIdentity::FreeMemory(szUrlValue.read_pointer)
        urlValue
    end

    def SetIdcrlOptions(options, flags)
        dwOptions = options.count
        pOptions = LiveIdentity::processOptions(options)
        dwFlags = flags
        hr = IDCRL.SetIdcrlOptions(pOptions, dwOptions, dwFlags)
        raise LiveIdentityError.new(hr) if LiveIdentity::IsError?(hr)
    end

    def SetUserExtendedProperty(userName, name, value)
        szUserName = StringToWSTR(userName)
        szPropertyName = StringToWSTR(name)
        szPropertyValue = StringToWSTR(value)
        hr = IDCRL.SetUserExtendedProperty(szUserName, szPropertyName, szPropertyValue)
        raise LiveIdentityError.new(hr) if LiveIdentity::IsError?(hr)
    end

    def GetUserExtendedProperty(userName, name)
        szUserName = StringToWSTR(userName)
        szPropertyName = StringToWSTR(name)
        szPropertyValue = FFI::MemoryPointer.new(:PLPWSTR)
        hr = IDCRL.GetUserExtendedProperty(szUserName, szPropertyName, szPropertyValue)
        raise LiveIdentityError.new(hr) if LiveIdentity::IsError?(hr)
        propertyValue = read_wide_string(szPropertyValue.read_pointer)
        LiveIdentity::FreeMemory(szPropertyValue.read_pointer)
        propertyValue
    end

    def SetChangeNotificationCallback(virtualApp, callBackFunction)
        szVirtualApp = StringToWSTR(virtualApp)
        hr = IDCRL.SetChangeNotificationCallback(szVirtualApp, nil, callBackFunction)
        raise LiveIdentityError.new(hr) if LiveIdentity::IsError?(hr)
    end

    def RemoveChangeNotificationCallback()
        hr = IDCRL.RemoveChangeNotificationCallback()
        raise LiveIdentityError.new(hr) if LiveIdentity::IsError?(hr)
    end

    def GetIdentities(cachedCredType)
        Identities.new(cachedCredType)
    end

    def GetIdentity(memberName, flags)
        Identity.new(memberName, flags)
    end

    class Identities
        attr_reader :peihEnumHandle
        def initialize(cachedCredType)
            @peihEnumHandle = nil
            szCachedCredType = nil
            szCachedCredType = StringToWSTR(cachedCredType) if cachedCredType
            peihEnumHandle = FFI::MemoryPointer.new(:PassportEnumIdentitiesHandlePointer)
            hr = IDCRL.EnumIdentitiesWithCachedCredentials(szCachedCredType, peihEnumHandle)
            raise LiveIdentityError.new(hr) if LiveIdentity::IsError?(hr)
            @peihEnumHandle = peihEnumHandle.read_ulong
            ObjectSpace.define_finalizer(self, self.class.finalize(@peihEnumHandle))
        end

        def self.finalize(peihEnumHandle)
            Proc.new do
                hr = IDCRL.CloseEnumIdentitiesHandle(peihEnumHandle)
                raise LiveIdentityError.new(hr) if LiveIdentity::IsError?(hr)
            end
        end

        def GetNextIdentityName
            wszMemberName = FFI::MemoryPointer.new(:PLPWSTR)
            hr = IDCRL.NextIdentity(@peihEnumHandle, wszMemberName)
            raise LiveIdentityError.new(hr) if LiveIdentity::IsError?(hr)
            return nil if hr == IDCRL::HRESULT::PPCRL_S_NO_MORE_IDENTITIES
            memberName = read_wide_string(wszMemberName.read_pointer)
            LiveIdentity::FreeMemory(wszMemberName.read_pointer)
            memberName
        end

        def GetAllIdentityNames
            identityNames = []
            loop do
                identityName = GetNextIdentityName()
                break unless identityName
                identityNames << identityName
            end
            identityNames
        end
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

        def SetCredential(type, value)
            wszCredType = StringToWSTR(type)
            wszCredValue = StringToWSTR(value)
            hr = IDCRL.SetCredential(@hIdentity, wszCredType, wszCredValue)
            raise LiveIdentityError.new(hr) if LiveIdentity::IsError?(hr)
        end

        def GetProperty(property)
            ipProperty = property
            pwszPropertyValue = FFI::MemoryPointer.new(:PLPWSTR)
            hr = IDCRL.GetIdentityProperty(@hIdentity, ipProperty, pwszPropertyValue)
            raise LiveIdentityError.new(hr) if LiveIdentity::IsError?(hr)
            propertyValue = read_wide_string(pwszPropertyValue.read_pointer)
            LiveIdentity::FreeMemory(pwszPropertyValue.read_pointer)
            propertyValue
        end

        def SetProperty(property, value)
            ipProperty = property
            wszPropertyValue = StringToWSTR(value)
            hr = IDCRL.SetIdentityProperty(@hIdentity, ipProperty, wszPropertyValue)
            raise LiveIdentityError.new(hr) if LiveIdentity::IsError?(hr)
        end

        def AuthToService(target, policy = 'HBI', flags = :SERVICE_TOKEN_FROM_CACHE, sessionKey = false)
            szServiceTarget = StringToWSTR(target.to_s)
            szServicePolicy = StringToWSTR(policy.to_s)
            dwTokenRequestFlags = flags
            szToken = FFI::MemoryPointer.new(:PLPWSTR)
            pdwResultFlags = FFI::MemoryPointer.new(:PDWORD)
            ppbSessionKey = nil
            pcbSessionKeyLength = nil
            if sessionKey
                ppbSessionKey = FFI::MemoryPointer.new(:PPBYTE)
                pcbSessionKeyLength = FFI::MemoryPointer.new(:PDWORD)
            end
            hr = IDCRL.AuthIdentityToService(@hIdentity, szServiceTarget, szServicePolicy, dwTokenRequestFlags, szToken, pdwResultFlags, ppbSessionKey, pcbSessionKeyLength)
            raise LiveIdentityError.new(hr) if LiveIdentity::IsError?(hr)
            authState = IDCRL::AuthState.new
            authState[:szToken] = szToken.read_pointer
            authState[:dwResultFlags] = pdwResultFlags.read_uint
            authState[:pbSessionKey] = ppbSessionKey.read_pointer if sessionKey
            authState[:dwSessionKeyLength] = pcbSessionKeyLength.read_uint if sessionKey
            authState.Token()
            authState.SessionKey()
            LiveIdentity::FreeMemory(szToken.read_pointer)
            LiveIdentity::FreeMemory(ppbSessionKey.read_pointer) if sessionKey
            authState
        end

        def PersistCredential(credType)
            wszCredType = StringToWSTR(credType)
            hr = IDCRL.PersistCredential(@hIdentity, wszCredType)
            raise LiveIdentityError.new(hr) if LiveIdentity::IsError?(hr)
        end

        def RemovePersistedCredential(credType)
            wszCredType = StringToWSTR(credType)
            hr = IDCRL.RemovePersistedCredential(@hIdentity, wszCredType)
            raise LiveIdentityError.new(hr) if LiveIdentity::IsError?(hr)
        end

        def GetAuthState
            hrAuthState = FFI::MemoryPointer.new(:PHRESULT)
            hrAuthRequired = FFI::MemoryPointer.new(:PHRESULT)
            hrRequestStatus = FFI::MemoryPointer.new(:PHRESULT)
            wszWebFlowUrl = FFI::MemoryPointer.new(:LPWSTR)
            hr = IDCRL.GetAuthState(@hIdentity, hrAuthState, hrAuthRequired, hrRequestStatus, wszWebFlowUrl)
            raise LiveIdentityError.new(hr) if LiveIdentity::IsError?(hr)
            status = IDCRL::IDCRL_STATUS_V1.new
            status[:hrAuthState] = hrAuthState.read_long
            status[:hrAuthRequired] = hrAuthRequired.read_long
            status[:hrRequestStatus] = hrRequestStatus.read_long
            status[:wszWebFlowUrl] = wszWebFlowUrl.read_pointer
            status.WebFlowUrl unless status[:wszWebFlowUrl].null?
            LiveIdentity::FreeMemory(status[:wszWebFlowUrl])
            status
        end

        def LogonIdentity(policy, authFlags)
            wszPolicy = StringToWSTR(policy)
            dwAuthFlags = authFlags
            hr = IDCRL.LogonIdentity(@hIdentity, wszPolicy, dwAuthFlags)
            raise LiveIdentityError.new(hr) if LiveIdentity::IsError?(hr)
        end

        def HasPersistedCredential?(credType)
            wszCredType = StringToWSTR(credType)
            lpbPersisted = FFI::MemoryPointer.new(:LONG)
            hr = IDCRL.HasPersistedCredential(@hIdentity, credType, lpbPersisted)
            raise LiveIdentityError.new(hr) if LiveIdentity::IsError?(hr)
            lpbPersisted.read_long == 0x00000001
        end

        def SetCallback(callBackData = nil, &callBackFunction)
            hr = IDCRL.SetIdentityCallback(@hIdentity, callBackFunction, callBackData)
            if WinCommon::Errors::HRESULT::Equal?(hr, IDCRL::HRESULT::PPCRL_E_BUSY)
                sleep(0.1)
                hr = IDCRL.SetIdentityCallback(@hIdentity, callBackFunction, callBackData)
            end
            raise LiveIdentityError.new(hr) if LiveIdentity::IsError?(hr)
        end

        def GetWebAuthUrl(targetServiceName, servicePolicy = 'HBI', additionalPostParams = nil, sourceServiceName = nil)
            wszTargetServiceName = StringToWSTR(targetServiceName)
            wszServicePolicy = StringToWSTR(servicePolicy)
            wszAdditionalPostParams = nil
            wszAdditionalPostParams = StringToWSTR(additionalPostParams) if additionalPostParams
            wszSourceServiceName = nil
            wszSourceServiceName = StringToWSTR(sourceServiceName) if sourceServiceName
            pszMD5Url   = FFI::MemoryPointer.new(:PLPWSTR)
            pszPostData = FFI::MemoryPointer.new(:PLPWSTR)
            hr = IDCRL.GetWebAuthUrl(@hIdentity, wszTargetServiceName, wszServicePolicy, wszAdditionalPostParams, wszSourceServiceName, pszMD5Url, pszPostData)
            raise LiveIdentityError.new(hr) if LiveIdentity::IsError?(hr)
            md5data = IDCRL::MD5Data.new
            md5data[:szMD5Url] = pszMD5Url.read_pointer
            md5data[:szPostData] = pszPostData.read_pointer
            md5data.MD5Url
            md5data.PostData
            LiveIdentity::FreeMemory(pszMD5Url.read_pointer)
            LiveIdentity::FreeMemory(pszPostData.read_pointer)
            md5data
        end

        def LogonIdentityEx(authPolicy, authFlags, rstParams = [])
            wszAuthPolicy = nil
            wszAuthPolicy = StringToWSTR(authPolicy) if authPolicy
            dwAuthFlags = authFlags
            dwpcRSTParamsCount = rstParams.count
            pcRSTParams = LiveIdentity::processRSTParams(rstParams)
            hr = IDCRL.LogonIdentityEx(@hIdentity, wszAuthPolicy, dwAuthFlags, pcRSTParams, dwpcRSTParamsCount)
            raise LiveIdentityError.new(hr) if LiveIdentity::IsError?(hr)
        end

        def AuthToServiceEx(requestFlags, rstParams)
            swRequestFlags = requestFlags
            dwpcRSTParamsCount = rstParams.count
            pcRSTParams = LiveIdentity::processRSTParams(rstParams)
            hr = IDCRL.AuthIdentityToServiceEx(@hIdentity, swRequestFlags, pcRSTParams, dwpcRSTParamsCount)
            raise LiveIdentityError.new(hr) if LiveIdentity::IsError?(hr)
        end

        def GetAuthStateEx(serviceTarget, status)
            wszServiceTarget = StringToWSTR(serviceTarget)
            hr = IDCRL.GetAuthStateEx(@hIdentity, wszServiceTarget, status[:hrAuthState], status[:hrAuthRequired], status[:hrRequestStatus], status[:wszWebFlowUrl])
            raise LiveIdentityError.new(hr) if LiveIdentity::IsError?(hr)
            status.WebFlowUrl
            LiveIdentity::FreeMemory(status[:wszWebFlowUrl])
        end

        def GetCertificate(rstParam, minTTL, requestFlags)
            pcRSTParams = IDCRL::RSTParams.build(rstParam)
            pdwMinTTL = FFI::MemoryPointer.new(:DWORD)
            pdwMinTTL.write_uint(minTTL)
            dwRequestFlags = requestFlags
            certSet = IDCRL::CertSet.build
            cbPOP = FFI::MemoryPointer.new(:DWORD)
            hr = IDCRL.GetCertificate(@hIdentity, pcRSTParams, pdwMinTTL, dwRequestFlags, certSet[:pCertContext], certSet[:pbPOP], cbPOP, certSet[:pCACertContext])
            certSet[:cbPOP] = cbPOP.read_uint
            raise LiveIdentityError.new(hr) if LiveIdentity::IsError?(hr)
            certSet
        end

        def CancelPendingRequest()
            hr = IDCRL.CancelPendingRequest(@hIdentity)
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

        def GetWebAuthUrlEx(webAuthFlag, targetServiceName, servicePolicy = 'HBI', additionalPostParams = nil)
            dwWebAuthFlag = webAuthFlag
            wszTargetServiceName = StringToWSTR(targetServiceName)
            wszServicePolicy = StringToWSTR(servicePolicy)
            wszAdditionalPostParams = nil
            wszAdditionalPostParams = StringToWSTR(additionalPostParams) if additionalPostParams
            pszSHA1Url      = FFI::MemoryPointer.new(:PLPWSTR)
            pszSHA1PostData = FFI::MemoryPointer.new(:PLPWSTR)
            hr = IDCRL.GetWebAuthUrlEx(@hIdentity, dwWebAuthFlag, wszTargetServiceName, wszServicePolicy, wszAdditionalPostParams, pszSHA1Url, pszSHA1PostData)
            raise LiveIdentityError.new(hr) if LiveIdentity::IsError?(hr)
            sha1 = IDCRL::SHA1.new
            sha1[:szSHA1Url] = pszSHA1Url.read_pointer
            sha1[:szSHA1PostData] = pszSHA1PostData.read_pointer
            sha1.SHA1Url
            sha1.SHA1PostData
            LiveIdentity::FreeMemory(pszSHA1Url.read_pointer)
            LiveIdentity::FreeMemory(pszSHA1PostData.read_pointer)
            sha1
        end

        def EncryptWithSessionKey(serviceName, algIdEncrypt, algIdHash, data)
            wszServiceName = StringToWSTR(serviceName)
            dwAlgIdEncrypt = algIdEncrypt
            dwAlgIdHash    = algIdHash
            dwDataSize     = data.count
            pbData         = FFI::MemoryPointer.new(:LPVOID)
            pbData.write_string(data, dwDataSize)
            pbCipher  = FFI::MemoryPointer.new(:PBYTE)
            pdwCipherSize = FFI::MemoryPointer.new(:PDWORD)
            hr = IDCRL.EncryptWithSessionKey(@hIdentity, wszServiceName, dwAlgIdEncrypt, dwAlgIdHash, pbData, dwDataSize, pbCipher, pdwCipherSize)
            raise LiveIdentityError.new(hr) if LiveIdentity::IsError?(hr)
            cipher = pbCipher.read_string(pdwCipherSize.read_pointer.read_uint)
            LiveIdentity::FreeMemory(pbCipher.read_pointer)
            cipher
        end

        def DecryptWithSessionKey(serviceName, algIdEncrypt, algIdHash, cipher)
            wszServiceName = StringToWSTR(serviceName)
            dwAlgIdEncrypt = algIdEncrypt
            dwAlgIdHash    = algIdHash
            dwCipherSize   = cipher.bytesize
            pbCipher       = FFI::MemoryPointer.new(:LPVOID)
            pbCipher.write_string(cipher, dwCipherSize)
            pbData      = FFI::MemoryPointer.new(:LPVOID)
            pdwDataSize = FFI::MemoryPointer.new(:PDWORD)
            hr = IDCRL.DecryptWithSessionKey(@hIdentity, wszServiceName, dwAlgIdEncrypt, dwAlgIdHash, pbCipher, dwCipherSize, pbData, pdwDataSize)
            raise LiveIdentityError.new(hr) if LiveIdentity::IsError?(hr)
            data = pbData.read_string(pdwDataSize.read_pointer.read_uint)
            LiveIdentity::FreeMemory(pbData.read_pointer)
            data
        end

        def GetExtendedError
            ExtendedError.new(self)
        end

        def IsAuthenticated?
            state = GetAuthState()
            if !state.IsAuthenticated?
                if !WinCommon::Errors::HRESULT::Equal?(state.RequestStatus, [WinCommon::Errors::HRESULT::S_OK, IDCRL::HRESULT::PPCRL_AUTHREQUIRED_E_PASSWORD])
                    puts GetExtendedError() if WinCommon::Errors::HRESULT::Equal?(state.RequestStatus, IDCRL::HRESULT::PPCRL_REQUEST_E_AUTH_SERVER_ERROR)
                    raise LiveIdentityError.new(state.RequestStatus)
                end
                if !WinCommon::Errors::HRESULT::Equal?(state.AuthState, [WinCommon::Errors::HRESULT::S_OK, IDCRL::HRESULT::PPCRL_AUTHSTATE_E_UNAUTHENTICATED, IDCRL::HRESULT::PPCRL_AUTHSTATE_E_EXPIRED])
                    raise LiveIdentityError.new(state.AuthState)
                end
                return false
            end
            true
        end

        def Authenticate(authPolicy, authFlags)
            done = false
            SetCallback() do |identity, data, canContinue|
                done = true
                0
            end
            begin
                LogonIdentityEx(authPolicy, authFlags)
            rescue LiveIdentityError
                state = GetAuthState()
                puts state
                CancelPendingRequest()
                puts GetExtendedError() if WinCommon::Errors::HRESULT::Equal?(state.RequestStatus, IDCRL::HRESULT::PPCRL_REQUEST_E_AUTH_SERVER_ERROR)
                raise
            end
            LiveIdentity::waitFor(Proc.new {done}, 'Authentication Timeout!') { CancelPendingRequest() }
            state = GetAuthState()
            if !state.IsAuthenticated?
                puts state
                CancelPendingRequest()
                puts GetExtendedError() if WinCommon::Errors::HRESULT::Equal?(state.RequestStatus, IDCRL::HRESULT::PPCRL_REQUEST_E_AUTH_SERVER_ERROR)
                raise LiveIdentityError.new(state.RequestStatus) if LiveIdentity::IsError?(state.RequestStatus)
                raise LiveIdentityError.new(state.AuthState)
            end
        ensure
            SetCallback()
        end

        def GetService(target, policy = 'HBI', flags = :SERVICE_TOKEN_FROM_CACHE, sessionKey = false)
            begin
                authState = AuthToService(target, policy, flags, sessionKey)
            rescue LiveIdentityError => e
                done = false
                SetCallback() do |identity, data, canContinue|
                    done = true
                    0
                end
                if WinCommon::Errors::HRESULT::Equal?(e.code, [IDCRL::HRESULT::PPCRL_E_BUSY, IDCRL::HRESULT::PPCRL_E_UNABLE_TO_RETRIEVE_SERVICE_TOKEN, IDCRL::HRESULT::PPCRL_REQUEST_E_FORCE_SIGNIN])
                    authState = AuthToService(target, policy, :SERVICE_TOKEN_REQUEST_TYPE_NONE, sessionKey)
                    LiveIdentity::waitFor(Proc.new {done}, 'Authorization Timeout!') { CancelPendingRequest() }
                    state = GetAuthState()
                    if !state.IsAuthenticated?
                        puts state
                        puts GetExtendedError() if WinCommon::Errors::HRESULT::Equal?(state.RequestStatus, IDCRL::HRESULT::PPCRL_REQUEST_E_AUTH_SERVER_ERROR)
                        raise LiveIdentityError.new(state.RequestStatus) if LiveIdentity::IsError?(state.RequestStatus)
                        raise LiveIdentityError.new(state.AuthState)
                    end
                else
                    raise
                end
            ensure
                SetCallback()
            end
            authState = AuthToService(target, policy, :SERVICE_TOKEN_FROM_CACHE, sessionKey) unless authState.Token()
            Service.new(authState)
        end

        class ExtendedError
            attr_reader :Category
            attr_reader :Error
            attr_reader :ErrorBlob
            attr_reader :ErrorBlobXML
            def initialize(identity)
                @Category = nil
                @Error = nil
                @ErrorBlob = nil
                @ErrorBlobXML = nil
                hIdentity = identity.hIdentity
                pdwCategory = FFI::MemoryPointer.new(:PDWORD)
                pdwError = FFI::MemoryPointer.new(:PDWORD)
                pszErrorBlob = FFI::MemoryPointer.new(:LPWSTR)
                hr = IDCRL.GetExtendedError(hIdentity, nil, pdwCategory, pdwError, pszErrorBlob)
                raise LiveIdentityError.new(hr) if LiveIdentity::IsError?(hr)
                @Category = pdwCategory.read_uint
                @Error = pdwError.read_uint
                @ErrorBlob = read_wide_string(pszErrorBlob.read_pointer)
                @ErrorBlobXML = Nokogiri::XML(@ErrorBlob)
                LiveIdentity::FreeMemory(pszErrorBlob.read_pointer)
            end

            def BlobResponse
                return unless @ErrorBlobXML
                @BlobResponse ||= Nokogiri::XML(@ErrorBlobXML.xpath('/IDCRLErrorInfo/Response').first.content)
            end

            def BlobResponseError
                response = BlobResponse()
                reasonText        = response.xpath('//S:Fault/S:Reason/S:Text').first.content
                errorValue        = response.xpath('//S:Fault/S:Detail/psf:error/psf:value').first.content.strip.to_i(16)
                internalError     = response.xpath('//S:Fault/S:Detail/psf:error/psf:internalerror/psf:code').first.content.strip.to_i(16)
                internalErrorText = response.xpath('//S:Fault/S:Detail/psf:error/psf:internalerror/psf:text').first.content.strip
                "ReasonText:    #{reasonText}\n" +
                "ErrorValue:    #{WinCommon::Errors::HRESULT::GetNameCode(errorValue)}\n" +
                "InternalError: #{internalErrorText} #{WinCommon::Errors::HRESULT::GetNameCode(internalError)}\n"
            end

            def to_s
                "Category:      #{IDCRL::IDCRL_ERROR_CATEGORY.to_h[@Category]} (#{@Category})\n" +
                "Error:         #{WinCommon::Errors::HRESULT::GetNameCode(@Error)}\n" + BlobResponseError()
            end
        end

        class Service
            attr_reader :Token
            attr_reader :ResultFlags
            attr_reader :SessionKey
            def initialize(authState)
                @Token = authState.Token()
                @ResultFlags = authState.ResultFlags()
                @SessionKey = authState.SessionKey()
            end
        end
    end
end
