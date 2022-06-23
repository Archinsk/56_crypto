;(function () {
    console.log("Inside CADES");
    function setExtensionLoadingInfo() {
        console.log("Расширение загружено");
        console.log("Обновляю информацию о расширении");
        if (document.getElementById('ExtensionEnabledImg'))
            document.getElementById('ExtensionEnabledImg').setAttribute("src", "Img/green_dot.png");
        if (document.getElementById('ExtensionEnabledTxt'))
            document.getElementById('ExtensionEnabledTxt').innerHTML = "Расширение загружено";
        if (document.getElementById('PluginEnabledImg'))
            document.getElementById('PluginEnabledImg').setAttribute("src", "Img/red_dot.png");
        if (document.getElementById('PlugInEnabledTxt'))
            document.getElementById('PlugInEnabledTxt').innerHTML = "Плагин не загружен";
        window.cadesplugin_extension_loaded = true;
    }
    function extensionLoadedCallback() {
        window.onload = function (e) {
            setExtensionLoadingInfo();
        }
        setExtensionLoadingInfo();
    }
    window.cadesplugin_extension_loaded_callback = extensionLoadedCallback;

    // start true cades_api;

    //already loaded
    if(window.cadesplugin)
        return;

    var pluginObject;
    var plugin_resolved = 0;
    var plugin_reject;
    var plugin_resolve;
    var isOpera = 0;
    var isFireFox = 0;
    var isSafari = 0;
    var isYandex = 0;
    var canPromise = !!window.Promise;
    var cadesplugin_loaded_event_recieved = false;
    var isFireFoxExtensionLoaded = false;
    var cadesplugin;

    if(canPromise)
    {
        cadesplugin = new Promise(function(resolve, reject)
        {
            plugin_resolve = resolve;
            plugin_reject = reject;
        });
    } else
    {
        cadesplugin = {};
    }

    function check_browser() {
        var ua= navigator.userAgent, tem, M= ua.match(/(opera|yabrowser|chrome|safari|firefox|msie|trident(?=\/))\/?\s*(\d+)/i) || [];
        if(/trident/i.test(M[1])){
            tem =  /\brv[ :]+(\d+)/g.exec(ua) || [];
            return { name:'IE', version:(tem[1] || '')};
        }
        if(M[1] === 'Chrome'){
            tem = ua.match(/\b(OPR|Edg|YaBrowser)\/(\d+)/);
            if (tem != null)
                return { name: tem[1].replace('OPR', 'Opera'), version: tem[2] };
        }
        M= M[2]? [M[1], M[2]]: [navigator.appName, navigator.appVersion, '-?'];
        if ((tem = ua.match(/version\/(\d+)/i)) != null)
            M.splice(1, 1, tem[1]);
        return {name:M[0],version:M[1]};
    }
    var browserSpecs = check_browser();

    function cpcsp_console_log(level, msg){
        //IE9 не может писать в консоль если не открыта вкладка developer tools
        if(typeof(console) === 'undefined')
            return;
        if (level <= cadesplugin.current_log_level ){
            if (level === cadesplugin.LOG_LEVEL_DEBUG)
                console.log("DEBUG: %s", msg);
            if (level === cadesplugin.LOG_LEVEL_INFO)
                console.info("INFO: %s", msg);
            if (level === cadesplugin.LOG_LEVEL_ERROR)
                console.error("ERROR: %s", msg);
            return;
        }
    }

    function set_log_level(level){
        if (!((level === cadesplugin.LOG_LEVEL_DEBUG) ||
            (level === cadesplugin.LOG_LEVEL_INFO) ||
            (level === cadesplugin.LOG_LEVEL_ERROR))){
            cpcsp_console_log(cadesplugin.LOG_LEVEL_ERROR, "cadesplugin_api.js: Incorrect log_level: " + level);
            return;
        }
        cadesplugin.current_log_level = level;
        if (cadesplugin.current_log_level === cadesplugin.LOG_LEVEL_DEBUG)
            cpcsp_console_log(cadesplugin.LOG_LEVEL_INFO, "cadesplugin_api.js: log_level = DEBUG");
        if (cadesplugin.current_log_level === cadesplugin.LOG_LEVEL_INFO)
            cpcsp_console_log(cadesplugin.LOG_LEVEL_INFO, "cadesplugin_api.js: log_level = INFO");
        if (cadesplugin.current_log_level === cadesplugin.LOG_LEVEL_ERROR)
            cpcsp_console_log(cadesplugin.LOG_LEVEL_INFO, "cadesplugin_api.js: log_level = ERROR");
        if(isNativeMessageSupported())
        {
            if (cadesplugin.current_log_level === cadesplugin.LOG_LEVEL_DEBUG)
                window.postMessage("set_log_level=debug", "*");
            if (cadesplugin.current_log_level === cadesplugin.LOG_LEVEL_INFO)
                window.postMessage("set_log_level=info", "*");
            if (cadesplugin.current_log_level === cadesplugin.LOG_LEVEL_ERROR)
                window.postMessage("set_log_level=error", "*");
        }
    }

    function set_constantValues()
    {
        cadesplugin.CAPICOM_MEMORY_STORE = 0;
        cadesplugin.CAPICOM_LOCAL_MACHINE_STORE = 1;
        cadesplugin.CAPICOM_CURRENT_USER_STORE = 2;
        cadesplugin.CAPICOM_SMART_CARD_USER_STORE = 4;
        cadesplugin.CADESCOM_MEMORY_STORE = 0;
        cadesplugin.CADESCOM_LOCAL_MACHINE_STORE = 1;
        cadesplugin.CADESCOM_CURRENT_USER_STORE = 2;
        cadesplugin.CADESCOM_SMART_CARD_USER_STORE = 4;
        cadesplugin.CADESCOM_CONTAINER_STORE = 100;

        cadesplugin.CAPICOM_MY_STORE = "My";

        cadesplugin.CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED = 2;

        cadesplugin.CAPICOM_CERTIFICATE_FIND_SUBJECT_NAME = 1;

        cadesplugin.CADESCOM_XML_SIGNATURE_TYPE_ENVELOPED = 0;
        cadesplugin.CADESCOM_XML_SIGNATURE_TYPE_ENVELOPING = 1;
        cadesplugin.CADESCOM_XML_SIGNATURE_TYPE_TEMPLATE = 2;

        cadesplugin.CADESCOM_XADES_DEFAULT = 0x00000010;
        cadesplugin.CADESCOM_XADES_BES = 0x00000020;
        cadesplugin.CADESCOM_XADES_T = 0x00000050;
        cadesplugin.CADESCOM_XADES_X_LONG_TYPE_1 = 0x000005d0;
        cadesplugin.CADESCOM_XMLDSIG_TYPE = 0x00000000;

        cadesplugin.XmlDsigGost3410UrlObsolete = "http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411";
        cadesplugin.XmlDsigGost3411UrlObsolete = "http://www.w3.org/2001/04/xmldsig-more#gostr3411";
        cadesplugin.XmlDsigGost3410Url = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102001-gostr3411";
        cadesplugin.XmlDsigGost3411Url = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr3411";

        cadesplugin.XmlDsigGost3411Url2012256 = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256";
        cadesplugin.XmlDsigGost3410Url2012256 = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256";
        cadesplugin.XmlDsigGost3411Url2012512 = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-512";
        cadesplugin.XmlDsigGost3410Url2012512 = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-512";

        cadesplugin.CADESCOM_CADES_DEFAULT = 0;
        cadesplugin.CADESCOM_CADES_BES = 1;
        cadesplugin.CADESCOM_CADES_T = 0x5;
        cadesplugin.CADESCOM_CADES_X_LONG_TYPE_1 = 0x5d;
        cadesplugin.CADESCOM_PKCS7_TYPE = 0xffff;

        cadesplugin.CADESCOM_ENCODE_BASE64 = 0;
        cadesplugin.CADESCOM_ENCODE_BINARY = 1;
        cadesplugin.CADESCOM_ENCODE_ANY = -1;

        cadesplugin.CAPICOM_CERTIFICATE_INCLUDE_CHAIN_EXCEPT_ROOT = 0;
        cadesplugin.CAPICOM_CERTIFICATE_INCLUDE_WHOLE_CHAIN = 1;
        cadesplugin.CAPICOM_CERTIFICATE_INCLUDE_END_ENTITY_ONLY = 2;

        cadesplugin.CAPICOM_CERT_INFO_SUBJECT_SIMPLE_NAME = 0;
        cadesplugin.CAPICOM_CERT_INFO_ISSUER_SIMPLE_NAME = 1;

        cadesplugin.CAPICOM_CERTIFICATE_FIND_SHA1_HASH = 0;
        cadesplugin.CAPICOM_CERTIFICATE_FIND_SUBJECT_NAME = 1;
        cadesplugin.CAPICOM_CERTIFICATE_FIND_ISSUER_NAME = 2;
        cadesplugin.CAPICOM_CERTIFICATE_FIND_ROOT_NAME = 3;
        cadesplugin.CAPICOM_CERTIFICATE_FIND_TEMPLATE_NAME = 4;
        cadesplugin.CAPICOM_CERTIFICATE_FIND_EXTENSION = 5;
        cadesplugin.CAPICOM_CERTIFICATE_FIND_EXTENDED_PROPERTY = 6;
        cadesplugin.CAPICOM_CERTIFICATE_FIND_APPLICATION_POLICY = 7;
        cadesplugin.CAPICOM_CERTIFICATE_FIND_CERTIFICATE_POLICY = 8;
        cadesplugin.CAPICOM_CERTIFICATE_FIND_TIME_VALID = 9;
        cadesplugin.CAPICOM_CERTIFICATE_FIND_TIME_NOT_YET_VALID = 10;
        cadesplugin.CAPICOM_CERTIFICATE_FIND_TIME_EXPIRED = 11;
        cadesplugin.CAPICOM_CERTIFICATE_FIND_KEY_USAGE = 12;

        cadesplugin.CAPICOM_DIGITAL_SIGNATURE_KEY_USAGE = 128;

        cadesplugin.CAPICOM_PROPID_ENHKEY_USAGE = 9;

        cadesplugin.CAPICOM_OID_OTHER = 0;
        cadesplugin.CAPICOM_OID_KEY_USAGE_EXTENSION = 10;

        cadesplugin.CAPICOM_EKU_CLIENT_AUTH = 2;
        cadesplugin.CAPICOM_EKU_SMARTCARD_LOGON = 5;
        cadesplugin.CAPICOM_EKU_OTHER = 0;

        cadesplugin.CAPICOM_AUTHENTICATED_ATTRIBUTE_SIGNING_TIME = 0;
        cadesplugin.CAPICOM_AUTHENTICATED_ATTRIBUTE_DOCUMENT_NAME = 1;
        cadesplugin.CAPICOM_AUTHENTICATED_ATTRIBUTE_DOCUMENT_DESCRIPTION = 2;
        cadesplugin.CADESCOM_AUTHENTICATED_ATTRIBUTE_SIGNING_TIME = 0;
        cadesplugin.CADESCOM_AUTHENTICATED_ATTRIBUTE_DOCUMENT_NAME = 1;
        cadesplugin.CADESCOM_AUTHENTICATED_ATTRIBUTE_DOCUMENT_DESCRIPTION = 2;
        cadesplugin.CADESCOM_AUTHENTICATED_ATTRIBUTE_MACHINE_INFO = 0x100;
        cadesplugin.CADESCOM_ATTRIBUTE_OTHER = -1;

        cadesplugin.CADESCOM_STRING_TO_UCS2LE = 0;
        cadesplugin.CADESCOM_BASE64_TO_BINARY = 1;

        cadesplugin.CADESCOM_DISPLAY_DATA_NONE = 0;
        cadesplugin.CADESCOM_DISPLAY_DATA_CONTENT = 1;
        cadesplugin.CADESCOM_DISPLAY_DATA_ATTRIBUTE = 2;

        cadesplugin.CADESCOM_ENCRYPTION_ALGORITHM_RC2 = 0;
        cadesplugin.CADESCOM_ENCRYPTION_ALGORITHM_RC4 = 1;
        cadesplugin.CADESCOM_ENCRYPTION_ALGORITHM_DES = 2;
        cadesplugin.CADESCOM_ENCRYPTION_ALGORITHM_3DES = 3;
        cadesplugin.CADESCOM_ENCRYPTION_ALGORITHM_AES = 4;
        cadesplugin.CADESCOM_ENCRYPTION_ALGORITHM_GOST_28147_89 = 25;

        cadesplugin.CADESCOM_HASH_ALGORITHM_SHA1 = 0;
        cadesplugin.CADESCOM_HASH_ALGORITHM_MD2 = 1;
        cadesplugin.CADESCOM_HASH_ALGORITHM_MD4 = 2;
        cadesplugin.CADESCOM_HASH_ALGORITHM_MD5 = 3;
        cadesplugin.CADESCOM_HASH_ALGORITHM_SHA_256 = 4;
        cadesplugin.CADESCOM_HASH_ALGORITHM_SHA_384 = 5;
        cadesplugin.CADESCOM_HASH_ALGORITHM_SHA_512 = 6;
        cadesplugin.CADESCOM_HASH_ALGORITHM_CP_GOST_3411 = 100;
        cadesplugin.CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_256 = 101;
        cadesplugin.CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_512 = 102;
        cadesplugin.CADESCOM_HASH_ALGORITHM_CP_GOST_3411_HMAC = 110;
        cadesplugin.CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_256_HMAC = 111;
        cadesplugin.CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_512_HMAC = 112;

        cadesplugin.LOG_LEVEL_DEBUG = 4;
        cadesplugin.LOG_LEVEL_INFO = 2;
        cadesplugin.LOG_LEVEL_ERROR = 1;

        cadesplugin.CADESCOM_AllowNone = 0;
        cadesplugin.CADESCOM_AllowNoOutstandingRequest = 0x1;
        cadesplugin.CADESCOM_AllowUntrustedCertificate = 0x2;
        cadesplugin.CADESCOM_AllowUntrustedRoot = 0x4;
        cadesplugin.CADESCOM_SkipInstallToStore = 0x10000000;
        cadesplugin.CADESCOM_InstallCertChainToContainer = 0x20000000;
        cadesplugin.CADESCOM_UseContainerStore = 0x40000000;

        cadesplugin.ENABLE_CARRIER_TYPE_CSP = 0x01;
        cadesplugin.ENABLE_CARRIER_TYPE_FKC_NO_SM = 0x02;
        cadesplugin.ENABLE_CARRIER_TYPE_FKC_SM = 0x04;
        cadesplugin.ENABLE_ANY_CARRIER_TYPE = 0x07;

        cadesplugin.DISABLE_EVERY_CARRIER_OPERATION = 0x00;
        cadesplugin.ENABLE_CARRIER_OPEN_ENUM = 0x01;
        cadesplugin.ENABLE_CARRIER_CREATE = 0x02;
        cadesplugin.ENABLE_ANY_OPERATION = 0x03;

        cadesplugin.CADESCOM_PRODUCT_CSP = 0;
        cadesplugin.CADESCOM_PRODUCT_OCSP = 1;
        cadesplugin.CADESCOM_PRODUCT_TSP = 2;

        cadesplugin.MEDIA_TYPE_REGISTRY = 0x00000001;
        cadesplugin.MEDIA_TYPE_HDIMAGE = 0x00000002;
        cadesplugin.MEDIA_TYPE_CLOUD = 0x00000004;
        cadesplugin.MEDIA_TYPE_SCARD = 0x00000008;

        cadesplugin.XCN_CRYPT_STRING_BASE64HEADER = 0;
        cadesplugin.AT_KEYEXCHANGE = 1;
        cadesplugin.AT_SIGNATURE = 2;

        cadesplugin.CARRIER_FLAG_REMOVABLE = 1;
        cadesplugin.CARRIER_FLAG_UNIQUE = 2;
        cadesplugin.CARRIER_FLAG_PROTECTED = 4;
        cadesplugin.CARRIER_FLAG_FUNCTIONAL_CARRIER = 8;
        cadesplugin.CARRIER_FLAG_SECURE_MESSAGING = 16;
        cadesplugin.CARRIER_FLAG_ABLE_VISUALISE_SIGNATURE = 64;
        cadesplugin.CARRIER_FLAG_VIRTUAL = 128;
    }

    function async_spawn(generatorFunc) {

        function continuer(verb, arg) {
            var result;
            try {
                result = generator[verb](arg);
            } catch (err) {
                return Promise.reject(err);
            }
            if (result.done) {
                return result.value;
            } else {
                return Promise.resolve(result.value).then(onFulfilled, onRejected);
            }
        }
        var generator = generatorFunc(Array.prototype.slice.call(arguments, 1));
        var onFulfilled = continuer.bind(continuer, "next");
        var onRejected = continuer.bind(continuer, "throw");
        return onFulfilled();
    }

    function isIE() {
        // var retVal = (("Microsoft Internet Explorer" == navigator.appName) || // IE < 11
        //     navigator.userAgent.match(/Trident\/./i)); // IE 11
        return (browserSpecs.name === 'IE' || browserSpecs.name === 'MSIE');
    }

    function isIOS() {
        return (navigator.userAgent.match(/ipod/i) ||
            navigator.userAgent.match(/ipad/i) ||
            navigator.userAgent.match(/iphone/i));
    }

    function isNativeMessageSupported()
    {
        // В IE работаем через NPAPI
        if(isIE())
            return false;
        // В Edge работаем через NativeMessage
        if (browserSpecs.name === 'Edg') {
            return true;
        }
        if (browserSpecs.name === 'YaBrowser') {
            isYandex = true;
            return true;
        }
        // В Chrome, Firefox, Safari и Opera работаем через асинхронную версию в зависимости от версии
        if(browserSpecs.name === 'Opera') {
            isOpera = true;
            if(browserSpecs.version >= 33){
                return true;
            }
            else{
                return false;
            }
        }
        if(browserSpecs.name === 'Firefox') {
            isFireFox = true;
            if(browserSpecs.version >= 52){
                return true;
            }
            else{
                return false;
            }
        }
        if(browserSpecs.name === 'Chrome') {
            if(browserSpecs.version >= 42){
                return true;
            }
            else{
                return false;
            }
        }
        //В Сафари начиная с 12 версии нет NPAPI
        if(browserSpecs.name === 'Safari') {
            isSafari = true;
            if(browserSpecs.version >= 12) {
                return true;
            } else {
                return false;
            }
        }
    }

    // Функция активации объектов КриптоПро ЭЦП Browser plug-in
    function CreateObject(name) {
        if (isIOS()) {
            // На iOS для создания объектов используется функция
            // call_ru_cryptopro_npcades_10_native_bridge, определенная в IOS_npcades_supp.js
            return call_ru_cryptopro_npcades_10_native_bridge("CreateObject", [name]);
        }
        if (isIE()) {
            // В Internet Explorer создаются COM-объекты
            if (name.match(/X509Enrollment/i)) {
                try {
                    // Объекты CertEnroll пробуем создавать через нашу фабрику,
                    // если не получилось то через CX509EnrollmentWebClassFactory
                    var objCertEnrollClassFactory = document.getElementById("webClassFactory");
                    return objCertEnrollClassFactory.CreateObject(name);
                }
                catch (e) {
                    try {
                        var objWebClassFactory = document.getElementById("certEnrollClassFactory");
                        return objWebClassFactory.CreateObject(name);
                    }
                    catch (err) {
                        throw ("Для создания обьектов X509Enrollment следует настроить веб-узел на использование проверки подлинности по протоколу HTTPS");
                    }
                }
            }
            // Объекты CAPICOM и CAdESCOM создаются через CAdESCOM.WebClassFactory
            try {
                var objWebClassFactory = document.getElementById("webClassFactory");
                return objWebClassFactory.CreateObject(name);
            }
            catch (e) {
                // Для версий плагина ниже 2.0.12538
                return new ActiveXObject(name);
            }
        }
        // создаются объекты NPAPI
        return pluginObject.CreateObject(name);
    }

    function decimalToHexString(number) {
        if (number < 0) {
            number = 0xFFFFFFFF + number + 1;
        }

        return number.toString(16).toUpperCase();
    }

    function GetMessageFromException(e) {
        var err = e.message;
        if (!err) {
            err = e;
        } else if (e.number) {
            err += " (0x" + decimalToHexString(e.number) + ")";
        }
        return err;
    }

    function getLastError(exception) {
        if(isNativeMessageSupported() || isIE() || isIOS() ) {
            return GetMessageFromException(exception);
        }

        try {
            return pluginObject.getLastError();
        } catch(e) {
            return GetMessageFromException(exception);
        }
    }

    // Функция для удаления созданных объектов
    function ReleasePluginObjects() {
        return cpcsp_chrome_nmcades.ReleasePluginObjects();
    }

    // Функция активации асинхронных объектов КриптоПро ЭЦП Browser plug-in
    function CreateObjectAsync(name) {
        return pluginObject.CreateObjectAsync(name);
    }

    //Функции для IOS
    var ru_cryptopro_npcades_10_native_bridge = {
        callbacksCount : 1,
        callbacks : {},

        // Automatically called by native layer when a result is available
        resultForCallback : function resultForCallback(callbackId, resultArray) {
            var callback = ru_cryptopro_npcades_10_native_bridge.callbacks[callbackId];
            if (!callback) return;
            callback.apply(null,resultArray);
        },

        // Use this in javascript to request native objective-c code
        // functionName : string (I think the name is explicit :p)
        // args : array of arguments
        // callback : function with n-arguments that is going to be called when the native code returned
        call : function call(functionName, args, callback) {
            var hasCallback = callback && typeof callback === "function";
            var callbackId = hasCallback ? ru_cryptopro_npcades_10_native_bridge.callbacksCount++ : 0;

            if (hasCallback)
                ru_cryptopro_npcades_10_native_bridge.callbacks[callbackId] = callback;

            var iframe = document.createElement("IFRAME");
            var arrObjs = new Array("_CPNP_handle");
            try{
                iframe.setAttribute("src", "cpnp-js-call:" + functionName + ":" + callbackId+ ":" + encodeURIComponent(JSON.stringify(args, arrObjs)));
            } catch(e){
                alert(e);
            }
            document.documentElement.appendChild(iframe);
            iframe.parentNode.removeChild(iframe);
            iframe = null;
        }
    };

    function call_ru_cryptopro_npcades_10_native_bridge(functionName, array){
        var tmpobj;
        var ex;
        ru_cryptopro_npcades_10_native_bridge.call(functionName, array, function(e, response){
            ex = e;
            var str='tmpobj='+response;
            eval(str);
            if (typeof (tmpobj) === "string"){
                tmpobj = tmpobj.replace(/\\\n/gm, "\n");
                tmpobj = tmpobj.replace(/\\\r/gm, "\r");
            }
        });
        if(ex)
            throw ex;
        return tmpobj;
    }

    function show_firefox_missing_extension_dialog()
    {
        if (!window.cadesplugin_skip_extension_install)
        {
            var ovr = document.createElement('div');
            ovr.id = "cadesplugin_ovr";
            ovr.style = "visibility: hidden; position: fixed; left: 0px; top: 0px; width:100%; height:100%; background-color: rgba(0,0,0,0.7)";
            ovr.innerHTML = "<div id='cadesplugin_ovr_item' style='position:relative; width:400px; margin:100px auto; background-color:#fff; border:2px solid #000; padding:10px; text-align:center; opacity: 1; z-index: 1500'>" +
                "<button id='cadesplugin_close_install' style='float: right; font-size: 10px; background: transparent; border: 1; margin: -5px'>X</button>" +
                "<p>Для работы КриптоПро ЭЦП Browser plugin на данном сайте необходимо расширение для браузера. Убедитесь, что оно у Вас включено или установите его." +
                "<p><a href='https://www.cryptopro.ru/sites/default/files/products/cades/extensions/firefox_cryptopro_extension_latest.xpi'>Скачать расширение</a></p>" +
                "</div>";
            document.getElementsByTagName("Body")[0].appendChild(ovr);
            document.getElementById("cadesplugin_close_install").addEventListener('click',function()
            {
                plugin_loaded_error("Плагин недоступен");
                document.getElementById("cadesplugin_ovr").style.visibility = 'hidden';
            });

            ovr.addEventListener('click',function()
            {
                plugin_loaded_error("Плагин недоступен");
                document.getElementById("cadesplugin_ovr").style.visibility = 'hidden';
            });
            ovr.style.visibility="visible";
        }
    }
    function firefox_or_safari_nmcades_onload() {
        if (window.cadesplugin_extension_loaded_callback)
            window.cadesplugin_extension_loaded_callback();
        isFireFoxExtensionLoaded = true;
        cpcsp_chrome_nmcades.check_chrome_plugin(plugin_loaded, plugin_loaded_error);
    }

    function nmcades_api_onload() {
        if (!isIE() && !isFireFox && !isSafari) {
            if (window.cadesplugin_extension_loaded_callback)
                window.cadesplugin_extension_loaded_callback();
        }
        window.postMessage("cadesplugin_echo_request", "*");
        window.addEventListener("message", function (event){
            if (typeof(event.data) !== "string" || !event.data.match("cadesplugin_loaded"))
                return;
            if (cadesplugin_loaded_event_recieved)
                return;
            if(isFireFox || isSafari)
            {
                // Для Firefox, Сафари вместе с сообщением cadesplugin_loaded прилетает url для загрузки nmcades_plugin_api.js
                var url = event.data.substring(event.data.indexOf("url:") + 4);
                if (!url.match("^moz-extension://[a-zA-Z0-9-]+/nmcades_plugin_api.js$")
                    && !url.match("^safari-extension://[a-zA-Z0-9-]+/[a-zA-Z0-9]+/nmcades_plugin_api.js$"))
                {
                    cpcsp_console_log(cadesplugin.LOG_LEVEL_ERROR, "Bad url \"" + url + "\" for load CryptoPro Extension for CAdES Browser plug-in");
                    plugin_loaded_error();
                    return;
                }
                var fileref = document.createElement('script');
                fileref.setAttribute("type", "text/javascript");
                fileref.setAttribute("src", url);
                fileref.onerror = plugin_loaded_error;
                fileref.onload = firefox_or_safari_nmcades_onload;
                document.getElementsByTagName("head")[0].appendChild(fileref);
            }else {
                cpcsp_chrome_nmcades.check_chrome_plugin(plugin_loaded, plugin_loaded_error);
            }
            cadesplugin_loaded_event_recieved = true;
        }, false);
    }

    //Загружаем расширения для Chrome, Opera, YaBrowser, FireFox, Edge, Safari
    function load_extension()
    {
        if(isFireFox || isSafari){
            // вызываем callback руками т.к. нам нужно узнать ID расширения. Он уникальный для браузера.
            nmcades_api_onload();
        } else {
            // в асинхронном варианте для Yandex и Opera подключаем расширение из Opera store.
            if (isOpera || isYandex) {
                var fileref = document.createElement('script');
                fileref.setAttribute("type", "text/javascript");
                fileref.setAttribute("src", "chrome-extension://epebfcehmdedogndhlcacafjaacknbcm/nmcades_plugin_api.js");
                fileref.onerror = plugin_loaded_error;
                fileref.onload = nmcades_api_onload;
                document.getElementsByTagName("head")[0].appendChild(fileref);
            } else {
                // для Chrome, Chromium, Chromium Edge расширение из Chrome store
                var fileref = document.createElement('script');
                fileref.setAttribute("type", "text/javascript");
                fileref.setAttribute("src", "chrome-extension://iifchhfnnmpdbibifmljnfjhpififfog/nmcades_plugin_api.js");
                fileref.onerror = plugin_loaded_error;
                fileref.onload = nmcades_api_onload;
                document.getElementsByTagName("head")[0].appendChild(fileref);
            }
        }
    }

    //Загружаем плагин для NPAPI
    function load_npapi_plugin()
    {
        var elem = document.createElement('object');
        elem.setAttribute("id", "cadesplugin_object");
        elem.setAttribute("type", "application/x-cades");
        elem.setAttribute("style", "visibility: hidden");
        document.getElementsByTagName("body")[0].appendChild(elem);
        pluginObject = document.getElementById("cadesplugin_object");
        if(isIE())
        {
            var elem1 = document.createElement('object');
            elem1.setAttribute("id", "certEnrollClassFactory");
            elem1.setAttribute("classid", "clsid:884e2049-217d-11da-b2a4-000e7bbb2b09");
            elem1.setAttribute("style", "visibility: hidden");
            document.getElementsByTagName("body")[0].appendChild(elem1);
            var elem2 = document.createElement('object');
            elem2.setAttribute("id", "webClassFactory");
            elem2.setAttribute("classid", "clsid:B04C8637-10BD-484E-B0DA-B8A039F60024");
            elem2.setAttribute("style", "visibility: hidden");
            document.getElementsByTagName("body")[0].appendChild(elem2);
        }
    }

    //Отправляем событие что все ок.
    function plugin_loaded()
    {
        plugin_resolved = 1;
        if(canPromise)
        {
            plugin_resolve();
        }else {
            window.postMessage("cadesplugin_loaded", "*");
        }
    }

    //Отправляем событие что сломались.
    function plugin_loaded_error(msg)
    {
        if(typeof(msg) === 'undefined' || typeof(msg) === 'object')
            msg = "Плагин недоступен";
        plugin_resolved = 1;
        if(canPromise)
        {
            plugin_reject(msg);
        } else {
            window.postMessage("cadesplugin_load_error", "*");
        }
    }

    //проверяем что у нас хоть какое то событие ушло, и если не уходило кидаем еще раз ошибку
    function check_load_timeout()
    {
        if(plugin_resolved === 1)
            return;
        if(isFireFox)
        {
            if (!isFireFoxExtensionLoaded)
                show_firefox_missing_extension_dialog();
        }
        plugin_resolved = 1;
        if(canPromise)
        {
            plugin_reject("Истекло время ожидания загрузки плагина");
        } else {
            window.postMessage("cadesplugin_load_error", "*");
        }

    }

    //Вспомогательная функция для NPAPI
    function createPromise(arg)
    {
        return new Promise(arg);
    }

    function check_npapi_plugin (){
        try {
            var oAbout = CreateObject("CAdESCOM.About");
            plugin_loaded();
        }
        catch (err) {
            document.getElementById("cadesplugin_object").style.display = 'none';
            // Объект создать не удалось, проверим, установлен ли
            // вообще плагин. Такая возможность есть не во всех браузерах
            var mimetype = navigator.mimeTypes["application/x-cades"];
            if (mimetype) {
                var plugin = mimetype.enabledPlugin;
                if (plugin) {
                    plugin_loaded_error("Плагин загружен, но не создаются обьекты");
                }else
                {
                    plugin_loaded_error("Ошибка при загрузке плагина");
                }
            }else
            {
                plugin_loaded_error("Плагин недоступен");
            }
        }
    }

    //Проверяем работает ли плагин
    function check_plugin_working()
    {
        var div = document.createElement("div");
        div.innerHTML = "<!--[if lt IE 9]><i></i><![endif]-->";
        var isIeLessThan9 = (div.getElementsByTagName("i").length === 1);
        if (isIeLessThan9) {
            plugin_loaded_error("Internet Explorer версии 8 и ниже не поддерживается");
            return;
        }

        if(isNativeMessageSupported())
        {
            load_extension();
        }else if(!canPromise) {
            window.addEventListener("message", function (event){
                    if (event.data !== "cadesplugin_echo_request")
                        return;
                    load_npapi_plugin();
                    check_npapi_plugin();
                },
                false);
        }else
        {
            if(document.readyState === "complete"){
                load_npapi_plugin();
                check_npapi_plugin();
            } else {
                window.addEventListener("load", function (event) {
                    load_npapi_plugin();
                    check_npapi_plugin();
                }, false);
            }
        }
    }

    function set_pluginObject(obj)
    {
        pluginObject = obj;
    }

    function is_capilite_enabled()
    {
        if ((typeof (cadesplugin.EnableInternalCSP) !== 'undefined') && cadesplugin.EnableInternalCSP)
            return true;
        return false;
    };

    //Export
    cadesplugin.JSModuleVersion = "2.3.2";
    cadesplugin.async_spawn = async_spawn;
    cadesplugin.set = set_pluginObject;
    cadesplugin.set_log_level = set_log_level;
    cadesplugin.getLastError = getLastError;
    cadesplugin.is_capilite_enabled = is_capilite_enabled;

    if(isNativeMessageSupported())
    {
        cadesplugin.CreateObjectAsync = CreateObjectAsync;
        cadesplugin.ReleasePluginObjects = ReleasePluginObjects;
    }

    if(!isNativeMessageSupported())
    {
        cadesplugin.CreateObject = CreateObject;
    }

    if(window.cadesplugin_load_timeout)
    {
        setTimeout(check_load_timeout, window.cadesplugin_load_timeout);
    }
    else
    {
        setTimeout(check_load_timeout, 20000);
    }

    set_constantValues();

    cadesplugin.current_log_level = cadesplugin.LOG_LEVEL_ERROR;
    window.cadesplugin = cadesplugin;
    check_plugin_working();

    // from code.js

    var isPluginEnabled = false;
    var fileContent; // Переменная для хранения информации из файла, значение присваивается в cades_bes_file.html
    var global_selectbox_container = new Array();
    var global_isFromCont = new Array();
    var global_selectbox_counter = 0;
    function getXmlHttp(){
        var xmlhttp;
        try {
            xmlhttp = new ActiveXObject("Msxml2.XMLHTTP");
        } catch (e) {
            try {
                xmlhttp = new ActiveXObject("Microsoft.XMLHTTP");
            } catch (E) {
                xmlhttp = false;
            }
        }
        if (!xmlhttp && typeof XMLHttpRequest!='undefined') {
            xmlhttp = new XMLHttpRequest();
        }
        return xmlhttp;
    }
    function CertStatusEmoji(isValid, hasPrivateKey) {
        if (isValid) {
            _emoji = "\u2705";
        } else {
            _emoji = "\u274C";
        }
        //if (hasPrivateKey) {
        //    _emoji += "\uD83D\uDD11";
        //} else {
        //    _emoji += String.fromCodePoint(0x1F6AB);
        //}
        return _emoji;
    }
    var async_code_included = 0;
    var async_Promise;
    var async_resolve;
    function include_async_code()
    {
        if(async_code_included)
        {
            return async_Promise;
        }
        var fileref = document.createElement('script');
        fileref.setAttribute("type", "text/javascript");
        fileref.setAttribute("src", "async_code.js");
        document.getElementsByTagName("head")[0].appendChild(fileref);
        async_Promise = new Promise(function(resolve, reject){
            async_resolve = resolve;
        });
        async_code_included = 1;
        return async_Promise;
    }

    function Common_RetrieveCertificate()
    {
        var canAsync = !!cadesplugin.CreateObjectAsync;
        if(canAsync)
        {
            include_async_code().then(function(){
                return RetrieveCertificate_Async();
            });
        }else
        {
            return RetrieveCertificate_NPAPI();
        }
    }

    function Common_CreateSimpleSign(id)
    {
        var canAsync = !!cadesplugin.CreateObjectAsync;
        if(canAsync)
        {
            include_async_code().then(function(){
                return CreateSimpleSign_Async(id);
            });
        }else
        {
            return CreateSimpleSign_NPAPI(id);
        }
    }

    function Common_SignCadesBES(id, text, setDisplayData)
    {
        var canAsync = !!cadesplugin.CreateObjectAsync;
        if(canAsync)
        {
            include_async_code().then(function(){
                return SignCadesBES_Async(id, text, setDisplayData);
            });
        }else
        {
            return SignCadesBES_NPAPI(id, text, setDisplayData);
        }
    }

    function Common_SignCadesBES_File(id) {
        var canAsync = !!cadesplugin.CreateObjectAsync;
        if (canAsync) {
            include_async_code().then(function () {
                return SignCadesBES_Async_File(id);
            });
        } else {
            return SignCadesBES_NPAPI_File(id);
        }
    }

    function Common_SignCadesEnhanced(id, sign_type)
    {
        var canAsync = !!cadesplugin.CreateObjectAsync;
        if(canAsync)
        {
            include_async_code().then(function(){
                return SignCadesEnhanced_Async(id, sign_type);
            });
        }else
        {
            return SignCadesEnhanced_NPAPI(id, sign_type);
        }
    }

    function Common_SignCadesXML(id, signatureType)
    {
        var canAsync = !!cadesplugin.CreateObjectAsync;
        if(canAsync)
        {
            include_async_code().then(function(){
                return SignCadesXML_Async(id, signatureType);
            });
        }else
        {
            return SignCadesXML_NPAPI(id, signatureType);
        }
    }

    function Common_CheckForPlugIn() {
        cadesplugin.set_log_level(cadesplugin.LOG_LEVEL_DEBUG);
        var canAsync = !!cadesplugin.CreateObjectAsync;
        if(canAsync)
        {
            console.log("Могу асинхронно");
            include_async_code().then(function(){
                return CheckForPlugIn_Async();
            });
        }else
        {
            return CheckForPlugIn_NPAPI();
        }
    }

    function Common_Encrypt() {
        var canAsync = !!cadesplugin.CreateObjectAsync;
        if(canAsync)
        {
            include_async_code().then(function(){
                return Encrypt_Async();
            });
        }else
        {
            return Encrypt_NPAPI();
        }
    }

    function Common_Decrypt(id) {
        var canAsync = !!cadesplugin.CreateObjectAsync;
        if(canAsync)
        {
            include_async_code().then(function(){
                return Decrypt_Async(id);
            });
        }else
        {
            return Decrypt_NPAPI(id);
        }
    }

    function GetCertificate_NPAPI(certListBoxId) {
        var e = document.getElementById(certListBoxId);
        var selectedCertID = e.selectedIndex;
        if (selectedCertID == -1) {
            alert("Select certificate");
            return;
        }
        return global_selectbox_container[selectedCertID];
    }

    function FillCertInfo_NPAPI(certificate, certBoxId, isFromContainer)
    {
        var BoxId;
        var field_prefix;
        if(typeof(certBoxId) == 'undefined' || certBoxId == "CertListBox")
        {
            BoxId = 'cert_info';
            field_prefix = '';
        }else if (certBoxId == "CertListBox1") {
            BoxId = 'cert_info1';
            field_prefix = 'cert_info1';
        } else if (certBoxId == "CertListBox2") {
            BoxId = 'cert_info2';
            field_prefix = 'cert_info2';
        } else {
            BoxId = certBoxId;
            field_prefix = certBoxId;
        }

        var ValidToDate = new Date(certificate.ValidToDate);
        var ValidFromDate = new Date(certificate.ValidFromDate);
        var IsValid = false;
        //если попадется сертификат с неизвестным алгоритмом
        //тут будет исключение. В таком сертификате просто пропускаем такое поле
        try {
            IsValid = certificate.IsValid().Result;
        } catch (e) {

        }
        var hasPrivateKey = certificate.HasPrivateKey();
        var Now = new Date();

        var certObj = new CertificateObj(certificate);
        document.getElementById(BoxId).style.display = '';
        document.getElementById(field_prefix + "subject").innerHTML = "Владелец: <b>" + certObj.GetCertName() + "<b>";
        document.getElementById(field_prefix + "issuer").innerHTML = "Издатель: <b>" + certObj.GetIssuer() + "<b>";
        document.getElementById(field_prefix + "from").innerHTML = "Выдан: <b>" + certObj.GetCertFromDate() + " UTC<b>";
        document.getElementById(field_prefix + "till").innerHTML = "Действителен до: <b>" + certObj.GetCertTillDate() + " UTC<b>";
        if (hasPrivateKey) {
            document.getElementById(field_prefix + "provname").innerHTML = "Криптопровайдер: <b>" + certObj.GetPrivateKeyProviderName() + "<b>";
            try {
                var privateKeyLink = certObj.GetPrivateKeyLink();
                document.getElementById(field_prefix + "privateKeyLink").innerHTML = "Ссылка на закрытый ключ: <b>" + privateKeyLink + "<b>";
            } catch (e) {
                document.getElementById(field_prefix + "privateKeyLink").innerHTML = "Ссылка на закрытый ключ: <b> Набор ключей не существует<b>";
            }
        } else {
            document.getElementById(field_prefix + "provname").innerHTML = "Криптопровайдер:<b>";
            document.getElementById(field_prefix + "privateKeyLink").innerHTML = "Ссылка на закрытый ключ:<b>";
        }

        document.getElementById(field_prefix + "algorithm").innerHTML = "Алгоритм ключа: <b>" + certObj.GetPubKeyAlgorithm() + "<b>";
        if(Now < ValidFromDate) {
            document.getElementById(field_prefix + "status").innerHTML = "Статус: <span style=\"color:red; font-weight:bold; font-size:16px\"><b>Срок действия не наступил</b></span>";
        } else if( Now > ValidToDate){
            document.getElementById(field_prefix + "status").innerHTML = "Статус: <span style=\"color:red; font-weight:bold; font-size:16px\"><b>Срок действия истек</b></span>";
        } else if( !hasPrivateKey ){
            document.getElementById(field_prefix + "status").innerHTML = "Статус: <span style=\"color:red; font-weight:bold; font-size:16px\"><b>Нет привязки к закрытому ключу</b></span>";
        } else if( !IsValid ){
            document.getElementById(field_prefix + "status").innerHTML = "Статус: <span style=\"color:red; font-weight:bold; font-size:16px\"><b>Ошибка при проверке цепочки сертификатов. Возможно на компьютере не установлены сертификаты УЦ, выдавшего ваш сертификат</b></span>";
        } else {
            document.getElementById(field_prefix + "status").innerHTML = "Статус: <b> Действителен<b>";
        }
        if(isFromContainer)
        {
            document.getElementById(field_prefix + "location").innerHTML = "Установлен в хранилище: <b>Нет</b>";
        } else {
            document.getElementById(field_prefix + "location").innerHTML = "Установлен в хранилище: <b>Да</b>";
        }
    }

    function MakeCadesBesSign_NPAPI(dataToSign, certObject, setDisplayData, isBase64) {
        var errormes = "";

        try {
            var oSigner = cadesplugin.CreateObject("CAdESCOM.CPSigner");
        } catch (err) {
            errormes = "Failed to create CAdESCOM.CPSigner: " + err.number;
            alert(errormes);
            throw errormes;
        }

        if (oSigner) {
            oSigner.Certificate = certObject;
        }
        else {
            errormes = "Failed to create CAdESCOM.CPSigner";
            alert(errormes);
            throw errormes;
        }

        try {
            var oSignedData = cadesplugin.CreateObject("CAdESCOM.CadesSignedData");
        } catch (err) {
            alert('Failed to create CAdESCOM.CadesSignedData: ' + err.number);
            return;
        }

        var CADES_BES = 1;
        var Signature;

        if (dataToSign) {
            oSignedData.ContentEncoding = 1; //CADESCOM_BASE64_TO_BINARY
            // Данные на подпись ввели
            if (typeof (isBase64) == 'undefined') {
                oSignedData.Content = Base64.encode(dataToSign);
            } else {
                oSignedData.Content = dataToSign;
            }
        }

        if (typeof (setDisplayData) != 'undefined') {
            //Set display data flag flag for devices like Rutoken PinPad
            oSignedData.DisplayData = 1;
        }
        oSigner.Options = 1; //CAPICOM_CERTIFICATE_INCLUDE_WHOLE_CHAIN
        try {
            Signature = oSignedData.SignCades(oSigner, CADES_BES);
        }
        catch (err) {
            errormes = "Не удалось создать подпись из-за ошибки: " + cadesplugin.getLastError(err);
            alert(cadesplugin.getLastError(err));
            throw errormes;
        }
        return Signature;
    }

    function MakeCadesEnhanced_NPAPI(dataToSign, tspService, certObject, sign_type) {
        var errormes = "";

        try {
            var oSigner = cadesplugin.CreateObject("CAdESCOM.CPSigner");
        } catch (err) {
            errormes = "Failed to create CAdESCOM.CPSigner: " + err.number;
            alert(errormes);
            throw errormes;
        }

        if (oSigner) {
            oSigner.Certificate = certObject;
        }
        else {
            errormes = "Failed to create CAdESCOM.CPSigner";
            alert(errormes);
            throw errormes;
        }

        try {
            var oSignedData = cadesplugin.CreateObject("CAdESCOM.CadesSignedData");
        } catch (err) {
            alert('Failed to create CAdESCOM.CadesSignedData: ' + cadesplugin.getLastError(err));
            return;
        }

        var Signature;

        if (dataToSign) {
            // Данные на подпись ввели
            oSignedData.Content = dataToSign;
        }
        oSigner.Options = 1; //CAPICOM_CERTIFICATE_INCLUDE_WHOLE_CHAIN
        oSigner.TSAAddress = tspService;
        try {
            Signature = oSignedData.SignCades(oSigner, sign_type);
        }
        catch (err) {
            errormes = "Не удалось создать подпись из-за ошибки: " + cadesplugin.getLastError(err);
            alert(errormes);
            throw errormes;
        }
        return Signature;
    }

    function MakeXMLSign_NPAPI(dataToSign, certObject, signatureType) {
        try {
            var oSigner = cadesplugin.CreateObject("CAdESCOM.CPSigner");
        } catch (err) {
            errormes = "Failed to create CAdESCOM.CPSigner: " + err.number;
            alert(errormes);
            throw errormes;
        }

        if (oSigner) {
            oSigner.Certificate = certObject;
        }
        else {
            errormes = "Failed to create CAdESCOM.CPSigner";
            alert(errormes);
            throw errormes;
        }

        var signMethod = "";
        var digestMethod = "";

        var pubKey = certObject.PublicKey();
        var algo = pubKey.Algorithm;
        var algoOid = algo.Value;
        if (algoOid == "1.2.643.7.1.1.1.1") {   // алгоритм подписи ГОСТ Р 34.10-2012 с ключом 256 бит
            signMethod = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256";
            digestMethod = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256";
        }
        else if (algoOid == "1.2.643.7.1.1.1.2") {   // алгоритм подписи ГОСТ Р 34.10-2012 с ключом 512 бит
            signMethod = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-512";
            digestMethod = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-512";
        }
        else if (algoOid == "1.2.643.2.2.19") {  // алгоритм ГОСТ Р 34.10-2001
            signMethod = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102001-gostr3411";
            digestMethod = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr3411";
        }
        else {
            errormes = "Данная демо страница поддерживает XML подпись сертификатами с алгоритмом ГОСТ Р 34.10-2012, ГОСТ Р 34.10-2001";
            throw errormes;
        }

        var CADESCOM_XML_SIGNATURE_TYPE_ENVELOPED = 0|signatureType;
        if (signatureType > cadesplugin.CADESCOM_XADES_BES) {
            var tspService = document.getElementById("TSPServiceTxtBox").value;
            oSigner.TSAAddress = tspService;
        }

        try {
            var oSignedXML = cadesplugin.CreateObject("CAdESCOM.SignedXML");
        } catch (err) {
            alert('Failed to create CAdESCOM.SignedXML: ' + cadesplugin.getLastError(err));
            return;
        }

        oSignedXML.Content = dataToSign;
        oSignedXML.SignatureType = CADESCOM_XML_SIGNATURE_TYPE_ENVELOPED;
        oSignedXML.SignatureMethod = signMethod;
        oSignedXML.DigestMethod = digestMethod;


        var sSignedMessage = "";
        try {
            sSignedMessage = oSignedXML.Sign(oSigner);
        }
        catch (err) {
            errormes = "Не удалось создать подпись из-за ошибки: " + cadesplugin.getLastError(err);
            alert(errormes);
            throw errormes;
        }

        return sSignedMessage;
    }

    function GetSignatureTitleElement()
    {
        var elementSignatureTitle = null;
        var x = document.getElementsByName("SignatureTitle");

        if(x.length == 0)
        {
            elementSignatureTitle = document.getElementById("SignatureTxtBox").parentNode.previousSibling;

            if(elementSignatureTitle.nodeName == "P")
            {
                return elementSignatureTitle;
            }
        }
        else
        {
            elementSignatureTitle = x[0];
        }

        return elementSignatureTitle;
    }

    function SignCadesBES_NPAPI(certListBoxId, data, setDisplayData) {
        var certificate = GetCertificate_NPAPI(certListBoxId);
        var dataToSign = document.getElementById("DataToSignTxtBox").value;
        if(typeof(data) != 'undefined')
        {
            dataToSign = data;
        }
        var x = GetSignatureTitleElement();
        try
        {
            var signature = MakeCadesBesSign_NPAPI(dataToSign, certificate, setDisplayData);
            document.getElementById("SignatureTxtBox").innerHTML = signature;
            if(x!=null)
            {
                x.innerHTML = "Подпись сформирована успешно:";
            }
        }
        catch(err)
        {
            if(x!=null)
            {
                x.innerHTML = "Возникла ошибка:";
            }
            document.getElementById("SignatureTxtBox").innerHTML = err;
        }
    }

    function SignCadesBES_NPAPI_File(certListBoxId) {
        var certificate = GetCertificate_NPAPI(certListBoxId);
        var dataToSign = fileContent;
        var x = GetSignatureTitleElement();
        try {
            var StartTime = Date.now();
            var setDisplayData;
            var signature = MakeCadesBesSign_NPAPI(dataToSign, certificate, setDisplayData, 1);
            var EndTime = Date.now();
            document.getElementsByName('TimeTitle')[0].innerHTML = "Время выполнения: " + (EndTime - StartTime) + " мс";
            document.getElementById("SignatureTxtBox").innerHTML = signature;
            if (x != null) {
                x.innerHTML = "Подпись сформирована успешно:";
            }
        }
        catch (err) {
            if (x != null) {
                x.innerHTML = "Возникла ошибка:";
            }
            document.getElementById("SignatureTxtBox").innerHTML = err;
        }
    }

    function SignCadesEnhanced_NPAPI(certListBoxId, sign_type) {
        var certificate = GetCertificate_NPAPI(certListBoxId);
        var dataToSign = document.getElementById("DataToSignTxtBox").value;
        var tspService = document.getElementById("TSPServiceTxtBox").value ;
        var x = GetSignatureTitleElement();
        try
        {
            var signature = MakeCadesEnhanced_NPAPI(dataToSign, tspService, certificate, sign_type);
            document.getElementById("SignatureTxtBox").innerHTML = signature;
            if(x!=null)
            {
                x.innerHTML = "Подпись сформирована успешно:";
            }
        }
        catch(err)
        {
            if(x!=null)
            {
                x.innerHTML = "Возникла ошибка:";
            }
            document.getElementById("SignatureTxtBox").innerHTML = err;
        }
    }

    function SignCadesXML_NPAPI(certListBoxId, signatureType) {
        var certificate = GetCertificate_NPAPI(certListBoxId);
        var dataToSign = document.getElementById("DataToSignTxtBox").value;
        var x = GetSignatureTitleElement();
        try
        {
            var signature = MakeXMLSign_NPAPI(dataToSign, certificate, signatureType);
            document.getElementById("SignatureTxtBox").innerHTML = signature;

            if(x!=null)
            {
                x.innerHTML = "Подпись сформирована успешно:";
            }
        }
        catch(err)
        {
            if(x!=null)
            {
                x.innerHTML = "Возникла ошибка:";
            }
            document.getElementById("SignatureTxtBox").innerHTML = err;
        }
    }

    function MakeVersionString(oVer)
    {
        var strVer;
        if(typeof(oVer)=="string")
            return oVer;
        else
            return oVer.MajorVersion + "." + oVer.MinorVersion + "." + oVer.BuildVersion;
    }

    function CheckForPlugIn_NPAPI() {
        function VersionCompare_NPAPI(StringVersion, ObjectVersion)
        {
            if(typeof(ObjectVersion) == "string")
                return -1;
            var arr = StringVersion.split('.');

            if(ObjectVersion.MajorVersion == parseInt(arr[0]))
            {
                if(ObjectVersion.MinorVersion == parseInt(arr[1]))
                {
                    if(ObjectVersion.BuildVersion == parseInt(arr[2]))
                    {
                        return 0;
                    }
                    else if(ObjectVersion.BuildVersion < parseInt(arr[2]))
                    {
                        return -1;
                    }
                }else if(ObjectVersion.MinorVersion < parseInt(arr[1]))
                {
                    return -1;
                }
            }else if(ObjectVersion.MajorVersion < parseInt(arr[0]))
            {
                return -1;
            }

            return 1;
        }

        function GetCSPVersion_NPAPI() {
            try {
                var oAbout = cadesplugin.CreateObject("CAdESCOM.About");
            } catch (err) {
                alert('Failed to create CAdESCOM.About: ' + cadesplugin.getLastError(err));
                return;
            }
            var ver = oAbout.CSPVersion("", 80);
            window.onload = function (e) {
                document.getElementById('CspEnabledImg').setAttribute("src", "Img/green_dot.png");
                document.getElementById('CspEnabledTxt').innerHTML = "Криптопровайдер загружен";
            }
            document.getElementById('CspEnabledImg').setAttribute("src", "Img/green_dot.png");
            document.getElementById('CspEnabledTxt').innerHTML = "Криптопровайдер загружен";
            return ver.MajorVersion + "." + ver.MinorVersion + "." + ver.BuildVersion;
        }

        function GetCSPName_NPAPI() {
            var sCSPName = "";
            try {
                var oAbout = cadesplugin.CreateObject("CAdESCOM.About");
                sCSPName = oAbout.CSPName(80);

            } catch (err) {
            }
            return sCSPName;
        }

        function ShowCSPVersion_NPAPI(CurrentPluginVersion)
        {
            if(typeof(CurrentPluginVersion) != "string")
            {
                document.getElementById('CSPVersionTxt').innerHTML = "Версия криптопровайдера: " + GetCSPVersion_NPAPI();
            }
            var sCSPName = GetCSPName_NPAPI();
            if(sCSPName!="")
            {
                document.getElementById('CSPNameTxt').innerHTML = "Криптопровайдер: " + sCSPName;
            }
        }
        function GetLatestVersion_NPAPI(CurrentPluginVersion) {
            var xmlhttp = getXmlHttp();
            xmlhttp.open("GET", "/sites/default/files/products/cades/latest_2_0.txt", true);
            xmlhttp.onreadystatechange = function() {
                var PluginBaseVersion;
                if (xmlhttp.readyState == 4) {
                    if(xmlhttp.status == 200) {
                        PluginBaseVersion = xmlhttp.responseText;
                        if (isPluginWorked) { // плагин работает, объекты создаются
                            if (VersionCompare_NPAPI(PluginBaseVersion, CurrentPluginVersion)<0) {
                                document.getElementById('PluginEnabledImg').setAttribute("src", "Img/yellow_dot.png");
                                document.getElementById('PlugInEnabledTxt').innerHTML = "Плагин загружен, но есть более свежая версия";
                            }
                        }
                        else { // плагин не работает, объекты не создаются
                            if (isPluginLoaded) { // плагин загружен
                                if (!isPluginEnabled) { // плагин загружен, но отключен
                                    document.getElementById('PluginEnabledImg').setAttribute("src", "Img/red_dot.png");
                                    document.getElementById('PlugInEnabledTxt').innerHTML = "Плагин загружен, но отключен в настройках браузера";
                                }
                                else { // плагин загружен и включен, но объекты не создаются
                                    document.getElementById('PluginEnabledImg').setAttribute("src", "Img/red_dot.png");
                                    document.getElementById('PlugInEnabledTxt').innerHTML = "Плагин загружен, но не удается создать объекты. Проверьте настройки браузера";
                                }
                            }
                            else { // плагин не загружен
                                document.getElementById('PluginEnabledImg').setAttribute("src", "Img/red_dot.png");
                                document.getElementById('PlugInEnabledTxt').innerHTML = "Плагин не загружен";
                            }
                        }
                    }
                }
            }
            xmlhttp.send(null);
        }

        var isPluginLoaded = false;
        var isPluginWorked = false;
        var isActualVersion = false;
        try {
            var oAbout = cadesplugin.CreateObject("CAdESCOM.About");
            isPluginLoaded = true;
            isPluginEnabled = true;
            isPluginWorked = true;

            // Это значение будет проверяться сервером при загрузке демо-страницы
            var CurrentPluginVersion = oAbout.PluginVersion;
            if( typeof(CurrentPluginVersion) == "undefined")
                CurrentPluginVersion = oAbout.Version;

            window.onload = function (e) {
                document.getElementById('PluginEnabledImg').setAttribute("src", "Img/green_dot.png");
                document.getElementById('PlugInEnabledTxt').innerHTML = "Плагин загружен";
                document.getElementById('CspEnabledImg').setAttribute("src", "Img/yellow_dot.png");
                document.getElementById('CspEnabledTxt').innerHTML = "КриптоПро CSP не загружен";
            }
            document.getElementById('PluginEnabledImg').setAttribute("src", "Img/green_dot.png");
            document.getElementById('PlugInEnabledTxt').innerHTML = "Плагин загружен";
            document.getElementById('CspEnabledImg').setAttribute("src", "Img/yellow_dot.png");
            document.getElementById('CspEnabledTxt').innerHTML = "КриптоПро CSP не загружен";
            document.getElementById('PlugInVersionTxt').innerHTML = "Версия плагина: " + MakeVersionString(CurrentPluginVersion);
            ShowCSPVersion_NPAPI(CurrentPluginVersion);
        }
        catch (err) {
            // Объект создать не удалось, проверим, установлен ли
            // вообще плагин. Такая возможность есть не во всех браузерах
            var mimetype = navigator.mimeTypes["application/x-cades"];
            if (mimetype) {
                isPluginLoaded = true;
                var plugin = mimetype.enabledPlugin;
                if (plugin) {
                    isPluginEnabled = true;
                }
            }
        }
        GetLatestVersion_NPAPI(CurrentPluginVersion);
        if(location.pathname.indexOf("symalgo_sample.html")>=0){
            FillCertList_NPAPI('CertListBox1');
            FillCertList_NPAPI('CertListBox2');
        } else{
            FillCertList_NPAPI('CertListBox');
        }
    }

    function CertificateObj(certObj)
    {
        this.cert = certObj;
        this.certFromDate = new Date(this.cert.ValidFromDate);
        this.certTillDate = new Date(this.cert.ValidToDate);
    }

    CertificateObj.prototype.check = function(digit)
    {
        return (digit<10) ? "0"+digit : digit;
    }

    CertificateObj.prototype.checkQuotes = function(str)
    {
        var result = 0, i = 0;
        for(i;i<str.length;i++)if(str[i]==='"')
            result++;
        return !(result%2);
    }

    CertificateObj.prototype.extract = function(from, what)
    {
        certName = "";

        var begin = from.indexOf(what);

        if(begin>=0)
        {
            var end = from.indexOf(', ', begin);
            while(end > 0) {
                if (this.checkQuotes(from.substr(begin, end-begin)))
                    break;
                end = from.indexOf(', ', end + 1);
            }
            certName = (end < 0) ? from.substr(begin) : from.substr(begin, end - begin);
        }

        return certName;
    }

    CertificateObj.prototype.DateTimePutTogether = function(certDate)
    {
        return this.check(certDate.getUTCDate())+"."+this.check(certDate.getUTCMonth()+1)+"."+certDate.getFullYear() + " " +
            this.check(certDate.getUTCHours()) + ":" + this.check(certDate.getUTCMinutes()) + ":" + this.check(certDate.getUTCSeconds());
    }

    CertificateObj.prototype.GetCertString = function()
    {
        return this.extract(this.cert.SubjectName,'CN=') + "; Выдан: " + this.GetCertFromDate();
    }

    CertificateObj.prototype.GetCertFromDate = function()
    {
        return this.DateTimePutTogether(this.certFromDate);
    }

    CertificateObj.prototype.GetCertTillDate = function()
    {
        return this.DateTimePutTogether(this.certTillDate);
    }

    CertificateObj.prototype.GetPubKeyAlgorithm = function()
    {
        return this.cert.PublicKey().Algorithm.FriendlyName;
    }

    CertificateObj.prototype.GetCertName = function()
    {
        return this.extract(this.cert.SubjectName, 'CN=');
    }

    CertificateObj.prototype.GetIssuer = function()
    {
        return this.extract(this.cert.IssuerName, 'CN=');
    }

    CertificateObj.prototype.GetPrivateKeyProviderName = function()
    {
        return this.cert.PrivateKey.ProviderName;
    }

    CertificateObj.prototype.GetPrivateKeyLink = function () {
        return this.cert.PrivateKey.UniqueContainerName;
    }

    function GetFirstCert_NPAPI() {
        try {
            var oStore = cadesplugin.CreateObject("CAdESCOM.Store");
            oStore.Open();
        }
        catch (e) {
            alert("Certificate not found");
            return;
        }

        var dateObj = new Date();
        var certCnt;

        try {
            certCnt = oStore.Certificates.Count;
            if(certCnt==0)
                throw "Certificate not found";
        }
        catch (ex) {
            oStore.Close();
            document.getElementById("boxdiv").style.display = '';
            return;
        }

        if(certCnt) {
            try {
                for (var i = 1; i <= certCnt; i++) {
                    var cert = oStore.Certificates.Item(i);
                    if(dateObj<cert.ValidToDate && cert.HasPrivateKey() && cert.IsValid().Result){
                        return cert;
                    }
                }
            }
            catch (ex) {
                alert("Ошибка при перечислении сертификатов: " + cadesplugin.getLastError(ex));
                return;
            }
        }
    }

    function CreateSimpleSign_NPAPI()
    {
        oCert = GetFirstCert_NPAPI();
        var x = GetSignatureTitleElement();
        try
        {
            if (typeof oCert != "undefined") {
                FillCertInfo_NPAPI(oCert);
                var sSignedData = MakeCadesBesSign_NPAPI(txtDataToSign, oCert);
                document.getElementById("SignatureTxtBox").innerHTML = sSignedData;
                if(x!=null)
                {
                    x.innerHTML = "Подпись сформирована успешно:";
                }
            }
        }
        catch(err)
        {
            if(x!=null)
            {
                x.innerHTML = "Возникла ошибка:";
            }
            document.getElementById("SignatureTxtBox").innerHTML = err;
        }
    }

    function onCertificateSelected(event) {
        var selectedCertID = event.target.selectedIndex;
        var certificate = global_selectbox_container[selectedCertID];
        FillCertInfo_NPAPI(certificate, event.target.boxId, global_isFromCont[selectedCertID]);
    }


    function FillCertList_NPAPI(lstId) {
        try {
            var lst = document.getElementById(lstId);
            if(!lst)
                return;
        }
        catch (ex) {
            return;
        }

        lst.onchange = onCertificateSelected;
        lst.boxId = lstId;
        var MyStoreExists = true;

        try {
            var oStore = cadesplugin.CreateObject("CAdESCOM.Store");
            oStore.Open();
        }
        catch (ex) {
            MyStoreExists = false;
        }


        var certCnt;
        if(MyStoreExists) {
            certCnt = oStore.Certificates.Count;
            for (var i = 1; i <= certCnt; i++) {
                var cert;
                try {
                    cert = oStore.Certificates.Item(i);
                }
                catch (ex) {
                    alert("Ошибка при перечислении сертификатов: " + cadesplugin.getLastError(ex));
                    return;
                }

                var oOpt = document.createElement("OPTION");
                try {
                    var certObj = new CertificateObj(cert, true);
                    oOpt.text = CertStatusEmoji(cert.ValidToDate > Date.now()) + certObj.GetCertString();
                }
                catch (ex) {
                    alert("Ошибка при получении свойства SubjectName: " + cadesplugin.getLastError(ex));
                }
                try {
                    oOpt.value = global_selectbox_counter
                    global_selectbox_container.push(cert);
                    global_isFromCont.push(false);
                    global_selectbox_counter++;
                }
                catch (ex) {
                    alert("Ошибка при получении свойства Thumbprint: " + cadesplugin.getLastError(ex));
                }

                lst.options.add(oOpt);
            }

            oStore.Close();
        }

        //В версии плагина 2.0.13292+ есть возможность получить сертификаты из
        //закрытых ключей и не установленных в хранилище
        try {
            oStore.Open(cadesplugin.CADESCOM_CONTAINER_STORE);
            certCnt = oStore.Certificates.Count;
            for (var i = 1; i <= certCnt; i++) {
                var cert = oStore.Certificates.Item(i);
                //Проверяем не добавляли ли мы такой сертификат уже?
                var found = false;
                for (var j = 0; j < global_selectbox_container.length; j++)
                {
                    if (global_selectbox_container[j].Thumbprint === cert.Thumbprint)
                    {
                        found = true;
                        break;
                    }
                }
                if(found)
                    continue;
                var certObj = new CertificateObj(cert);
                var oOpt = document.createElement("OPTION");
                oOpt.text = CertStatusEmoji(cert.ValidToDate > Date.now()) + certObj.GetCertString();
                oOpt.value = global_selectbox_counter
                global_selectbox_container.push(cert);
                global_isFromCont.push(true);
                global_selectbox_counter++;
                lst.options.add(oOpt);
            }
            oStore.Close();
        }
        catch (ex) {
        }
        if(global_selectbox_container.length == 0) {
            document.getElementById("boxdiv").style.display = '';
        }
    }

    function CreateCertRequest_NPAPI()
    {
        try {
            var PrivateKey = cadesplugin.CreateObject("X509Enrollment.CX509PrivateKey");
        }
        catch (e) {
            alert('Failed to create X509Enrollment.CX509PrivateKey: ' + cadesplugin.getLastError(e));
            return;
        }

        PrivateKey.ProviderName = "Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider";
        PrivateKey.ProviderType = 80;
        PrivateKey.KeySpec = 1; //XCN_AT_KEYEXCHANGE

        try {
            var CertificateRequestPkcs10 = cadesplugin.CreateObject("X509Enrollment.CX509CertificateRequestPkcs10");
        }
        catch (e) {
            alert('Failed to create X509Enrollment.CX509CertificateRequestPkcs10: ' + cadesplugin.getLastError(e));
            return;
        }

        CertificateRequestPkcs10.InitializeFromPrivateKey(0x1, PrivateKey, "");

        try {
            var DistinguishedName = cadesplugin.CreateObject("X509Enrollment.CX500DistinguishedName");
        }
        catch (e) {
            alert('Failed to create X509Enrollment.CX500DistinguishedName: ' + cadesplugin.getLastError(e));
            return;
        }

        var CommonName = "Test Certificate";
        DistinguishedName.Encode("CN=\""+CommonName.replace(/"/g, "\"\"")+"\"");

        CertificateRequestPkcs10.Subject = DistinguishedName;

        var KeyUsageExtension = cadesplugin.CreateObject("X509Enrollment.CX509ExtensionKeyUsage");
        var CERT_DATA_ENCIPHERMENT_KEY_USAGE = 0x10;
        var CERT_KEY_ENCIPHERMENT_KEY_USAGE = 0x20;
        var CERT_DIGITAL_SIGNATURE_KEY_USAGE = 0x80;
        var CERT_NON_REPUDIATION_KEY_USAGE = 0x40;

        KeyUsageExtension.InitializeEncode(
            CERT_KEY_ENCIPHERMENT_KEY_USAGE |
            CERT_DATA_ENCIPHERMENT_KEY_USAGE |
            CERT_DIGITAL_SIGNATURE_KEY_USAGE |
            CERT_NON_REPUDIATION_KEY_USAGE);

        CertificateRequestPkcs10.X509Extensions.Add(KeyUsageExtension);

        try {
            var Enroll = cadesplugin.CreateObject("X509Enrollment.CX509Enrollment");
        }
        catch (e) {
            alert('Failed to create X509Enrollment.CX509Enrollment: ' + cadesplugin.getLastError(e));
            return;
        }
        var cert_req;
        try {
            Enroll.InitializeFromRequest(CertificateRequestPkcs10);
            cert_req = Enroll.CreateRequest(0x1);
        } catch (e) {
            alert('Failed to generate KeyPair or reguest: ' + cadesplugin.getLastError(e));
            return;
        }

        return cert_req;
    }

    function RetrieveCertificate_NPAPI()
    {
        var cert_req = CreateCertRequest_NPAPI();
        var params = 'CertRequest=' + encodeURIComponent(cert_req) +
            '&Mode=' + encodeURIComponent('newreq') +
            '&TargetStoreFlags=' + encodeURIComponent('0') +
            '&SaveCert=' + encodeURIComponent('no');

        var xmlhttp = getXmlHttp();
        xmlhttp.open("POST", "https://testca.cryptopro.ru/certsrv/certfnsh.asp", true);
        xmlhttp.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
        var response;
        xmlhttp.onreadystatechange = function() {
            if (xmlhttp.readyState == 4) {
                if(xmlhttp.status == 200) {
                    response = xmlhttp.responseText;
                    var cert_data = "";

                    if(!isIE())
                    {
                        var start = response.indexOf("var sPKCS7");
                        var end = response.indexOf("sPKCS7 += \"\"") + 13;
                        cert_data = response.substring(start, end);
                    }
                    else
                    {
                        var start = response.indexOf("sPKCS7 & \"") + 9;
                        var end = response.indexOf("& vbNewLine\r\n\r\n</Script>");
                        cert_data = response.substring(start, end);
                        cert_data = cert_data.replace(new RegExp(" & vbNewLine",'g'),";");
                        cert_data = cert_data.replace(new RegExp("&",'g'),"+");
                        cert_data = "var sPKCS7=" + cert_data + ";";
                    }

                    eval(cert_data);

                    try {
                        var Enroll = cadesplugin.CreateObject("X509Enrollment.CX509Enrollment");
                    }
                    catch (e) {
                        alert('Failed to create X509Enrollment.CX509Enrollment: ' + cadesplugin.getLastError(e));
                        return;
                    }

                    Enroll.Initialize(0x1);
                    Enroll.InstallResponse(0, sPKCS7, 0x7, "");
                    document.getElementById("boxdiv").style.display = 'none';
                    if(location.pathname.indexOf("simple")>=0) {
                        location.reload();
                    }
                    else if(location.pathname.indexOf("symalgo_sample.html")>=0){
                        FillCertList_NPAPI('CertListBox1');
                        FillCertList_NPAPI('CertListBox2');
                    }
                    else{
                        FillCertList_NPAPI('CertListBox');
                    }
                }
            }
        }
        xmlhttp.send(params);
    }

    function Encrypt_NPAPI() {

        document.getElementById("DataEncryptedIV1").innerHTML = "";
        document.getElementById("DataEncryptedIV2").innerHTML = "";
        document.getElementById("DataEncryptedDiversData1").innerHTML = "";
        document.getElementById("DataEncryptedDiversData2").innerHTML = "";
        document.getElementById("DataEncryptedBox1").innerHTML = "";
        document.getElementById("DataEncryptedBox2").innerHTML = "";
        document.getElementById("DataEncryptedKey1").innerHTML = "";
        document.getElementById("DataEncryptedKey2").innerHTML = "";
        document.getElementById("DataDecryptedBox1").innerHTML = "";
        document.getElementById("DataDecryptedBox2").innerHTML = "";

        var certificate1 = GetCertificate_NPAPI('CertListBox1');
        if(typeof(certificate1) == 'undefined')
        {
            return;
        }
        var certificate2 = GetCertificate_NPAPI('CertListBox2');
        if(typeof(certificate2) == 'undefined')
        {
            return;
        }

        var dataToEncr1 = Base64.encode(document.getElementById("DataToEncrTxtBox1").value);
        var dataToEncr2 = Base64.encode(document.getElementById("DataToEncrTxtBox2").value);

        if(dataToEncr1 === "" || dataToEncr2 === "") {
            errormes = "Empty data to encrypt";
            alert(errormes);
            throw errormes;
        }

        try
        {
            //FillCertInfo_NPAPI(certificate1, 'cert_info1');
            //FillCertInfo_NPAPI(certificate2, 'cert_info2');
            var errormes = "";

            try {
                var oSymAlgo = cadesplugin.CreateObject("cadescom.symmetricalgorithm");
            } catch (err) {
                errormes = "Failed to create cadescom.symmetricalgorithm: " + err;
                alert(errormes);
                throw errormes;
            }

            oSymAlgo.GenerateKey();

            var oSesKey1 = oSymAlgo.DiversifyKey();
            var oSesKey1DiversData = oSesKey1.DiversData;
            document.getElementById("DataEncryptedDiversData1").value = oSesKey1DiversData;
            var oSesKey1IV = oSesKey1.IV;
            document.getElementById("DataEncryptedIV1").value = oSesKey1IV;
            var EncryptedData1 = oSesKey1.Encrypt(dataToEncr1, 1);
            document.getElementById("DataEncryptedBox1").value = EncryptedData1;

            var oSesKey2 = oSymAlgo.DiversifyKey();
            var oSesKey2DiversData = oSesKey2.DiversData;
            document.getElementById("DataEncryptedDiversData2").value = oSesKey2DiversData;
            var oSesKey2IV = oSesKey2.IV;
            document.getElementById("DataEncryptedIV2").value = oSesKey2IV;
            var EncryptedData2 = oSesKey2.Encrypt(dataToEncr2, 1);
            document.getElementById("DataEncryptedBox2").value = EncryptedData2;

            var ExportedKey1 = oSymAlgo.ExportKey(certificate1);
            document.getElementById("DataEncryptedKey1").value = ExportedKey1;

            var ExportedKey2 = oSymAlgo.ExportKey(certificate2);
            document.getElementById("DataEncryptedKey2").value = ExportedKey2;

            alert("Данные зашифрованы успешно:");
        }
        catch(err)
        {
            alert("Ошибка при шифровании данных:" + err);
        }
    }

    function Decrypt_NPAPI(certListBoxId) {

        document.getElementById("DataDecryptedBox1").value = "";
        document.getElementById("DataDecryptedBox2").value = "";

        var certificate = GetCertificate_NPAPI(certListBoxId);
        if(typeof(certificate) == 'undefined')
        {
            return;
        }
        var dataToDecr1 = document.getElementById("DataEncryptedBox1").value;
        var dataToDecr2 = document.getElementById("DataEncryptedBox2").value;
        var field;
        if(certListBoxId == 'CertListBox1')
            field ="DataEncryptedKey1";
        else
            field ="DataEncryptedKey2";

        var EncryptedKey = document.getElementById(field).value;
        try
        {
            FillCertInfo_NPAPI(certificate, 'cert_info_decr');
            var errormes = "";

            try {
                var oSymAlgo = cadesplugin.CreateObject("cadescom.symmetricalgorithm");
            } catch (err) {
                errormes = "Failed to create cadescom.symmetricalgorithm: " + err;
                alert(errormes);
                throw errormes;
            }
            oSymAlgo.ImportKey(EncryptedKey, certificate);
            var oSesKey1DiversData = document.getElementById("DataEncryptedDiversData1").value;
            var oSesKey1IV = document.getElementById("DataEncryptedIV1").value;
            oSymAlgo.DiversData = oSesKey1DiversData;
            var oSesKey1 = oSymAlgo.DiversifyKey();
            oSesKey1.IV = oSesKey1IV;
            var EncryptedData1 = oSesKey1.Decrypt(dataToDecr1, 1);
            document.getElementById("DataDecryptedBox1").value = Base64.decode(EncryptedData1);
            var oSesKey2DiversData = document.getElementById("DataEncryptedDiversData2").value;
            var oSesKey2IV = document.getElementById("DataEncryptedIV2").value;
            oSymAlgo.DiversData = oSesKey2DiversData;
            var oSesKey2 = oSymAlgo.DiversifyKey();
            oSesKey2.IV = oSesKey2IV;
            var EncryptedData2 = oSesKey2.Decrypt(dataToDecr2, 1);
            document.getElementById("DataDecryptedBox2").value = Base64.decode(EncryptedData2);

            alert("Данные расшифрованы успешно:");
        }
        catch(err)
        {
            alert("Ошибка при шифровании данных:" + err);
        }
    }

    function isIE() {
        var retVal = (("Microsoft Internet Explorer" == navigator.appName) || // IE < 11
            navigator.userAgent.match(/Trident\/./i)); // IE 11
        return retVal;
    }

    function isEdge() {
        var retVal = navigator.userAgent.match(/Edge\/./i);
        return retVal;
    }

    function ShowEdgeNotSupported() {
        document.getElementById('PluginEnabledImg').setAttribute("src", "Img/red_dot.png");
        document.getElementById('PlugInEnabledTxt').innerHTML = "К сожалению, браузер Edge не поддерживается!";
    }

//-----------------------------------
    var Base64 = {


        _keyStr: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",


        encode: function(input) {
            var output = "";
            var chr1, chr2, chr3, enc1, enc2, enc3, enc4;
            var i = 0;

            input = Base64._utf8_encode(input);

            while (i < input.length) {

                chr1 = input.charCodeAt(i++);
                chr2 = input.charCodeAt(i++);
                chr3 = input.charCodeAt(i++);

                enc1 = chr1 >> 2;
                enc2 = ((chr1 & 3) << 4) | (chr2 >> 4);
                enc3 = ((chr2 & 15) << 2) | (chr3 >> 6);
                enc4 = chr3 & 63;

                if (isNaN(chr2)) {
                    enc3 = enc4 = 64;
                } else if (isNaN(chr3)) {
                    enc4 = 64;
                }

                output = output + this._keyStr.charAt(enc1) + this._keyStr.charAt(enc2) + this._keyStr.charAt(enc3) + this._keyStr.charAt(enc4);

            }

            return output;
        },


        decode: function(input) {
            var output = "";
            var chr1, chr2, chr3;
            var enc1, enc2, enc3, enc4;
            var i = 0;

            input = input.replace(/[^A-Za-z0-9\+\/\=]/g, "");

            while (i < input.length) {

                enc1 = this._keyStr.indexOf(input.charAt(i++));
                enc2 = this._keyStr.indexOf(input.charAt(i++));
                enc3 = this._keyStr.indexOf(input.charAt(i++));
                enc4 = this._keyStr.indexOf(input.charAt(i++));

                chr1 = (enc1 << 2) | (enc2 >> 4);
                chr2 = ((enc2 & 15) << 4) | (enc3 >> 2);
                chr3 = ((enc3 & 3) << 6) | enc4;

                output = output + String.fromCharCode(chr1);

                if (enc3 != 64) {
                    output = output + String.fromCharCode(chr2);
                }
                if (enc4 != 64) {
                    output = output + String.fromCharCode(chr3);
                }

            }

            output = Base64._utf8_decode(output);

            return output;

        },

        _utf8_encode: function(string) {
            string = string.replace(/\r\n/g, "\n");
            var utftext = "";

            for (var n = 0; n < string.length; n++) {

                var c = string.charCodeAt(n);

                if (c < 128) {
                    utftext += String.fromCharCode(c);
                }
                else if ((c > 127) && (c < 2048)) {
                    utftext += String.fromCharCode((c >> 6) | 192);
                    utftext += String.fromCharCode((c & 63) | 128);
                }
                else {
                    utftext += String.fromCharCode((c >> 12) | 224);
                    utftext += String.fromCharCode(((c >> 6) & 63) | 128);
                    utftext += String.fromCharCode((c & 63) | 128);
                }

            }

            return utftext;
        },

        _utf8_decode: function(utftext) {
            var string = "";
            var i = 0;
            var c = c1 = c2 = 0;

            while (i < utftext.length) {

                c = utftext.charCodeAt(i);

                if (c < 128) {
                    string += String.fromCharCode(c);
                    i++;
                }
                else if ((c > 191) && (c < 224)) {
                    c2 = utftext.charCodeAt(i + 1);
                    string += String.fromCharCode(((c & 31) << 6) | (c2 & 63));
                    i += 2;
                }
                else {
                    c2 = utftext.charCodeAt(i + 1);
                    c3 = utftext.charCodeAt(i + 2);
                    string += String.fromCharCode(((c & 15) << 12) | ((c2 & 63) << 6) | (c3 & 63));
                    i += 3;
                }

            }

            return string;
        }

    }
    var MakePayment = function(sum,date,to){
        return '<!PINPADFILE UTF8><N>Платежное поручение<V>500'
            + '<N>Сумма<V>' + sum
            + '<N>Дата<V>' + date
            + '<N>Получатель<V>' + to
            + '<N>Инн<V>102125125212'
            + '<N>КПП<V>1254521521'
            + '<N>Назначение платежа<V>За телематические услуги'
            + '<N>Банк получателя<V>Сбербанк'
            + '<N>БИК<V>5005825'
            + '<N>Номер счета получателя<V>1032221122214422'
            + '<N>Плательщик<V>ЗАО "Актив-софт"'
            + '<N>Банк плательщика<V>Банк ВТБ (открытое акционерное общество)'
            + '<N>БИК<V>044525187'
            + '<N>Номер счета плательщика<V>30101810700000000187';
    };



    function ShowPinPadelogin(){
        var loginvalue = document.getElementById('Login').value;
        var text = '<!PINPADFILE UTF8><N>Авторизация<V><N>Подтвердите авторизацию на сайте<V>'
            + 'cryptopro.ru'
            + '<N>Вход будет произведен с логином<V>' + loginvalue;
        Common_SignCadesBES('CertListBox',text, 1);
    }

    // End of code.js
}());
