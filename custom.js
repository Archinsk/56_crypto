function getJasperSignatureCertificatesList() {

    let oStore;

    if (cadesplugin.CreateObjectAsync) {
        cadesplugin.async_spawn(function* () {
            try {
                oStore = yield cadesplugin.CreateObjectAsync("CAPICOM.Store");
            } catch (e) {
                err = cadesplugin.getLastError(e);
                if (err.indexOf("0x80090019") + 1) {
                    showError("Указанный CSP не установлен");
                    return;
                } else {
                    showError("Невозможно загрузить хранилище сертификатов!");
                    return;
                }
            }

            try {
                yield oStore.Open(cadesplugin.CAPICOM_CURRENT_USER_STORE, cadesplugin.CAPICOM_MY_STORE,
                    cadesplugin.CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED);
            } catch (e) {
                showError("Ошибка при открытии хранилища: " + GetErrorMessage(e));
                return;
            }

            const oCerts = yield oStore.Certificates;
            const certCnt = yield oCerts.Count;
            var Adjust = new CertificateAdjuster();

            if (certificatesList.length > 0) certificatesList = [];

            for (let i = 1; i <= certCnt; i++) {
                try {
                    certx = yield oCerts.Item(i);
                } catch (e) {
                    showError("Ошибка при перечислении сертификатов: " + GetErrorMessage(e));
                    return;
                }
                let temp = {};
                try {
                    var ValidToDate = new Date((yield certx.ValidToDate));
                    var ValidFromDate = new Date((yield certx.ValidFromDate));
                    var Validator;
                    var IsValid = false;
                    //если попадется сертификат с неизвестным алгоритмом
                    //тут будет исключение. В таком сертификате просто пропускаем такое поле
                    try {
                        Validator = yield certx.IsValid();
                        IsValid = yield Validator.Result;
                    } catch (e) {

                    }
                    temp.signatureData = {};
                    temp.subject = "Владелец: <b>" + Adjust.GetCertName(yield certx.SubjectName) + "<b>";
                    temp.signatureData.subject = Adjust.GetCertName(yield certx.SubjectName);

                    temp.issuer = "Издатель: <b>" + Adjust.GetIssuer(yield certx.IssuerName) + "<b>";
                    temp.from = "Выдан: <b>" + Adjust.GetCertDate(ValidFromDate) + "<b>";
                    temp.signatureData.from = Adjust.GetCertDate(ValidFromDate);
                    temp.validFrom = "Действителен до: <b>" + Adjust.GetCertDate(ValidToDate) + "<b>";
                    temp.signatureData.validDue = Adjust.GetCertDate(ValidToDate);
                    var pubKey = yield certx.PublicKey();
                    var algo = yield pubKey.Algorithm;
                    var fAlgoName = yield algo.FriendlyName;

                    temp.pubKey = pubKey;
                    temp.algo = algo;
                    temp.fAlgoName = fAlgoName;

                    temp.algorithm = "Алгоритм ключа: <b>" + fAlgoName + "<b>";

                    var hasPrivateKey = yield certx.HasPrivateKey();
                    var Now = new Date();

                    if (hasPrivateKey) {
                        var oPrivateKey = yield certx.PrivateKey;
                        var sProviderName = yield oPrivateKey.ProviderName;
                        temp.provname = "Криптопровайдер: <b>" + sProviderName + "<b>";
                        try {
                            var sPrivateKeyLink = yield oPrivateKey.UniqueContainerName;
                            temp.privateKeyLink = "Ссылка на закрытый ключ: <b> " + sPrivateKeyLink + "<b>";
                        } catch (e) {
                            temp.privateKeyLink = "Ссылка на закрытый ключ: <b>" + e.message + "<b>";
                        }
                    } else {
                        temp.provname = "Криптопровайдер:";
                        temp.privateKeyLink = "Ссылка на закрытый ключ:";
                    }
                    if (Now < ValidFromDate) {
                        temp.status = "Статус: <span style=\"color:red; font-weight:bold; font-size:16px\">Срок действия не наступил</span>";
                    } else if (Now > ValidToDate) {
                        temp.status = "Статус: <span style=\"color:red; font-weight:bold; font-size:16px\">Срок действия истек</span>";
                    } else if (!hasPrivateKey) {
                        temp.status = "Статус: <span style=\"color:red; font-weight:bold; font-size:16px\">Нет привязки к закрытому ключу</span>";
                    } else if (!IsValid) {
                        temp.status = "Статус: <span style=\"color:red; font-weight:bold; font-size:16px\">Ошибка при проверке цепочки сертификатов. Возможно на компьютере не установлены сертификаты УЦ, выдавшего ваш сертификат</span>";
                    } else {
                        temp.status = "Статус: <span style=\"color:darkgreen; font-weight:bold; font-size:16px\">Действителен</span>";
                    }

                    temp.isValid = IsValid;

                    /*if(args[3])
                    {
                        document.getElementById(field_prefix + "location").innerHTML = "Установлен в хранилище: <b>Нет</b>";
                    } else {
                        document.getElementById(field_prefix + "location").innerHTML = "Установлен в хранилище: <b>Да</b>";
                    }*/

                } catch (e) {
                    showError("Ошибка при получении свойств сертификата: " + GetErrorMessage(e));
                }

                try {
                    temp.thumbprint = yield certx.Thumbprint;
                    temp.signatureData.thumbprint = yield certx.Thumbprint;

                } catch (e) {
                    showError("Ошибка при получении свойства Thumbprint: " + GetErrorMessage(e));
                }
                if (temp.hasOwnProperty('thumbprint') && temp.hasOwnProperty('algo')) {
                    temp.description = temp.subject.replaceAll("CN=", '').replaceAll("<b>", "") + ', ' + temp.from.replaceAll("<b>", "");
                    certificatesList.push(temp);
                }
            }
            $('#jasperSignatureSelect').on('change', function () {
                let value = $('#jasperSignatureSelect').val();
                if (value != null && typeof value != 'undefined' && value !== '') {
                    let payload = null;
                    let breakException = {};
                    try {
                        certificatesList.forEach(el => {
                            if (el.thumbprint === value) {
                                payload = el;
                                throw breakException;
                            }
                        })
                    } catch (e) {
                    }
                    if (payload) {
                        $('#certificateSubject').html(payload.subject);
                        $('#certificateIssuer').html(payload.issuer);
                        $('#certificateFrom').html(payload.from);
                        $('#certificateValidFrom').html(payload.validFrom);
                        $('#certificateFAlgoName').html(payload.algorithm);
                        $('#certificateProvname').html(payload.provname);
                        $('#certificatePrivateKeyLink').html(payload.privateKeyLink);
                        $('#certificateStatus').html(payload.status);
                        if (payload.isValid) $('#certificateSubmitButton').show();
                        else $('#certificateSubmitButton').hide();
                        $('#certificateInfoDiv').show();
                        jasperDataToSign["params_handler_incoming_request_data"] = JSON.stringify(payload.signatureData);
                    } else {
                        $('#certificateInfoDiv').hide();
                    }

                } else {
                    $('#certificateInfoDiv').hide();
                }
            });
            $('#jasperSignatureSelect').empty();
            if (certificatesList.length > 0) {
                certificatesList.forEach(el => {
                    $('#jasperSignatureSelect').append($('<option>', {value: el.thumbprint, text: el.description}));
                })
                let payload = certificatesList[0];
                $('#certificateSubject').html(payload.subject);
                $('#certificateIssuer').html(payload.issuer);
                $('#certificateFrom').html(payload.from);
                $('#certificateValidFrom').html(payload.validFrom);
                $('#certificateFAlgoName').html(payload.algorithm);
                $('#certificateProvname').html(payload.provname);
                $('#certificatePrivateKeyLink').html(payload.privateKeyLink);
                $('#certificateStatus').html(payload.status);
                $('#certificateInfoDiv').show();
                jasperDataToSign["params_handler_incoming_request_data"] = JSON.stringify(payload.signatureData);
            } else {
                $('#certificateInfoDiv').hide();
            }

            yield oStore.Close();
            MicroModal.show("jasperSignatureModal");
        });
    }
}

async function jasperSignContainerData(hashToSign, certificate) {
    let oStore;
    cadesplugin.async_spawn(function* () {
        try {
            oStore = yield cadesplugin.CreateObjectAsync("CAdESCOM.Store");
        } catch (e) {
            showError("Невозможно загрузить хранилище сертификатов! " + GetErrorMessage(e));
            return
        }

        try {
            yield oStore.Open(cadesplugin.CAPICOM_CURRENT_USER_STORE, cadesplugin.CAPICOM_MY_STORE,
                cadesplugin.CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED);
        } catch (e) {
            showError("Ошибка при открытии хранилища: " + GetErrorMessage(e));
            return;
        }

        let oCerts
        try {
            let oAllCerts = yield oStore.Certificates;
            oCerts = yield oAllCerts.Find(cadesplugin.CAPICOM_CERTIFICATE_FIND_SHA1_HASH, certificate);
        } catch (e) {
            showError("Не удалось найти сертификат: " + GetErrorMessage(e));
            return;
        }

        if (yield oCerts.Count === 0) {
            showError("Сертификат для подписи не найден!");
            return;
        }

        const oCert = yield oCerts.Item(1);
        yield SignCreateAsync(oCert, hashToSign);
        yield oStore.Close();
    });
}

async function SignCreateAsync(oCert, dataToSign) {
    return new Promise(function () {
        cadesplugin.async_spawn(function* () {
            var oSigner = yield cadesplugin.CreateObjectAsync("CAdESCOM.CPSigner");
            yield oSigner.propset_Certificate(oCert);
            yield oSigner.propset_CheckCertificate(true);

            var oSignedData = yield cadesplugin.CreateObjectAsync("CAdESCOM.CadesSignedData");
            yield oSignedData.propset_ContentEncoding(cadesplugin.CADESCOM_BASE64_TO_BINARY);
            yield oSignedData.propset_Content(dataToSign);
            try {
                jasperResultSignature = yield oSignedData.SignCades(oSigner, cadesplugin.CADESCOM_CADES_BES, true);
            } catch (e) {
                showError("Failed to create signature. Error: " + GetErrorMessage(e));
            }
        });
    });
}

function GetErrorMessage(e) {
    let err = e.message;
    if (!err) {
        err = e;
    } else if (e.number) {
        err += " (" + e.number + ")";
    }
    return err;
}


function CertificateAdjuster() {
}

CertificateAdjuster.prototype.checkQuotes = function (str) {
    var result = 0, i = 0;
    for (i; i < str.length; i++) if (str[i] === '"')
        result++;
    return !(result % 2);
}

CertificateAdjuster.prototype.extract = function (from, what) {
    certName = "";

    var begin = from.indexOf(what);

    if (begin >= 0) {
        var end = from.indexOf(', ', begin);
        while (end > 0) {
            if (this.checkQuotes(from.substr(begin, end - begin)))
                break;
            end = from.indexOf(', ', end + 1);
        }
        certName = (end < 0) ? from.substr(begin) : from.substr(begin, end - begin);
    }

    return certName;
}

CertificateAdjuster.prototype.Print2Digit = function (digit) {
    return (digit < 10) ? "0" + digit : digit;
}

CertificateAdjuster.prototype.GetCertDate = function (paramDate) {
    var certDate = new Date(paramDate);
    return this.Print2Digit(certDate.getUTCDate()) + "." + this.Print2Digit(certDate.getUTCMonth() + 1) + "." + certDate.getFullYear() + " " +
        this.Print2Digit(certDate.getUTCHours()) + ":" + this.Print2Digit(certDate.getUTCMinutes()) + ":" + this.Print2Digit(certDate.getUTCSeconds());
}

CertificateAdjuster.prototype.GetCertName = function (certSubjectName) {
    return this.extract(certSubjectName, 'CN=');
}

CertificateAdjuster.prototype.GetIssuer = function (certIssuerName) {
    return this.extract(certIssuerName, 'CN=');
}

CertificateAdjuster.prototype.GetCertInfoString = function (certSubjectName, certFromDate) {
    return this.extract(certSubjectName, 'CN=') + "; Выдан: " + this.GetCertDate(certFromDate);
}


function CheckForPlugIn_AsyncJasperSignature() {
//     window.onload = function (e) {
//         document.getElementById('PluginEnabledImg').setAttribute("src", "green_dot.png");
//         document.getElementById('PlugInEnabledTxt').innerHTML = "Плагин загружен";
//         document.getElementById('CspEnabledImg').setAttribute("src", "yellow_dot.png");
//         document.getElementById('CspEnabledTxt').innerHTML = "КриптоПро CSP не загружен";
//     }
    document.getElementById('PluginEnabledImg').setAttribute("src", "green_dot.png");
    document.getElementById('PlugInEnabledTxt').innerHTML = "Плагин загружен";
    document.getElementById('CspEnabledImg').setAttribute("src", "yellow_dot.png");
    document.getElementById('CspEnabledTxt').innerHTML = "КриптоПро CSP не загружен";
    //
    // cadesplugin.async_spawn(function* () {
    //     var oAbout = yield cadesplugin.CreateObjectAsync("CAdESCOM.About");
    //     var CurrentPluginVersion = yield oAbout.PluginVersion;
    //     document.getElementById('PlugInVersionTxt').innerHTML = "Версия плагина: " + (yield CurrentPluginVersion.toString());
    //
    //     var ver = yield oAbout.CSPVersion("", 80);
    //     var ret = (yield ver.MajorVersion) + "." + (yield ver.MinorVersion) + "." + (yield ver.BuildVersion);
    //     document.getElementById('CSPVersionTxt').innerHTML = "Версия криптопровайдера: " + ret;
    //     try {
    //         var sCSPName = yield oAbout.CSPName(80);
    //         document.getElementById('CspEnabledImg').setAttribute("src", "green_dot.png");
    //         document.getElementById('CspEnabledTxt').innerHTML = "Криптопровайдер загружен";
    //         document.getElementById('CSPNameTxt').innerHTML = "Криптопровайдер: " + sCSPName;
    //     } catch (err) {
    //     }
    // });


}
