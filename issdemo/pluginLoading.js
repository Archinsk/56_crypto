console.log("---Точка 5");
console.log("---Загрузка плагина");

var txtDataToSign = "Hello World";
document.getElementById("DataToSignTxtBox").innerHTML = txtDataToSign;
document.getElementById("SignatureTxtBox").innerHTML = "";
var canPromise = !!window.Promise;
if (isEdge()) {
    ShowEdgeNotSupported();
} else {
    if (canPromise) {
        cadesplugin.then(function () {
                console.log("---Точка 5.1");
                console.log("---Запуск проверки плагина");
                Common_CheckForPlugIn();
            },
            function (error) {
                console.log("Проверка расширения");
                if (!window.cadesplugin_extension_loaded) {
                    document.getElementById('PluginEnabledImg').setAttribute("src", "Img/red_dot.png");
                    document.getElementById('PlugInEnabledTxt').innerHTML = error;
                }
            }
        );
    } else {
        window.addEventListener("message", function (event) {
                if (event.data == "cadesplugin_loaded") {
                    CheckForPlugIn_NPAPI();
                } else if (event.data == "cadesplugin_load_error") {
                    if (window.cadesplugin_extension_loaded) {
                        document.getElementById('PluginEnabledImg').setAttribute("src", "Img/red_dot.png");
                        document.getElementById('PlugInEnabledTxt').innerHTML = "Плагин не загружен";
                    }
                }
            },
            false);
        window.postMessage("cadesplugin_echo_request", "*");
    }
}

// Установка в поле исходной информации текста "Hello World" и очистка поля для вывода подписи
