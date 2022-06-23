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
        console.log("Могу промис");
        cadesplugin.then(function () {
                console.log("Проверяю плагин");
                Common_CheckForPlugIn();
            },
            function (error) {
                console.log("Проверка расширения");
                if (window.cadesplugin_extension_loaded) {
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
