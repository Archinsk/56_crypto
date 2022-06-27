console.log("---Точка 1");
console.log('---Файл обновления информации на странице о загрузке расширения');

function setExtensionLoadingInfo() {
    console.log("---Точка 1.3");
    console.log('---Запуск колбэка "Расширение загружено"');
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
        console.log("---Точка 1.2");
        console.log('---Выполнение после загрузки окна колбэка "Расширение загружено"');
        setExtensionLoadingInfo();
    }
    console.log("---Точка 1.1");
    console.log('---Вызов "window.cadesplugin_extension_loaded_callback()" из cadesplugin.api');
    setExtensionLoadingInfo();
    setTimeout(Common_CheckForPlugIn, 200);
    // Common_CheckForPlugIn();
}
window.cadesplugin_extension_loaded_callback = extensionLoadedCallback;

// Смена информации на странице о загрузке расширения по вызову из cadesplugin_api
