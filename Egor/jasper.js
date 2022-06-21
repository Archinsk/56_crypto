var jasperDataToSign = null;
var certificatesList = [];
var jasperResultSignature = null;

async function InternalJasperSignatureSign(actionPayload, submitPayload) {
    let appData = actionPayload.appData;

    let payload = {};
    payload["params_handler_model"] = appData.modelId;
    payload["params_handler_form_id"] = appData.formId;
    payload["params_handler_data"] = appData.formData;
    payload["params_handler_application"] = appData.appId;
    payload["params_handler_action"] = actionPayload.endpoint;
    payload["camunda_session_id"] = camunda_session_id;
    jasperDataToSign = payload;
    CheckForPlugIn_AsyncJasperSignature();
    getJasperSignatureCertificatesList();
}

async function getSignedData(readyCallback) {
    await getAuth();
    let response = await axios.post("/o/handler/invokeAJAX", jasperDataToSign, {headers: {'Content-Type': 'application/json; charset=UTF-8'}})
    if (response.data.hasOwnProperty('error')) {
        showError(response.data.error);
        console.debug("Error while printing report");
    } else {
        if (response.data.hasOwnProperty('hashToSign')) {
            await jasperSignContainerData(response.data.hashToSign, JSON.parse(jasperDataToSign.params_handler_incoming_request_data).thumbprint);
            await jasperSignatureTimes();
            if (jasperResultSignature) {
                let JSONObject = {};
                JSONObject.hashToSign = response.data.hashToSign;
                JSONObject.signature = jasperResultSignature;
                JSONObject.fileName = response.data.fileName;
                JSONObject.app_id = $('#' + camundaNameSpace + 'app_id').val();

                let finalResponse = await axios.post("/o/jasper/fillJasperSignatureData", JSONObject, {headers: {'Content-Type': 'application/json; charset=UTF-8'}})
                if (finalResponse.data.hasOwnProperty('error')) {
                    showError(finalResponse.data.error);
                } else {
                    download("data:application/octet-stream;base64," + finalResponse.data.signedFile, response.data.fileName, "application/octet-stream");
                    if (typeof readyCallback === 'function') {
                        readyCallback();
                    }
                }
            } else {
                showError('Ошибка при формировании подписи!')
                console.debug("unable to create signature");
            }
        } else {
            showError('Ошибка при формировании подписи!');
        }

    }
}

async function jasperSignatureTimes() {
    for (let i = 0; i < 30; i++) {
        if (jasperResultSignature) break;
        await timer(500);
    }
}

const timer = ms => new Promise(res => setTimeout(res, ms))
