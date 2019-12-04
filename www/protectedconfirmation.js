"use strict"
var exec = cordova.require('cordova/exec');

var ProtectedConfirmation = {
	serviceName: "ProtectedConfirmation",

    isSupported: function(success, error) {
        exec(success, error, this.serviceName, "isSupported");
    },

    initKey: function(success, error, challenge) {
		exec(success, error, this.serviceName, "initKey", [challenge]);
    },

    getCertificateChain: function(success, error) {
        exec(success, error, this.serviceName, "getCertificateChain");
    },

    presentPrompt: function(success, error, promptText, extraData, confirmationCallback) {
        exec(success, error, this.serviceName, "presentPrompt", [promptText, extraData, confirmationCallback]);
    },
};


if (typeof module != 'undefined' && module.exports) {
    module.exports = ProtectedConfirmation;
}
