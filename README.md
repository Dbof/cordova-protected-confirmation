# Cordova-Protected-Confirmation plugin for Cordova
This Cordova plugin provides the [Protected Confirmation](https://source.android.com/security/protected-confirmation) functionality introduced in Android 9 (Pie).
Note that Android Protected Confirmation Protected Confirmation may not be supported by all devices running Android Pie but requires a special co-processor in order to work. Also, this plugin **only works with Android**, at the moment there is no similar API for iOS.

At the time of writing this, only the following devices are supported:

- Google Pixel 3
- Google Pixel 3XL
- Google Pixel 3A


## Getting Started

### Install with cordova-cli
If you are using [cordova-cli](https://github.com/apache/cordova-cli), install with:

```
cordova plugins add https://github.com/Dbof/cordova-protected-confirmation.git
```


### Install with plugman

With [plugman](https://github.com/apache/cordova-plugman) and ``git`` installed, you should be able to install it with:

```
plugman --plugin https://github.com/Dbof/cordova-protected-confirmation.git --platform android --project <directory> 
```

## Methods
Every method has a success and an error callback. The ``success`` callback usually returns the requested value, while ``error`` contains an error message for debugging purposes.

- ``cordova.plugin.protectedconfirmation.isSupported(success(supported), error(msg));``
- ``cordova.plugin.protectedconfirmation.initKey(success, error(msg), base64_challenge);``
- ``cordova.plugin.protectedconfirmation.getCertificateChain(success(chain), error(msg));``
- ``cordova.plugin.protectedconfirmation.presentPrompt(success([base64_dataThatWasConfirmed, base64_signature]), error(msg), promptText, base64_extraData);``

### isSupported
Checks if Protected Confirmation is supported on the current device.

- Success callback argument: true/false

### initKey
Creates a new key which will be used to sign the Protected Confirmation message to be confirmed. A base64-encoded challenge should be provided. As a best practice, **the attestation server should provide this value** and save it to confirm the uniqueness of the key.

- Success callback argument: None

### getCertificateChain
Get the attestation certificate chain of your created key. You need to call initKey first in order to create an appropriate key. The certificates use the PEM format (plaintext) and are concatenated with the '|' character. Example:

```
"-----BEGIN CERTIFICATE-----
MIICkjCCAjagAwIBAgIBATAMBggqhkjOPQQDAgUAMC8xGTAXBgNVBAUTEDkwZThkYTNjYWRmYzc4MjAxEjAQBgNVBAwMCVN0cm9uZ0JveDAeFw03MDAxMDEwMDAwMDBaFw0yODA1MjMyMzU5NTlaMB8xHTAbBgNVBAMMFEFuZHJvaWQgS2V5c3RvcmUgS2V5MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESSzblfw5vKUHXYLpdW0OZf17GlYYDzS0SSU6zoqXNK/r3zC9ICi8vKHL3EfAXLJX9ZndFzRT767tJwKh4WyFMqOCAU8wggFLMA4GA1UdDwEB/wQEAwIHgDCCATcGCisGAQQB1nkCAREEggEnMIIBIwIBAwoBAgIBBAoBAgQOTXlLZXlDaGFsbGVuZ2UEADBcv4U9CAIGAW7R6A/Xv4VFTARKMEgxIjAgBBpkZS5mYXUudGYuY3MxLm5vdGFuLmNsaWVudAICJxAxIgQgOlN+NOHxplrRe9QFeunm880GaTVOwat52RI2+koJIpIwgaShBTEDAgECogMCAQOjBAICAQClCDEGAgEEAgEGv4N3AgUAv4N8AgUAv4U+AwIBAL+FQEwwSgQgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAQAKAQIEIDREORG7UGhP1fR0R7uq3fs9S0/hgn5mx2CHcMug8YPrv4VBBQIDAV+Qv4VCBQIDAxSzv4VOBgIEATPvqb+FTwUCAwMUszAMBggqhkjOPQQDAgUAA0gAMEUCIQDmiKSNuYKyFd7NmyKf5AS4NWkgmhsvR6dC3FKqoIym2QIgByjTHS/mtIrpWnXfIAbZQkEhR7rmPGUt5romyAO9Vhk=
-----END CERTIFICATE-----|-----BEGIN CERTIFICATE-----
MIICMDCCAbegAwIBAgIKESM4JDRACGgBcTAKBggqhkjOPQQDAjAvMRkwFwYDVQQFExBjY2QxOGI5YjYwOGQ2NThlMRIwEAYDVQQMDAlTdHJvbmdCb3gwHhcNMTgwNTI1MjMyODUwWhcNMjgwNTIyMjMyODUwWjAvMRkwFwYDVQQFExA5MGU4ZGEzY2FkZmM3ODIwMRIwEAYDVQQMDAlTdHJvbmdCb3gwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATkV0TCsZ+vcIoXK0BLe4q4sQ1veBPE228LqldQCQPCb6IBCpM7rHDgKmsaviWtsA0anJyUpXHTVix0mdIy9Xcno4G6MIG3MB0GA1UdDgQWBBRvsbUxnba4hRW+z8AMdxqP51TqljAfBgNVHSMEGDAWgBS8W8vVecaU3BmPm59nU8zr5mLf3jAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwICBDBUBgNVHR8ETTBLMEmgR6BFhkNodHRwczovL2FuZHJvaWQuZ29vZ2xlYXBpcy5jb20vYXR0ZXN0YXRpb24vY3JsLzExMjMzODI0MzQ0MDA4NjgwMTcxMAoGCCqGSM49BAMCA2cAMGQCMFBzxlbrGJarX+e8d7UfD5M2Br3QxKUFAS1tfGxy9Lw72yfFn8v3jxNyCamglqpw8gIwYkzbZDvx/uU6vXIaB1y0PRGq5Jp5xIgKqUEJvsBuyMN8JdJsfzvHbkYyZUujU/SV
-----END CERTIFICATE-----|…
```

- Success callback arguments: String with attestation certificate chain

### presentPrompt
Shows the actual fullscreen confirmation dialog with a given text. The extraData field should contain some base64-encoded unique data (e.g. a nonce). The extraData is not shown to the user, but included into the signed message that is returned to the application.
As a best practice, the extraData **should be checked by the remote party against a list of already-used values** in order to counter [replay attacks](https://en.wikipedia.org/wiki/Replay_attack).
The result includes both the confirmed message and the signature as base64-encoded string.

- Success callback argument: Array[base64_dataThatWasConfirmed, base64_signature]


## Example
```javascript
// errorCallback
var errorCallback = function(msg) {
    if (message !== undefined)
        alert(msg);
    else
        alert('An error occured');
}

// generate a key
cordova.plugin.protectedconfirmation.isSupported(function(ret) {
    if (ret) {
        var base64challenge = btoa('MyKeyChallenge');
        // init key generation
        cordova.plugin.protectedconfirmation.initKey(function() {
            // Key generation was successful!
            cordova.plugin.protectedconfirmation.getCertificateChain(function(chain) {
                // chain is an arraybuffer consistent of:
                // PEM_CERT_1 | PEM_CERT_2 | ... | PEM_CERT_ROOT
                if ("TextDecoder" in window) {
                    var dec = new TextDecoder();
                    console.log(dec.decode(chain));
                }
            }, errorCallback);
        }, errorCallback, base64challenge);

    } else {
        confirm('Protected Confirmation is currently not supported on this device!');
    }
}, errorCallback);

// present prompt
cordova.plugin.protectedconfirmation.presentPrompt(function(val){
    alert("dataThatWasConfirmed: " + atob(val[0]));
    alert("signature: " + atob(val[1]));
}, errorCallback, `Send 100€ to ?`, btoa('SomeExtraData'));
```

On a connected test device, you can check the logs with the following command:

```
adb logcat chromium:D SystemWebViewClient:D *:S
```


## License
The Cordova-Protected-Confirmation plugin for Cordova is open-sourced software licensed under the [MIT license](http://opensource.org/licenses/MIT).
