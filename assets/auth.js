function register () {
    let username = document.getElementById('username').value;
    if (username === "") {
        alert("Please enter a username");
        return;
    }

    fetch('http://localhost:8080/register_start/' + username, {
        method: 'POST'
    })
    .then(response => response.json() )
    .then(credentialCreationOptions => {
        credentialCreationOptions.publicKey.challenge = Base64.toUint8Array(credentialCreationOptions.publicKey.challenge);
        credentialCreationOptions.publicKey.user.id = Base64.toUint8Array(credentialCreationOptions.publicKey.user.id);

        return navigator.credentials.create({
            publicKey: credentialCreationOptions.publicKey
        });
    })
    .then((credential) => {
        fetch('http://localhost:8080/register_finish', {
            method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    id: credential.id,
                    rawId: bufferEncode(credential.rawId),
                    type: credential.type,
                    response: {
                        attestationObject: bufferEncode(credential.response.attestationObject),
                        clientDataJSON: bufferEncode(credential.response.clientDataJSON),
                },
            })
        })
        .then((response) => {
            if (response.ok){
                console.log("Registered!");
            } else {
                console.log("Error");
            }
        });
    })
}

function login() {
    let username = document.getElementById('username').value;
    if (username === "") {
        alert("Please enter a username");
        return;
    }

    fetch('http://localhost:8080/login_start/' + username, {
        method: 'POST'
    })
    .then(response => response.json())
    .then((credentialRequestOptions) => {
        credentialRequestOptions.publicKey.challenge = Base64.toUint8Array(credentialRequestOptions.publicKey.challenge);
        credentialRequestOptions.publicKey.allowCredentials.forEach(function (listItem) {
            listItem.id = Base64.toUint8Array(listItem.id)
        });

        return navigator.credentials.get({
            publicKey: credentialRequestOptions.publicKey
        });
    })
    .then((assertion) => {
        fetch('http://localhost:8080/login_finish', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                id: assertion.id,
                rawId: bufferEncode(assertion.rawId),
                type: assertion.type,
                response: {
                    authenticatorData: bufferEncode(assertion.response.authenticatorData),
                    clientDataJSON: bufferEncode(assertion.response.clientDataJSON),
                    signature: bufferEncode(assertion.response.signature),
                    userHandle: assertion.response.userHandle
                },
            }),
        })
        .then((response) => {
            if (response.ok){
                console.log("Logged In!");
            } else {
                console.log("Error");
            }
        });
    });
}

// Converts ArrayBuffer to URLBase64
function bufferEncode(value) {
    return btoa(String.fromCharCode.apply(null, new Uint8Array(value)));
}