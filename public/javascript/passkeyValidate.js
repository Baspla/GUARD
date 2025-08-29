const { startAuthentication } = SimpleWebAuthnBrowser;
// <button>
const elemBegin = document.getElementById('btnBegin');
// <span>/<p>/etc...
const elemSuccess = document.getElementById('success');
// <span>/<p>/etc...
const elemError = document.getElementById('error');

// Start authentication when the user clicks a button
elemBegin.addEventListener('click', async () => {
    // Reset success/error messages
    elemSuccess.innerHTML = '';
    elemError.innerHTML = '';

    // GET authentication options from the endpoint that calls
    // @simplewebauthn/server -> generateAuthenticationOptions()
    const resp = await fetch('/generate-authentication-options');
    const optionsJSON = await resp.json();

    let asseResp;
    try {
        // Pass the options to the authenticator and wait for a response
        asseResp = await startAuthentication({ optionsJSON });
    } catch (error) {
        // Some basic error handling
        elemError.innerText = error;
        throw error;
    }

    // POST the response to the endpoint that calls
    // @simplewebauthn/server -> verifyAuthenticationResponse()
    const verificationResp = await fetch('/verify-authentication', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(asseResp),
    });

    // Wait for the results of verification
    const verificationJSON = await verificationResp.json();
    console.log(verificationJSON);

    // Show UI appropriate for the `verified` status
    if (verificationJSON && verificationJSON.verified) {
        if (verificationJSON.redirect) {
            window.location.href = verificationJSON.redirect;
        } else {
            window.location.href = '/';
        }
    } else {
        elemError.innerHTML = `Oh no, something went wrong! Response: <pre>${JSON.stringify(
            verificationJSON,
        )}</pre>`;
    }
});