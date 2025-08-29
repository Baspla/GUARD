console.log('Passkey registration script loaded');

const { startRegistration } = SimpleWebAuthnBrowser;
// <button>
const elemBegin = document.getElementById('btnBegin');
// <span>/<p>/etc...
const elemSuccess = document.getElementById('success');
// <span>/<p>/etc...
const elemError = document.getElementById('error');

// Start registration when the user clicks a button
elemBegin.addEventListener('click', async () => {
// Reset success/error messages
elemSuccess.innerHTML = '';
elemError.innerHTML = '';

// GET registration options from the endpoint that calls
// @simplewebauthn/server -> generateRegistrationOptions()
const resp = await fetch('/generate-registration-options');
const optionsJSON = await resp.json();

let attResp;
try {
    // Pass the options to the authenticator and wait for a response
    attResp = await startRegistration({ optionsJSON });
} catch (error) {
    // Some basic error handling
    if (error.name === 'InvalidStateError') {
    elemError.innerText = 'Error: Authenticator was probably already registered by user';
    } else {
    elemError.innerText = error;
    }

    throw error;
}

// POST the response to the endpoint that calls
// @simplewebauthn/server -> verifyRegistrationResponse()
const verificationResp = await fetch('/verify-registration', {
    method: 'POST',
    headers: {
    'Content-Type': 'application/json',
    },
    body: JSON.stringify(attResp),
});

// Wait for the results of verification
const verificationJSON = await verificationResp.json();

// Show UI appropriate for the `verified` status
if (verificationJSON && verificationJSON.verified) {
    elemSuccess.innerHTML = 'Success!';
} else {
    elemError.innerHTML = `Oh no, something went wrong! Response: <pre>${JSON.stringify(
    verificationJSON,
    )}</pre>`;
}
});