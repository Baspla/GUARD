const elemConfirm = document.getElementById("confirmRemoveButton");

elemConfirm.addEventListener("click", async () => {
    const passkeyId = elemConfirm.getAttribute("data-passkey-id");
    const response = await fetch(`/passkeyRemove?id=${passkeyId}`, {
        method: "DELETE"
    });
    if (response.ok) {
        // Passkey erfolgreich entfernt
        window.location.href = "/passkeymanage";
    } else {
        // Fehler beim Entfernen des Passkeys
        const errorData = await response.json();
        alert(errorData.error || "Unbekannter Fehler");
    }
});
