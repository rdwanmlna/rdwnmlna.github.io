// script.js
function encryptMessage() {
    var message = document.getElementById("message").value;
    var key = CryptoJS.enc.Utf8.parse("SuperSecretKey123");
    var iv = CryptoJS.lib.WordArray.random(16);

    var encrypted = CryptoJS.AES.encrypt(message, key, {
        iv: iv,
        mode: CryptoJS.mode.CFB
    });

    var encryptedMessage = iv.concat(encrypted.ciphertext).toString(CryptoJS.enc.Hex);
    document.getElementById("encryptedMessage").value = encryptedMessage;
}

function decryptMessage() {
    var encryptedMessage = document.getElementById("encryptedMessageInput").value;
    var key = CryptoJS.enc.Utf8.parse("SuperSecretKey123");
    var iv = CryptoJS.enc.Hex.parse(encryptedMessage.slice(0, 32));
    var ciphertext = CryptoJS.enc.Hex.parse(encryptedMessage.slice(32));

    var decrypted = CryptoJS.AES.decrypt({ciphertext: ciphertext}, key, {
        iv: iv,
        mode: CryptoJS.mode.CFB
    });

    var decryptedMessage = decrypted.toString(CryptoJS.enc.Utf8);
    document.getElementById("decryptedMessage").value = decryptedMessage;
}
