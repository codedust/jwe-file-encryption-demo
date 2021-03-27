// SPDX-FileCopyrightText: 2021 codedust <codedust@so.urceco.de>
//
// SPDX-License-Identifier: EUPL-1.2

import CompactEncrypt from './panva-jose/dist/browser/jwe/compact/encrypt.js'
import CompactDecrypt from './panva-jose/dist/browser/jwe/compact/decrypt.js'
import generateKeyPair from './panva-jose/dist/browser/util/generate_key_pair.js'
import parseJwk from './panva-jose/dist/browser/jwk/parse.js'
import { Base64 } from './js-base64/base64.mjs';

const fileElement = document.getElementById("input");
const pElement = document.querySelector('#log');
const checkboxElement = document.querySelector('#showJWE');

document.querySelector('#btnPanva').addEventListener('click', jwe_test_panva, false);
document.querySelector('#btnJsJose').addEventListener('click', jwe_test_jsjose, false);

// show file in preview img element
function showFile(ui8) {
    const preview = document.querySelector('img');
    const reader = new FileReader();
    reader.addEventListener("load", function () {
      // convert image file to base64 string
      preview.src = reader.result;
    }, false);

    reader.readAsDataURL(new Blob([ui8], {type: 'image/png'}));
}

// helper function
function log(text){
  var el = document.createElement('p');
  el.textContent = text;
  pElement.appendChild(el);
}

// encryption and decryption using panva/jose
async function jwe_test_panva(){
  log('----- panva/jose test -----');
  if (!window.isSecureContext) {
    log("This page is not running in secure context. Aborting.");
    log("See https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts for details.");
    return;
  }

  // get file as Uint8Array
  const ui8 = await fileElement.files[0].arrayBuffer();
  log("plaintext size: " + ui8.byteLength/1000 + " KB");

  // generate key pair
  const { publicKey, privateKey } = await generateKeyPair('RSA-OAEP-256', { modulusLength: 4096 });
  log("key generation completed");

  //const encoder = new TextEncoder()
  //const jwe = await new CompactEncrypt(encoder.encode("Alice, you are my soulmate!"))

  // encrypt
  const a = new Date(); // start measuring
  const jwe = await new CompactEncrypt(ui8)
    .setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256GCM' })
    .encrypt(publicKey)
  const b = new Date();

  log("panva/jose (compact serialization, encryption) took " + (b-a) + " milliseconds");
  log("jwe size: " + jwe.length/1000 + " KB")

  // log jwe to DOM
  if (checkboxElement.checked) {
    const jweElement = document.querySelector('code');
    jweElement.textContent = jwe;
  }

  // decrypt
  const c = new Date();
  const { plaintext, protectedHeader } = await CompactDecrypt(jwe, privateKey)
  const d = new Date();
  log("panva/jose (compact serialization, decryption) took " + (d-c) + " milliseconds");

  showFile(plaintext);
  log("decrypted size: " + plaintext.byteLength/1000 + " KB");

  console.log("protectedHeader", protectedHeader)
}

// encryption and decryption using square/js-jose
async function jwe_test_jsjose() {
  log('----- square/js-jose test -----');
  if (!window.isSecureContext) {
    log("This page is not running in secure context. Aborting.");
    log("See https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts for details.");
    return;
  }

  // get file as Uint8Array
  const utf8buffer = await fileElement.files[0].arrayBuffer();
  var ui8 = new Uint8Array(utf8buffer);
  log("plaintext size: " + ui8.byteLength/1000 + " KB");

  // encode file as string
  const str = Base64.fromUint8Array(ui8);

  // generate key pair
  let keyPair = await window.crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 4096,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256"
    },
    true,
    ["encrypt", "decrypt", "wrapKey"]
  );
  log("key generation completed");

  // export the key in JWK format - optional
  const jwk_key = await crypto.subtle.exportKey('jwk', keyPair.privateKey);

  // import the key to Jose library - optional
  var public_rsa_key = Jose.Utils.importRsaPublicKey(jwk_key, "RSA-OAEP-256");
  var private_rsa_key = Jose.Utils.importRsaPrivateKey(jwk_key, "RSA-OAEP-256");

  const a = new Date();
  // create WebCryptographer instance
  var cryptographer = new Jose.WebCryptographer();
  cryptographer.setKeyEncryptionAlgorithm('RSA-OAEP-256');

  // either use the imported key or use the public key from the keypair directly
  //var encrypter = new Jose.JoseJWE.Encrypter(cryptographer, public_rsa_key);
  var encrypter = new Jose.JoseJWE.Encrypter(cryptographer, keyPair.publicKey);

  // encrypt
  encrypter.encrypt(str).then(function(jwe) {

    // log jwe to DOM
    if (checkboxElement.checked) {
      const jweElement = document.querySelector('code');
      jweElement.textContent = jwe;
    }

    const b = new Date();
    log("square/js-jose (compact serialization, encryption took " + (b-a) + " milliseconds)");
    log("jwe size: " + jwe.length/1000 + " KB")

    // create decrypter instance
    var decrypter = new Jose.JoseJWE.Decrypter(cryptographer, private_rsa_key);

    // decrypt
    const c = new Date();
    decrypter.decrypt(jwe).then(function(plaintext_decrypted_str) {
      if (plaintext_decrypted_str != str) {
        log("square/js-jose decryption failed!");
      } else {
        // success
        const d = new Date();
        log("square/js-jose (compact serialization, decryption) took " + (d-c) + " milliseconds");

        const plaintext_decrypted = Base64.toUint8Array(plaintext_decrypted_str);
        log("decrypted size: " + plaintext_decrypted.byteLength/1000 + " KB")

        showFile(plaintext_decrypted);
      }
    }).catch(function(err) {
      log("square/js-jose " + err);
    });
  }).catch(function(err){
    log("square/js-jose " + err);
  });
}
