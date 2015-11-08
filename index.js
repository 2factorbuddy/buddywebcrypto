var precond = require('precond');
var pkcs7 = require('pkcs7');

function encode_utf8(s) {
  return unescape(encodeURIComponent(s));
}

function decode_utf8(s) {
  return decodeURIComponent(escape(s));
}

function convertStringToArrayBufferView(str) {
  var utf8Str = decode_utf8(str);

  var bytes = new Uint8Array(utf8Str.length);
  for (var iii = 0; iii < utf8Str.length; iii++) {
    bytes[iii] = utf8Str.charCodeAt(iii);
  }

  return bytes;
}

function convertArrayBufferViewtoString(buffer) {
  var str = "";
  for (var iii = 0; iii < buffer.byteLength; iii++) {
    str += String.fromCharCode(buffer[iii]);
  }

  return encode_utf8(str);
}

/**
 * Generates a key of X length 
 */
function generateKey(length) {
  length = length || 256;

  return crypto.subtle.generateKey(
    { 
      name: 'AES-GCM', 
      length: length,
    },
    true, // is the key extractable?
    [
      "encrypt",
      "decrypt"
    ]
  );
}

module.exports = {
  generateKey: generateKey,
  encrypt: function(plaintext, options) {
    precond.checkIsDef(options);
    precond.checkIsDef(options.key);
    precond.checkIsDef(options.iv);
    precond.checkIsDef(options.algorithm);

    var plaintextBuffer = pkcs7.pad(convertStringToArrayBufferView(plaintext));
    var additionalData = convertStringToArrayBufferView('hola');

    return crypto.subtle.importKey(
      'raw', 
      options.key, 
      { name: 'AES-GCM', length: 256 }, 
      true, 
      ['encrypt', 'decrypt']
    ).then(
      function success(key) {
        return crypto.subtle.encrypt(
          {name: 'AES-GCM', iv: options.iv, tagLength: 128, additionalData: additionalData}, 
          key, 
          plaintextBuffer
        );
      }
    ).then(
      function success(ciphertext) {
        return {
          ciphertext: new Uint8Array(ciphertext),
          key: options.key,
          iv: options.iv,
          algorithm: options.algorithm
        };
      }
    );
  },
  decrypt: function(ciphertext, options) {
    precond.checkIsDef(options);
    precond.checkIsDef(options.key);
    precond.checkIsDef(options.iv);
    precond.checkIsDef(options.algorithm);
    
    var additionalData = convertStringToArrayBufferView('hola');

    return crypto.subtle.importKey(
      'raw', 
      options.key, 
      { name: 'AES-GCM', length: 256 }, 
      true, 
      ['encrypt', 'decrypt']
    ).then(
      function success(key) {
        return crypto.subtle.decrypt(
          {name: 'AES-GCM', iv: options.iv, tagLength: 128, additionalData: additionalData}, 
          key, 
          ciphertext
        );
      }
    ).then(
      function success(plaintextBuffer) {
        return {
          plaintext: convertArrayBufferViewtoString(pkcs7.unpad(new Uint8Array(plaintextBuffer))),
          key: options.key,
          iv: options.iv,
          algorithm: options.algorithm
        };
      }
    );
  },
  convertArrayBufferViewtoString: convertArrayBufferViewtoString,
  convertStringToArrayBufferView: convertStringToArrayBufferView
};
