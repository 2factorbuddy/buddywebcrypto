var buddywebcrypto = require('../index');
var assert = require('chai').assert;

describe('Test', function() {
  it('should encrypt and decrypt', function(done) {
    //var iv = crypto.getRandomValues(new Uint8Array(16));
    var iv = buddywebcrypto.convertStringToArrayBufferView("AAAAAAAAAAAAAAAA");
    var key = buddywebcrypto.convertStringToArrayBufferView("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

    var plaintext = '012';

    buddywebcrypto.encrypt(plaintext, { key: key, iv: iv, algorithm: 'AES-GCM' })
      .then(
        function success(response) {
          return buddywebcrypto.decrypt(response.ciphertext, { key: key, iv: iv, algorithm: 'AES-GCM' });
        }
      )
      .then(
        function success(response) {
          assert.equal(response.plaintext, plaintext, 'should have expected plaintext');
          return done();
        },
        function error(e) {
          return done(e);
        }
      );
  });
});
