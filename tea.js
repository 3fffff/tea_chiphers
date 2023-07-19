class Tea {
  /**
   * Encrypts text using Corrected Block TEA (xxtea) algorithm.
   *
   * @param   {string} plaintext - String to be encrypted (multi-byte safe).
   * @param   {string} password - Password to be used for encryption (1st 16 chars).
   * @returns {string} Encrypted text (encoded as base64).
   */
  static encrypt(plaintext, password, keyLength = 32) {
    const pow2 = Math.log2(keyLength)
    if (pow2 != ~~pow2) throw Error("keyLength must be power of 2");
    plaintext = String(plaintext);
    password = String(password);

    if (plaintext.length == 0) return ''; // nothing to encrypt

    //  v is n-word data vector; converted to array of longs from UTF-8 string
    const v = Tea.strToUint32(Tea.utf8Encode(plaintext));

    //  k is 4-word key; simply convert first 16 chars of password as key
    const k = Tea.strToUint32(Tea.utf8Encode(password).slice(0, keyLength));
    const k64 = Tea.strToUint64(Tea.utf8Encode(password).slice(0, keyLength))
    const d64 = Tea.uint64ToStr(k64)
    console.log(k64)
    console.log(d64)
    console.log(k)
    const cipher = Tea.encodeRTEA(v, k);

    // convert array of longs to string
    const ciphertext = Tea.uint32ToStr(cipher);

    // convert binary string to base64 ascii for safe transport
    const cipherbase64 = Tea.base64Encode(ciphertext);

    return cipherbase64;
  }


  /**
   * Decrypts text using Corrected Block TEA (xxtea) algorithm.
   *
   * @param   {string} ciphertext - String to be decrypted.
   * @param   {string} password - Password to be used for decryption (1st 16 chars).
   * @returns {string} Decrypted text.
   * @throws  {Error}  Invalid ciphertext
   */
  static decrypt(ciphertext, password, keyLength = 32) {
    const pow2 = Math.log2(keyLength)
    if (pow2 != ~~pow2) throw Error("keyLength must be power of 2");
    ciphertext = String(ciphertext);
    password = String(password);

    if (ciphertext.length == 0) return '';  // nothing to decrypt

    //  v is n-word data vector; converted to array of longs from base64 string
    const v = Tea.strToUint32(Tea.base64Decode(ciphertext));
    //  k is 4-word key; simply convert first 16 chars of password as key
    const k = Tea.strToUint32(Tea.utf8Encode(password).slice(0, keyLength));

    const plain = Tea.decodeRTEA(v, k);

    const plaintext = Tea.uint32ToStr(plain);

    // strip trailing null chars resulting from filling 4-char blocks:
    const plainUnicode = Tea.utf8Decode(plaintext.replace(/\0+$/, ''));

    return plainUnicode;
  }


  /**
   * XXTEA: encodes array of unsigned 32-bit integers using 128-bit key.
   *
   * @param   {number[]} v - Data vector.
   * @param   {number[]} k - Key.
   * @returns {number[]} Encoded vector.
   */
  static encode(v, k) {
    if (v.length < 2) v[1] = 0;  // algorithm doesn't work for n<2 so fudge by adding a null
    const n = v.length;
    const delta = 0x9e3779b9;
    let q = Math.floor(6 + 52 / n);

    let z = v[n - 1], y = v[0];
    let mx, e, sum = 0;

    while (q-- > 0) {  // 6 + 52/n operations gives between 6 & 32 mixes on each word
      sum += delta;
      e = sum >>> 2 & 3;
      for (let p = 0; p < n; p++) {
        y = v[(p + 1) % n];
        mx = (z >>> 5 ^ y << 2) + (y >>> 3 ^ z << 4) ^ (sum ^ y) + (k[p & 3 ^ e] ^ z);
        z = v[p] += mx;
      }
    }

    return v;
  }

  /**
 * XXTEA: decodes array of unsigned 32-bit integers using 128-bit key.
 *
 * @param   {number[]} v - Data vector.
 * @param   {number[]} k - Key.
 * @returns {number[]} Decoded vector.
 */
  static decode(v, k) {
    const n = v.length;
    const delta = 0x9e3779b9;
    const q = Math.floor(6 + 52 / n);

    let z = v[n - 1], y = v[0];
    let mx, e, sum = q * delta;

    while (sum != 0) {
      e = sum >>> 2 & 3;
      for (let p = n - 1; p >= 0; p--) {
        z = v[p > 0 ? p - 1 : n - 1];
        mx = (z >>> 5 ^ y << 2) + (y >>> 3 ^ z << 4) ^ (sum ^ y) + (k[p & 3 ^ e] ^ z);
        y = v[p] -= mx;
      }
      sum -= delta;
    }

    return v;
  }

  static encodeRTEA(v, k) {
    for (let i = 0; i < v.length; i += 2) {
      let a = v[i], b = v[i + 1];
      for (let r = 0; r < k.length * 4 + 32; r++) {
        b &= 0xFFFFFFFF;//overflow prevention
        const c = b;
        b += a + ((b << 6) ^ (b >> 8)) + k[r % k.length] + r;
        a = c;
      }
      v[i] = a
      v[i + 1] = b
    }
    return v
  }

  static decodeRTEA(v, k) {
    for (let i = 0; i < v.length; i += 2) {
      let a = v[i], b = v[i + 1];
      for (let r = k.length * 4 + 31; r >= 0; r--) {
        a &= 0xFFFFFFFF;//overflow prevention
        const c = a;
        a = b -= a + ((a << 6) ^ (a >> 8)) + k[r % k.length] + r;
        b = c;
      }
      v[i] = a
      v[i + 1] = b
    }
    return v
  }

  static encodeRaiden(v, k) {
    const key = [k[0], k[1], k[2], k[3]]
    for (let i = 0; i < v.length; i += 2) {
      let b0 = v[i], b1 = v[i + 1]
      for (let j = 0; j < 16; j++) {
        const sk = key[j % 4] = ((key[0] + key[1]) + ((key[2] + key[3]) ^ (key[0] << (key[2] & 0x1F))));
        b0 += ((sk + b1) << 9) ^ ((sk - b1) ^ ((sk + b1) >> 14));
        b1 += ((sk + b0) << 9) ^ ((sk - b0) ^ ((sk + b0) >> 14));
      }
      v[i] = b0;
      v[i + 1] = b1;
    }
    return v
  }

  static decodeRaiden(v, k) {
    let subkeys = Array(16);
    for (let i = 0; i < 16; i++) subkeys[i] = k[i % 4] = ((k[0] + k[1]) + ((k[2] + k[3]) ^ (k[0] << (k[2] & 0x1F))));
    for (let i = 0; i < v.length; i += 2) {
      let b0 = v[i], b1 = v[i + 1]
      for (let j = 15; j >= 0; j--) {
        b1 -= ((subkeys[j] + b0) << 9) ^ ((subkeys[j] - b0) ^ ((subkeys[j] + b0) >> 14));
        b0 -= ((subkeys[j] + b1) << 9) ^ ((subkeys[j] - b1) ^ ((subkeys[j] + b1) >> 14));
      }
      v[i] = b0;
      v[i + 1] = b1;
    }
    return v
  }

  static encryptSPECK(v, k) {
    let x = v[0], y = v[1];
    for (let i = 0; i < 22; i++) {
      x = (x << 9 | x >>> 7) + y & 65535 ^ k[i];
      y = (y << 2 | y >>> 14) & 65535 ^ x;
    }
    v[0] = x, v[1] = y;
    return v;
  }
  /**
   * Converts string to array of uint32 (each containing 4 chars).
   * @private
   */
  static strToUint32(s) {
    // note chars must be within ISO-8859-1 (Unicode code-point <= U+00FF) to fit 4/long
    const l = new Uint32Array(Math.ceil(s.length / 4));
    for (let i = 0; i < l.length; i++) {
      // note little-endian encoding - endianness is irrelevant as long as it matches uint32ToStr()
      l[i] = s.charCodeAt(i * 4) + (s.charCodeAt(i * 4 + 1) << 8) +
        (s.charCodeAt(i * 4 + 2) << 16) + (s.charCodeAt(i * 4 + 3) << 24);
    } // note running off the end of the string generates nulls since bitwise operators treat NaN as 0
    return l;
  }

  /**
 * Converts string to array of uint64 (each containing 8 chars).
 * @private
 */
  static strToUint64(s) {
    // note chars must be within ISO-8859-1 (Unicode code-point <= U+00FF) to fit 2/long
    const l = new BigUint64Array(Math.ceil(s.length / 8));
    const u8 = new Uint8Array(8)
    for (let i = 0; i < l.length; i++) {
      // note little-endian encoding - endianness is irrelevant as long as it matches uint32ToStr()
      u8[0] = s.charCodeAt(i * 8).toString(16);
      u8[1] = s.charCodeAt(i * 8 + 1).toString(16);
      u8[2] = s.charCodeAt(i * 8 + 2).toString(16);
      u8[3] = s.charCodeAt(i * 8 + 3).toString(16);
      u8[4] = s.charCodeAt(i * 8 + 4).toString(16);
      u8[5] = s.charCodeAt(i * 8 + 5).toString(16);
      u8[6] = s.charCodeAt(i * 8 + 6).toString(16);
      u8[7] = s.charCodeAt(i * 8 + 7).toString(16);
      l[i] = BigInt('0x' + u8.join(""));
    } // note running off the end of the string generates nulls since bitwise operators treat NaN as 0
    return l;
  }

  /**
   * Converts array of longs to string.
   * @private
   */
  static uint32ToStr(l) {
    let str = '';
    for (let i = 0; i < l.length; i++) str += String.fromCharCode(l[i] & 0xff, l[i] >>> 8 & 0xff, l[i] >>> 16 & 0xff, l[i] >>> 24 & 0xff);
    return str;
  }

  static uint64ToStr(l) {
    let str = '';
    for (let i = 0; i < l.length; i++) {
      const hex = l[i].toString(16);
      if (hex.length % 2) hex = '0' + hex;
      const len = hex.length / 2
      for (let j = 0; j < len; j++)str += String.fromCharCode(parseInt(hex.slice(2 * j, 2 * j + 2, 16), 16))
    }
    return str;
  }
  /**
   * Encodes multi-byte string to utf8 - monsur.hossa.in/2012/07/20/utf-8-in-javascript.html
   */
  static utf8Encode(str) {
    return decodeURIComponent(encodeURIComponent(str));
  }

  /**
   * Decodes utf8 string to multi-byte
   */
  static utf8Decode(utf8Str) {
    try {
      return decodeURIComponent(encodeURIComponent(utf8Str));
    } catch (e) {
      return utf8Str; // invalid UTF-8? return as-is
    }
  }


  /**
   * Encodes base64 - developer.mozilla.org/en-US/docs/Web/API/window.btoa, nodejs.org/api/buffer.html
   */
  static base64Encode(str) {
    if (typeof btoa != 'undefined') return btoa(str); // browser
    if (typeof Buffer != 'undefined') return new Buffer(str, 'binary').toString('base64'); // Node.js
    throw new Error('No Base64 Encode');
  }

  /**
   * Decodes base64
   */
  static base64Decode(b64Str) {
    if (typeof atob == 'undefined' && typeof Buffer == 'undefined') throw new Error('No base64 decode');
    try {
      if (typeof atob != 'undefined') return atob(b64Str); // browser
      if (typeof Buffer != 'undefined') return new Buffer(b64Str, 'base64').toString('binary'); // Node.js
    } catch (e) {
      throw new Error('Invalid ciphertext');
    }
  }

}

export default Tea;
