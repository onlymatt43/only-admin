const crypto = require('crypto');

function base32ToBuffer(base32) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = '';
    for (let i = 0; i < base32.length; i++) {
        const val = alphabet.indexOf(base32[i].toUpperCase());
        if (val === -1) continue;
        bits += val.toString(2).padStart(5, '0');
    }
    const bytes = [];
    for (let i = 0; i + 8 <= bits.length; i += 8) {
        bytes.push(parseInt(bits.substring(i, i + 8), 2));
    }
    return Buffer.from(bytes);
}

function getTOTP(secret) {
    const key = base32ToBuffer(secret);
    const epoch = Math.floor(Date.now() / 1000);
    const time = Buffer.alloc(8);
    let t = Math.floor(epoch / 30);
    for (let i = 7; i >= 0; i--) {
        time[i] = t & 0xff;
        t >>= 8;
    }

    const hmac = crypto.createHmac('sha1', key).update(time).digest();
    const offset = hmac[hmac.length - 1] & 0xf;
    const binary = ((hmac[offset] & 0x7f) << 24) |
                   ((hmac[offset + 1] & 0xff) << 16) |
                   ((hmac[offset + 2] & 0xff) << 8) |
                   (hmac[offset + 3] & 0xff);
    
    return (binary % 1000000).toString().padStart(6, '0');
}

console.log(getTOTP('SH5U7RVQFL77GBJUTPDMA32DGEP7TX23'));
