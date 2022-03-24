// Constants
const bufferToBase64 = (buffer) => {
    let bytes = new Uint8Array(buffer);
    let binary = "";
    let len = bytes.byteLength;
    for (let i = 0; i < len; i++)
        binary += String.fromCharCode(bytes[i]);
    return window.btoa(binary);
}
const base64ToBuffer = (base64) => {
    let binary_string = window.atob(base64);
    let len = binary_string.length;
    let bytes = new Uint8Array(len);
    for (var i = 0; i < len; i++)
        bytes[i] = binary_string.charCodeAt(i);
    return bytes.buffer;
}
const uid = () => {
    let a = new Uint32Array(3);
    window.crypto.getRandomValues(a);
    return (performance.now().toString(36) + Array.from(a).map(A => A.toString(36)).join("")).replace(/\./g, "");
}
// https://gist.github.com/ShirtlessKirk/2134376
const _LUHN_CHK = (function (arr) {
    return function (ccNum) {
        let len = ccNum.length, bit = 1, sum = 0, val;
        while (len) {
            val = parseInt(ccNum.charAt(--len), 10);
            sum += (bit ^= 1) ? arr[val] : val;
        }
        return sum && sum % 10 === 0;
    };
}([0, 2, 4, 6, 8, 1, 3, 5, 7, 9]));
const CryptoAPI = window.crypto;
const _CARD_DEFAULT_FORMAT = /(\d{1,4})/g;
// DaietsuPay
const DaietsuPay = {
    _DAIETSU_SERVER_ENDPOINT: "https://api.daietsu.app",
    _SANBDOX_DAIETSU_SERVER_ENDPOINT: "https://sandbox-api.daietsu.app",
    _ALG: { name: "RSA-OAEP", hash: { name: "SHA-256" }, label: new TextEncoder().encode("daietsu-pay") },
    _CARD_DEFAULT_FORMAT,
    _CARDS_REGISTRY: [
        {
            type: 'visaelectron',
            pattern: /^4(026|17500|405|508|844|91[37])/,
            format: _CARD_DEFAULT_FORMAT,
            length: [16],
            cvcLength: [3],
            luhn: true
        },
        {
            type: 'maestro',
            pattern: /^(5(018|0[23]|[68])|6(39|7))/,
            format: _CARD_DEFAULT_FORMAT,
            length: [12, 13, 14, 15, 16, 17, 18, 19],
            cvcLength: [3],
            luhn: true
        },
        {
            type: 'forbrugsforeningen',
            pattern: /^600/,
            format: _CARD_DEFAULT_FORMAT,
            length: [16],
            cvcLength: [3],
            luhn: true
        },
        {
            type: 'dankort',
            pattern: /^5019/,
            format: _CARD_DEFAULT_FORMAT,
            length: [16],
            cvcLength: [3],
            luhn: true
        },
        {
            type: 'visa',
            pattern: /^4/,
            format: _CARD_DEFAULT_FORMAT,
            length: [13, 16],
            cvcLength: [3],
            luhn: true
        },
        {
            type: 'mastercard',
            pattern: /^(5[1-5]|2[2-7])/,
            format: _CARD_DEFAULT_FORMAT,
            length: [16],
            cvcLength: [3],
            luhn: true
        },
        {
            type: 'amex',
            pattern: /^3[47]/,
            format: /(\d{1,4})(\d{1,6})?(\d{1,5})?/,
            length: [15],
            cvcLength: [3, 4],
            luhn: true
        },
        {
            type: 'dinersclub',
            pattern: /^3[0689]/,
            format: /(\d{1,4})(\d{1,6})?(\d{1,4})?/,
            length: [14],
            cvcLength: [3],
            luhn: true
        },
        {
            type: 'discover',
            pattern: /^6([045]|22)/,
            format: _CARD_DEFAULT_FORMAT,
            length: [16],
            cvcLength: [3],
            luhn: true
        }, 
        {
            type: 'unionpay',
            pattern: /^(62|88)/,
            format: _CARD_DEFAULT_FORMAT,
            length: [16, 17, 18, 19],
            cvcLength: [3],
            luhn: false
        }, 
        {
            type: 'jcb',
            pattern: /^35/,
            format: _CARD_DEFAULT_FORMAT,
            length: [16],
            cvcLength: [3],
            luhn: true
        }
    ],
    _$get(url) {
        return new Promise((resolve, reject) => {
            fetch(url).then(res => res.json()).then(resolve).catch(reject);
        });
    },
    _$post (url, data) {
        return new Promise((resolve, reject) => {
            fetch(url, {
                method: 'POST',
                mode: 'cors',
                cache: 'no-cache',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json'
                },
                redirect: 'error',
                body: JSON.stringify(data)
            }).then(res => res.json()).then(resolve).catch(reject);
        });
    },
    async _enc(data, key) {
        let enc = new TextEncoder();
        let cry = await CryptoAPI.subtle.encrypt(this._ALG, key, enc.encode(data));
        return bufferToBase64(cry);
    },
    async get_public_keys() {
        return new Promise(async (resolve, reject) => {
            try {
                const keys = (await this._$get(this._DAIETSU_SERVER_ENDPOINT + "/v1/paycli/public_keys")).keys;
                let imported_keys = {};
                for (let i in keys) {
                    let key_buf = base64ToBuffer(keys[i]);
                    imported_keys[i] = await CryptoAPI.subtle.importKey("spki", key_buf, this._ALG, true, ["encrypt"]);
                }
                return resolve(imported_keys);
            } catch (e) {
                return reject();
            }
        });
    },
    _card: {
        validate_luhn (value) {
            return _LUHN_CHK(value);
        },
        get_card_type_from_number (num) {
            if(!num) return null;
            num = num.replace(/\D/g, '');
            for(let card of DaietsuPay._CARDS_REGISTRY) {
                if(card.pattern.test(num)) return card;
            }
            return null;
        },
        get_card_type_by_id (type) {
            let card = DaietsuPay._CARDS_REGISTRY.filter(x => x.type == type);
            return (card.length==1?card[0]:null);
        },
        format_expiry (val) {
            let parts = val.match(/^\D*(\d{1,2})(\D+)?(\d{1,4})?/);
            if(!parts) return '';
            let mon = parts[1] || '', sep = parts[2] || '', year = parts[3] || '';
            if(year.length > 0) sep = ' / ';
            else if(sep === ' /') {mon=mon.substring(0,1);sep='';}
            else if(mon.length === 2 || sep.length > 0) sep = ' / ';
            else if(mon.length === 1 && (mon !== '0' && mon !== '1')) {mon='0'+mon;sep=' / ';}
            return mon+sep+year;
        },
        format_card_number (num) {
            num = num.replace(/\D/g, '');
            let card = DaietsuPay._card.get_card_type_from_number(num);
            if(!card) return num;
            let upperLen = card.length[card.length.length - 1];
            num = num.slice(0, upperLen);
            if(card.format.global) {
                let _ref = num.match(card.format);
                return (_ref ? _ref.join(' ') : null);
            } else {
                let groups = card.format.exec(num);
                if(!groups) return;
                groups.shift();
                groups = groups.filter(x => x);
                return groups.join(' ');
            }
        },
        parse_expiry_val (val) {
            let _ref = val.split(/[\s\/]+/, 2), month = _ref[0] || '', year = _ref[1] || '';
            if(year && year.length === 2 && /^\d+$/.test(year)) 
                year = (new Date).getFullYear().toString().slice(0, 2) + year;
            month = parseInt(month, 10);
            year = parseInt(year, 10);
            return {month, year};
        },
        validate_card_no (val) {
            val = (val + '').replace(/\s+|-/g, '');
            if (!/^\d+$/.test(val)) return false;
            let card = this.get_card_type_from_number(val);
            if (!card) return false;
            return (card.length.includes(val.length)) && (card.luhn === false || this.validate_luhn(val));
        },
        validate_card_expiry (month, year) {
            if(!(month && year)) return false;
            month = "" + month;
            year = "" + year;
            month = month.trim();
            year = year.trim();
            if (!/^\d+$/.test(month) || !/^\d+$/.test(year)) return false;
            if (!((1 <= month && month <= 12))) return false;
            if(year.length == 2) year = (year < 70 ? "20" : "19") + year;
            if(year.length !== 4) return false;
            let expiry = new Date(year, month);
            let currentTime = new Date();
            expiry.setMonth(expiry.getMonth() + 1, 1);
            return expiry > currentTime;
        },
        validate_card_cvc (cvc, type) {
            cvc = cvc.trim();
            if (!/^\d+$/.test(cvc)) return false;
            let card = this.get_card_type_by_id(type);
            return (card ?  card.cvcLength.includes(cvc.length): (cvc.length >= 3 && cvc.length <= 4));
        }
    },
    async execute_payment (payment_id, payment_token, card_number, expiry_month, expiry_year, cvc) {
        return new Promise(async (resolve) => {
            // validate
            let e = [];
            // TODO: better card validation
            if(!this._card.validate_card_no(card_number)) e.push("INVALID_CARD_NUMBER");
            if(!this._card.validate_card_expiry(expiry_month, expiry_year)) e.push("INVALID_EXPIRATION_DATE");
            let card_type = this._card.get_card_type_from_number(card_number);
            if(!this._card.validate_card_cvc(cvc, (card_type ? card_type.type : null))) e.push("INVALID_CARD_CVC");
            if(e.length>0) return resolve(e);
            // public keys
            let public_keys;
            try {
                public_keys = await this.get_public_keys();
            } catch (e) {
                return resolve("UNABLE_TO_GET_PUBLIC_KEYS");
            }
            // decode token
            let decoded_token;
            try {
                decoded_token = JSON.parse(window.atob(payment_token.split(".")[1]));
            } catch (e) {
                return resolve("INVALID_PAYMENT_TOKEN_PROVIDED");
            }
            if (decoded_token.sub != payment_id) return resolve("INVALID_PAYMENT_TOKEN_PROVIDED"); 
            // crypt
            card_number = card_number.replace(/ /g, "");
            let encrypted_details = await DaietsuPay._enc(JSON.stringify({card_number, expiry_month, expiry_year, cvc}), public_keys[decoded_token.rsa_key]);
            delete card_number, delete expiry_month, delete expiry_year, delete cvc;
            // execute payment
            let payment_data;
            try {
                payment_data = await this._$post((decoded_token.is_sandbox ? this._SANBDOX_DAIETSU_SERVER_ENDPOINT : this._DAIETSU_SERVER_ENDPOINT) + "/v1/paycli/" + payment_id, {payment_token, encrypted_details});
            } catch (e) {
                return resolve("UNABLE_TO_EXECUTE_PAYMENT");
            }
            // resolve
            return resolve(payment_data);
        });
    }
}
if(module !== undefined) module.exports = DaietsuPay;