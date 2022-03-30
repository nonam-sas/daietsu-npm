// Imports
import fetch from "node-fetch";
import crypto from "crypto";
// Hosts
const SANDBOX_API_HOST = "https://sandbox-api.daietsu.app/v1";
const API_HOST = "https://api.daietsu.app/v1";
/** DaietsuAPI Server library */
class DaietsuAPI {
    // Constructor
    _sandbox;
    _client_id;
    _client_secret;

    // Type defs
    /**
     * @typedef CorporationMember
     * @property {(string|User|undefined)} user Member's related user
     * @property {number} added_at Member's join timestamp 
     * @property {(string|User|undefined)} added_by Member's invite issued by
     * 
     */

    /**
     * @typedef Corporation
     * @property {string} _id Corporation ID
     * @property {string} name Corporation name
     * @property {(string|User|undefined)} owner Corporation's owner
     * @property {(CorporationMember[]|undefined)} members Corporation's members
     * @property {number} created_at Corporation creation timestamp
     * @property {(string|User|undefined)} created_by Corporation's creation user
     * @property {number} edited_at Corporation last edition timestamp
     */

    /**
     * @typedef Organisation
     * @property {string} _id Organisation ID
     * @property {string} name Organisation name
     * @property {(string|Corporation)} organisation Organisation's corporation
     * @property {number} created_at Organisation creation timestamp
     * @property {(string|User|undefined)} created_by Organisation's creation user
     * @property {number} edited_at Organisation last edition timestamp
     */

    /**
     * @typedef ProviderAccount
     * @property {string} provider Provider code
     * @property {number} rate Rate for this provider
     * @property {number} added_at Provider addition timestamp
     * @property {(string|User|undefined)} added_by Provider added by User
     */

    /**
     * @typedef PaymentDetails
     * @property {boolean} active Payments enabled?
     * @property {(ProviderAccount[]|undefined)} provider_accounts Provider accounts
     * @property {string} return_url Default return URL
     */

    /**
     * @typedef Establishment
     * @property {string} _id Establishment ID
     * @property {string} name Establishment name
     * @property {(PaymentDetails|undefined)} payment_details Establishment's payment details
     * @property {(string|Organisation)} organisation Establishment's organisation
     * @property {number} created_at Establishment creation timestamp
     * @property {(string|User|undefined)} created_by Establishment's creation user
     * @property {number} edited_at Establishemnt last edition timestamp
     */

    /**
     * Creates instance of DaietsuAPI
     * @param {string} client_id Client ID
     * @param {string} client_secret Client secret
     * @param {boolean} sandbox Use sandbox API?
     */
    constructor (client_id, client_secret, sandbox = false) {
        this._sandbox = sandbox;
        this._client_id = client_id;
        this._client_secret = client_secret;
    }

    // _app_post
    _app_post (endpoint, body = null, token = null) {
        return new Promise((resolve, reject) => {
            fetch((this._sandbox ? SANDBOX_API_HOST : API_HOST) + endpoint, {method: "POST", headers: {"Content-Type": "application/json", "X-API-Authentication": this._client_id + ":" + this._client_secret, ...(token ? {Authorization: "Bearer " + token} : {})}, ...(body ? {body: JSON.stringify(body)} : {})})
                .then(r => r.json())
                .then(d => {
                    if(d.error || d.errors) return reject((d.errors ? d.errors : [d.error]));
                    return resolve(d.result);
                })
                .catch(e => {
                    reject(["REQUEST_ISSUE"]);
                });
        });
    }

    // _app_get
    _app_get (endpoint, token = null) {
        return new Promise((resolve, reject) => {
            fetch((this._sandbox ? SANDBOX_API_HOST : API_HOST) + endpoint, {method: "POST", headers: {"X-API-Authentication": this._client_id + ":" + this._client_secret, ...(token ? {Authorization: "Bearer " + token} : {})}})
                .then(r => r.json())
                .then(d => {
                    if(d.error || d.errors) return reject((d.errors ? d.errors : [d.error]));
                    return resolve(d.result);
                })
                .catch(e => {
                    reject(["REQUEST_ISSUE"]);
                });
        });
    }

    /**
     * Create authorization URL
     * @param {string} redirect_uri Redirect URI to send back user to after prompt
     * @param {(string|string[])} scopes Scopes to request access to
     * @returns {string} manage.daietsu.app authorization URL
     */
    create_authorization_url (redirect_uri = null, scopes = []) {
        let errors = [];
        if(!redirect_uri) errors.push("MISSING_REDIRECT_URI");
        scopes = (typeof scopes == "string" ? scopes.split(",") : scopes);
        if(!Array.isArray(scopes)) errors.push("INVALID_SCOPES_FORMAT");
        if(errors.length>0) return reject(errors);
        return `https://manage.daietsu.app/authorize?a=${this._client_id}&m=establishment&s=${scopes.join(",")}&r=${encodeURIComponent(redirect_uri)}`;
    }

    /**
     * Exchange authorization code for a token
     * @param {string} authorization_code
     * @param {(string|string[])} scopes 
     * @returns {Promise<String>} JWT token linking to authorized access
     */
    exchange_authorization_code (authorization_code = null, scopes = []) {
        return new Promise(async (resolve, reject) => {
            let errors = [];
            if(!authorization_code) errors.push("MISSING_AUTHORIZATION_CODE");
            scopes = (typeof scopes == "string" ? scopes.split(",") : scopes);
            if(!Array.isArray(scopes)) errors.push("INVALID_SCOPES_FORMAT");
            if(errors.length>0) return reject(errors);
            let token;
            try {
                token = await this._app_post("/auth/exchange", {code: authorization_code, scopes: scopes.join(",")});
            } catch (e) {
                return reject(e);
            }
            return resolve(token);
        });
    }

    /**
     * Get authorized establishment
     * @param {string} token JWT token related to establishment access
     * @returns {Promise<Establishment>} Establishment connected to token
     */
    get_authorized_establishment (token = null) {
        return new Promise(async (resolve, reject) => {
            if(!token) return reject(["MISSING_TOKEN"]);
            let establishment;
            try {
                establishment = await this._app_get("/establishments/@current");
            } catch (e) {
                return reject(e);
            }
            return resolve(establishment);
        });
    }

    /**
     * @typedef TransactionInfos
     * @property {string} payment_id Payment ID
     * @property {(string|null)} payment_token Payment token (for client SDK)
     */

    /**
     * Create payment
     * @param {string} token Establishment token
     * @param {number} amount Amount to pay
     * @param {string} currency Payment currency
     * @param {string} description Payment description
     * @param {string} [meta] Payment meta 
     * @param {string} [return_url] Specific transaction return URL 
     * @param {string} [webhook] Specific transaction Webhook ID
     * @returns {Promise<TransactionInfos>} Transaction infos
     */
    create_payment (token = null, amount = null, currency = null, description = null, meta = null, return_url = null, webhook = null) {
        return new Promise(async (resolve, reject) => {
            let errors = [];
            if(!token) errors.push("MISSING_TOKEN");
            amount = Number.parseFloat(amount);
            if(!amount || Number.isNaN(amount)) errors.push("MISSING_AMOUNT");
            else if(amount < 0.5) errors.push("MINIMUM_AMOUNT_ISSUE");
            if(!currency) errors.push("MISSING_CURRENCY");
            if(!description) errors.push("MISSING_DESCRIPTION");
            if(errors.length>0) return reject(errors);
            let data = {amount, currency, description};
            if(meta) data.meta = meta;
            if(webhook) data.webhook = webhook;
            if(return_url) data.return_url;
            let transaction_infos;
            try {
                transaction_infos = await this._app_post("/payments", data, token);
            } catch (e) {
                return reject(e);
            }
            return resolve(transaction_infos);
        });
    }

    /**
     * @typedef PaymentStatus
     * @property {string} value Payment status code
     * @property {(object|null|undefined)} details Payment status details
     * @property {number} at Payment status adopted timestamp
     */

    /**
     * @typedef Payment
     * @property {string} _id Payment ID
     * @property {PaymentStatus[]} status_history Status history
     * @property {number} amount Payment amount
     * @property {string} description Payment description
     * @property {number} billed_fees Billed fees amount
     * @property {(string|Currency)} currency Payment currency
     * @property {boolean} is_sandbox Is sandbox payment?
     * @property {string} encryption_key Key ID used to sign instrument
     * @property {string} meta Payment meta
     * @property {(string|null)} provider Provider in charge of payment
     * @property {(object|null|undefined)} provider_details Provider related data
     * @property {(string|null)} return_url Payment-specific return URL
     * @property {number} created_at Payment creation timestamp
     * @property {(string|User|null)} created_by Payment creating user
     * @property {(string|App|null)} created_via Payment creating app
     */

    /**
     * Get payment
     * @param {string} token Establishment token
     * @param {string} payment_id ID of payment to retrieve
     * @returns {Promise<Payment>} Payment data
     */
    get_payment (token = null, payment_id = null) {
        return new Promise(async (resolve, reject) => {
            let errors = [];
            if(!token) errors.push("INVALID_TOKEN");
            if(!payment_id) errors.push("INVALID_PAYMENT_ID");
            if(errors.length>0) return reject(errors);
            let payment;
            try {
                payment = await this._app_get("/payments/" + payment_id, token);
            } catch (e) {
                return reject(e);
            }
            return resolve(payment);
        });
    }

    /**
     * Validate webhook content
     * @param {string} header X-Daietsu-Webhook header content
     * @param {Object} content Received JSON content
     * @param {string} webhook_secret Webhook secret
     * @returns {boolean} Valid?
     */
    validate_webhook_content (header, content, webhook_secret) {
        let hashed_content = crypto.createHash("sha512").update(webhook_secret + ":" + (typeof content == "string" ? content : JSON.stringify(content))).digest("base64");
        return (header == hashed_content);
    }
}
export default DaietsuAPI;