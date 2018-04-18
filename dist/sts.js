"use strict";
/**
 * 阿里云STS
 * 本代码参考自 https://github.com/ali-sdk/ali-oss/blob/master/lib/sts.js
 *
 * @author Zongmin Lei <leizongmin@gmail.com>
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const url_1 = __importDefault(require("url"));
const https_1 = __importDefault(require("https"));
const assert_1 = __importDefault(require("assert"));
const crypto_1 = __importDefault(require("crypto"));
const querystring_1 = __importDefault(require("querystring"));
exports.ENDPOINT = "https://sts.aliyuncs.com";
exports.FORMAT = "JSON";
exports.API_VERSION = "2015-04-01";
exports.SIG_METHOD = "HMAC-SHA1";
exports.SIG_VERSION = "1.0";
exports.TIMEOUT = 60000;
class STS {
    constructor(options) {
        assert_1.default(options.accessKeyId, "missing required `accessKeyId`");
        assert_1.default(options.accessKeySecret, "missing required `accessKeySecret`");
        this.options = {
            accessKeyId: options.accessKeyId,
            accessKeySecret: options.accessKeySecret,
            endpoint: options.endpoint || exports.ENDPOINT,
            format: exports.FORMAT,
            apiVersion: exports.API_VERSION,
            sigMethod: exports.SIG_METHOD,
            sigVersion: exports.SIG_VERSION,
            timeout: exports.TIMEOUT,
        };
        this.agent = options.agent;
        this.endpoint = url_1.default.parse(this.options.endpoint, false);
    }
    async assumeRole(role, policy, expiration, session, options = {}) {
        const params = {
            Action: "AssumeRole",
            RoleArn: role,
            RoleSessionName: session || "app",
            DurationSeconds: expiration || 3600,
            Format: this.options.format,
            Version: this.options.apiVersion,
            AccessKeyId: this.options.accessKeyId,
            SignatureMethod: this.options.sigMethod,
            SignatureVersion: this.options.sigVersion,
            SignatureNonce: Math.random().toString(),
            Timestamp: new Date().toISOString(),
        };
        if (policy) {
            let policyStr;
            if (typeof policy === "string") {
                try {
                    policyStr = JSON.stringify(JSON.parse(policy));
                }
                catch (err) {
                    throw new Error(`Policy string is not a valid JSON: ${err.message}`);
                }
            }
            else {
                policyStr = JSON.stringify(policy);
            }
            params.Policy = policyStr;
        }
        const signature = this.getSignature("POST", params, this.options.accessKeySecret);
        params.Signature = signature;
        const reqParams = {
            agent: this.agent,
            method: "POST",
            host: this.endpoint.host,
            port: this.endpoint.port,
            protocol: this.endpoint.protocol,
            path: this.endpoint.path,
            timeout: options.timeout || this.options.timeout,
            headers: {
                "Content-Type": "application/x-www-form-urlencoded",
            },
        };
        const res = await this.request(reqParams, querystring_1.default.stringify(params));
        if (!(res.statusCode && res.statusCode >= 200 && res.statusCode <= 299)) {
            const err = new Error();
            err.code = res.body.Code;
            err.message = `${res.body.Code}: ${res.body.Message}`;
            err.requestId = res.body.RequestId;
            err.params = reqParams;
            throw err;
        }
        return res.body.Credentials;
    }
    request(options, body, json = true) {
        return new Promise((resolve, reject) => {
            const req = https_1.default.request(options, res => {
                res.on("error", err => reject(err));
                const list = [];
                res.on("data", chunk => list.push(chunk));
                res.on("end", () => {
                    const res2 = res;
                    res2.body = Buffer.concat(list);
                    if (json) {
                        res2.body = JSON.parse(res2.body.toString());
                    }
                    resolve(res2);
                });
            });
            req.on("error", err => reject(err));
            req.end(body);
        });
    }
    getSignature(method, params, key) {
        const canoQuery = Object.keys(params)
            .sort()
            .map(k => `${this.escape(k)}=${this.escape(params[k])}`)
            .join("&");
        const stringToSign = `${method.toUpperCase()}&${this.escape("/")}&${this.escape(canoQuery)}`;
        const signature = crypto_1.default
            .createHmac("sha1", `${key}&`)
            .update(stringToSign)
            .digest("base64");
        return signature;
    }
    /**
     * Since `encodeURIComponent` doesn't encode '*', which causes
     * 'SignatureDoesNotMatch'. We need do it ourselves.
     */
    escape(str) {
        return encodeURIComponent(str).replace(/\*/g, "%2A");
    }
}
exports.STS = STS;
exports.default = STS;
//# sourceMappingURL=sts.js.map