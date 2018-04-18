/**
 * 阿里云OSS签名
 * 本代码参考自 https://github.com/ali-sdk/ali-oss/blob/master/lib/sts.js
 *
 * @author Zongmin Lei <leizongmin@gmail.com>
 */

import url from "url";
import http from "http";
import https from "https";
import assert from "assert";
import crypto from "crypto";
import querystring from "querystring";

export interface STSOptions {
  accessKeyId: string;
  accessKeySecret: string;
  /** 默认 https://sts.aliyuncs.com */
  endpoint?: string;
  agent?: https.Agent | boolean;
}

export interface AssumeRoleOptions {
  /** 毫秒 */
  timeout?: number;
}

export const ENDPOINT = "https://sts.aliyuncs.com";
export const FORMAT = "JSON";
export const API_VERSION = "2015-04-01";
export const SIG_METHOD = "HMAC-SHA1";
export const SIG_VERSION = "1.0";
export const TIMEOUT = 60000;

interface Params {
  Action: string;
  RoleArn: string;
  RoleSessionName: string;
  DurationSeconds: number;
  Format: string;
  Version: string;
  AccessKeyId: string;
  SignatureMethod: string;
  SignatureVersion: string;
  SignatureNonce: string;
  Timestamp: string;
  [k: string]: any;
}

interface HttpResponse extends http.IncomingMessage {
  body: any;
}

export interface Policy {
  Statement: Array<{
    Effect: string;
    Action: string[];
    Resource: string[];
  }>;
  Version: string;
}

export interface AssumeRoleResult {
  AccessKeySecret: string;
  AccessKeyId: string;
  Expiration: string;
  SecurityToken: string;
}

export class STS {
  private options: {
    accessKeyId: string;
    accessKeySecret: string;
    endpoint: string;
    format: string;
    apiVersion: string;
    sigMethod: string;
    sigVersion: string;
    timeout: number;
  };
  private agent: https.Agent | boolean | undefined;
  private endpoint: url.Url;

  constructor(options: STSOptions) {
    assert(options.accessKeyId, "missing required `accessKeyId`");
    assert(options.accessKeySecret, "missing required `accessKeySecret`");
    this.options = {
      accessKeyId: options.accessKeyId,
      accessKeySecret: options.accessKeySecret,
      endpoint: options.endpoint || ENDPOINT,
      format: FORMAT,
      apiVersion: API_VERSION,
      sigMethod: SIG_METHOD,
      sigVersion: SIG_VERSION,
      timeout: TIMEOUT,
    };
    this.agent = options.agent;
    this.endpoint = url.parse(this.options.endpoint, false);
  }

  public async assumeRole(
    role: string,
    policy: Policy,
    expiration: number,
    session: string,
    options: AssumeRoleOptions = {},
  ): Promise<AssumeRoleResult> {
    const params: Params = {
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
      let policyStr: string;
      if (typeof policy === "string") {
        try {
          policyStr = JSON.stringify(JSON.parse(policy));
        } catch (err) {
          throw new Error(`Policy string is not a valid JSON: ${err.message}`);
        }
      } else {
        policyStr = JSON.stringify(policy);
      }
      params.Policy = policyStr;
    }

    const signature = this.getSignature("POST", params, this.options.accessKeySecret);
    params.Signature = signature;

    const reqParams: https.RequestOptions = {
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
    const res = await this.request(reqParams, querystring.stringify(params));

    if (!(res.statusCode && res.statusCode >= 200 && res.statusCode <= 299)) {
      const err = new Error() as any;
      err.code = res.body.Code;
      err.message = `${res.body.Code}: ${res.body.Message}`;
      err.requestId = res.body.RequestId;
      err.params = reqParams;
      throw err;
    }

    return res.body.Credentials;
  }

  private request(options: https.RequestOptions, body: string, json: boolean = true) {
    return new Promise<HttpResponse>((resolve, reject) => {
      const req = https.request(options, res => {
        res.on("error", err => reject(err));
        const list: Buffer[] = [];
        res.on("data", chunk => list.push(chunk as Buffer));
        res.on("end", () => {
          const res2 = res as HttpResponse;
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

  private getSignature(method: string, params: Params, key: string) {
    const canoQuery = Object.keys(params)
      .sort()
      .map(k => `${this.escape(k)}=${this.escape(params[k])}`)
      .join("&");
    const stringToSign = `${method.toUpperCase()}&${this.escape("/")}&${this.escape(canoQuery)}`;
    const signature = crypto
      .createHmac("sha1", `${key}&`)
      .update(stringToSign)
      .digest("base64");
    return signature;
  }

  /**
   * Since `encodeURIComponent` doesn't encode '*', which causes
   * 'SignatureDoesNotMatch'. We need do it ourselves.
   */
  private escape(str: string) {
    return encodeURIComponent(str).replace(/\*/g, "%2A");
  }
}
