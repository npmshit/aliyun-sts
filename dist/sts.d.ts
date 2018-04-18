/// <reference types="node" />
import https from "https";
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
export declare const ENDPOINT = "https://sts.aliyuncs.com";
export declare const FORMAT = "JSON";
export declare const API_VERSION = "2015-04-01";
export declare const SIG_METHOD = "HMAC-SHA1";
export declare const SIG_VERSION = "1.0";
export declare const TIMEOUT = 60000;
export interface Policy {
    Statement: Array<{
        Effect?: string;
        Action?: string[];
        Resource?: string[];
        Condition?: Record<string, any>;
    }>;
    Version: string;
}
export interface AssumeRoleResult {
    AccessKeySecret: string;
    AccessKeyId: string;
    Expiration: string;
    SecurityToken: string;
}
export declare class STS {
    private options;
    private agent;
    private endpoint;
    constructor(options: STSOptions);
    assumeRole(role: string, policy: Policy, expiration: number, session: string, options?: AssumeRoleOptions): Promise<AssumeRoleResult>;
    private request(options, body, json?);
    private getSignature(method, params, key);
    /**
     * Since `encodeURIComponent` doesn't encode '*', which causes
     * 'SignatureDoesNotMatch'. We need do it ourselves.
     */
    private escape(str);
}
export default STS;
