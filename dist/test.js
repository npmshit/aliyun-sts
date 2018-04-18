"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const sts_1 = require("./sts");
const chai_1 = require("chai");
const OSS = require("ali-oss").Wrapper;
const ENV_ACCESS_KEY_ID = process.env.ACCESS_KEY_ID;
const ENV_ACCESS_KEY_SECRET = process.env.ACCESS_KEY_SECRET;
const ENV_REGION = process.env.REGION;
const ENV_BUCKET = process.env.BUCKET;
const ENV_ACS_RAM = process.env.ACS_RAM;
describe("STS", function () {
    before(function () {
        chai_1.expect(typeof ENV_ACCESS_KEY_ID).to.equal("string");
        chai_1.expect(typeof ENV_ACCESS_KEY_SECRET).to.be.equal("string");
        chai_1.expect(typeof ENV_REGION).to.be.equal("string");
        chai_1.expect(typeof ENV_BUCKET).to.be.equal("string");
        chai_1.expect(typeof ENV_ACS_RAM).to.be.equal("string");
    });
    it("生成签名并上传文件成功", async function () {
        const sts = new sts_1.STS({
            accessKeyId: ENV_ACCESS_KEY_ID,
            accessKeySecret: ENV_ACCESS_KEY_SECRET,
        });
        const policy = {
            Statement: [
                {
                    Effect: "Allow",
                    Action: ["oss:GetObject", "oss:PutObject"],
                    Resource: [`acs:oss:*:*:${ENV_BUCKET}/*`],
                },
            ],
            Version: "1",
        };
        const credentials = await sts.assumeRole(ENV_ACS_RAM, policy, 15 * 60, "RoleSessionName");
        console.log(credentials);
        const oss = new OSS({
            region: ENV_REGION,
            accessKeyId: credentials.AccessKeyId,
            accessKeySecret: credentials.AccessKeySecret,
            stsToken: credentials.SecurityToken,
            bucket: ENV_BUCKET,
        });
        const KEY = `test2/usr001/1/${Math.random()}`;
        const CONTENT = Buffer.from(`test from @blueshit/oss-sts hello, world ${Date.now()}`);
        {
            const { name, url, res } = await oss.put(KEY, CONTENT);
            console.log(name, url, res);
            chai_1.expect(name).to.equal(KEY);
            chai_1.expect(res.statusCode).to.equal(200);
        }
        {
            const { res, content } = await oss.get(KEY);
            console.log(res, content);
            chai_1.expect(res.statusCode).to.equal(200);
            chai_1.expect(content).to.deep.equal(CONTENT);
        }
    });
});
//# sourceMappingURL=test.js.map