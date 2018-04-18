# @blueshit/aliyun-sts

轻量级阿里云STS客户端，不依赖任何第三方库，体验飞一般的感觉

## 安装

```bash
npm i @blueshit/aliyun-sts -S
```

## 使用

```typescript
import { STS } from "@blueshit/aliyun-sts";

const sts = new STS({
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
```

## 授权协议

The MIT License
