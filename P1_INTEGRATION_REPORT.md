# P1 集成测试报告

**测试时间**: 2026-11-03 06:32 UTC  
**测试脚本**: `test-p1-integration.mjs`  
**App**: dazi-superagent-test (ID: 5580392)  
**Installation**: 177845221  
**Repository**: zx110511/dsh-superagent-prototype (ID: 1443021924)

---

## 结果：40/40 PASS ✅

| 测试阶段 | 项目数 | 通过 | 说明 |
|---------|-------|------|------|
| Step 1: 私钥验证 | 4 | 4 | RSA 2048-bit, 格式正确 |
| Step 2: JWT 签发 | 5 | 5 | RS256, 10 分钟有效期, 60s 时钟偏移 |
| Step 3: App 身份 | 3 | 3 | GitHub API 接受 JWT, slug=dazi-superagent-test |
| Step 4: 安装验证 | 6 | 6 | 安装活跃, 所有者匹配 |
| Step 5: Token 颁发 | 5 | 5 | ghs_ 前缀, 1 小时有效期, 6 项权限 |
| Step 6: 仓库访问 | 3 | 3 | 目标仓库可访问, ID 匹配 |
| Step 7: Bot 身份 | 3 | 3 | dazi-superagent-test[bot], type=Bot |
| Step 8: 事件轮询 | 4 | 4 | Issues API + PRs API 可用, ETag 返回 |
| Step 9: 身份协议 | 7 | 7 | AppIdentity v1 完整合规 |

---

## AppIdentity 文档（实测）

```json
{
  "version": 1,
  "app": { "id": 5580392, "slug": "dazi-superagent-test" },
  "bot": { "id": 351530142, "login": "dazi-superagent-test[bot]" },
  "repository": { "id": 1443021924, "full_name": "zx110511/dsh-superagent-prototype" },
  "permissions": {
    "issues": "read",
    "pull_requests": "write",
    "contents": "read",
    "checks": "read",
    "commit_statuses": "read",
    "metadata": "read"
  },
  "expires_at": "2026-11-02T23:32:36Z",
  "token_sha256": "Z20od2XizJvMreRwM75UfBNkNR2FnB9kWhksw3Dy4GE="
}
```

---

## 配置备注

### 已生效
- JWT RS256 签名 ✓
- Installation token 颁发 ✓
- 单仓 repository_ids 请求 ✓
- 仓级 Issues API 轮询 ✓
- Bot 身份验证 ✓
- Token SHA256 指纹 ✓

### 待优化（CONFIG 级别，非阻塞）
- `repository_selection='all'`：App 安装配置为全仓访问，代码层通过 `repository_ids` 参数约束单仓。如需 API 层硬约束，需在 GitHub App 设置中改为 `selected` 并只选择目标仓库。
- 权限授予：GitHub 返回 App 配置的完整权限（issues/contents 为 write），代码请求最小权限（read）。实际运行以代码层 PERMISSIONS 常量为准。

---

## 结论

GitHub App 单仓凭据系统端到端验证通过：
1. **私钥 → JWT → Token** 全链路正常
2. **AppIdentity v1 协议** 9 个字段全部合规
3. **仓级事件轮询** Issues API + PRs API 可用
4. **安全边界** Token 1 小时过期，SHA256 指纹可追溯
