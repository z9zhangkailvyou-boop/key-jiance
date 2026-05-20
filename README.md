# Secret Scanner

扫描代码库中意外提交的 API Key 和敏感凭证。支持已知模式匹配 + 信息熵检测，覆盖 DeepSeek、OpenAI、Anthropic、GitHub、AWS、GCP 等主流服务。

## 快速开始

```bash
# 扫描当前目录
python secret-scanner.py

# 扫描特定路径
python secret-scanner.py --path ./src

# 同时扫描 git 提交历史
python secret-scanner.py --git-history

# JSON 输出（适合集成到其他工具）
python secret-scanner.py --json
```

## 支持的密钥类型

| 类型 | 示例 |
|------|------|
| Anthropic API Key | `sk-ant-api03-...` |
| DeepSeek API Key | `sk-...` |
| OpenAI / Claude API Key | `sk-proj-...` |
| GitHub Token | `ghp_...` / `gho_...` |
| AWS Access Key | `AKIA...` |
| GCP API Key | `AIza...` |
| Stripe Secret Key | `sk_live_...` |
| Slack Bot Token | `xoxb-...` |
| JWT Token | `eyJ...` |
| Private Key Block | `-----BEGIN ... PRIVATE KEY-----` |

此外，信息熵检测还能发现不符合已知格式的高随机性凭证。

## CI 集成

### pre-commit

```bash
pip install pre-commit
pre-commit install --hook-type pre-commit --hook-type pre-push
```

每次 `git commit` 和 `git push` 前自动扫描。

### GitHub Actions

已内置 [workflow](.github/workflows/secret-scan.yml)，每次 push/PR 到 main 分支时自动运行。
