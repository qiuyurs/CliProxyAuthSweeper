# CliProxyAuthSweeper

`CliProxyAuthSweeper` 是一个基于 Bash 的 CLIProxyAPI 授权清理工具。

核心特性：

- 默认直接删除失效授权文件（`RUN_MODE=delete`）
- 支持观察模式（`RUN_MODE=observe`，只检测不删除）
- 仅使用环境变量配置，不接收命令行参数
- 运行时不创建任何本地文件
- 支持首次全量、后续增量窗口（通过环境变量 `LAST_RUN_EPOCH` 传入）

## 判定规则

- 按 `auth_index` 计算连续失败次数
- 遇到成功请求（`failed=false`）立即重置计数
- 连续失败 `>= THRESHOLD` 判定为失效

匹配顺序：

1. `auth_index == files[].id`
2. 回退 `auth_index == files[].name`
3. 回退 `auth_index == files[].name` 去掉 `.json`

## 依赖

- Bash 4+
- curl
- jq 1.6+

## 环境变量

- `MANAGEMENT_KEY`：必填，管理密钥
- `BASE_URL`：可选，默认 `http://localhost:8317/v0/management`
- `THRESHOLD`：可选，默认 `3`
- `RUN_MODE`：可选，`delete|observe`，默认 `delete`
- `LAST_RUN_EPOCH`：可选，Unix 秒级时间戳；设置后启用增量窗口
- `ALLOW_NAME_FALLBACK`：可选，`1|0`，默认 `1`
- `TIMEOUT`：可选，默认 `10`
- `INSECURE`：可选，`1|0`，默认 `0`
- `VERBOSE`：可选，`1|0`，默认 `0`

## 快速运行（3 行）

```bash
export MANAGEMENT_KEY='your_management_key' BASE_URL='http://localhost:8317/v0/management' THRESHOLD='3' RUN_MODE='delete' LAST_RUN_EPOCH='' ALLOW_NAME_FALLBACK='1' TIMEOUT='10' INSECURE='0' VERBOSE='0'
curl -fsSL -o cleanup_invalid_auth_files.sh https://raw.githubusercontent.com/qiuyurs/CliProxyAuthSweeper/main/scripts/cleanup_invalid_auth_files.sh
bash cleanup_invalid_auth_files.sh
```

## 增量运行说明（无文件状态）

脚本不会写状态文件。每次运行会输出：

- `NEXT_LAST_RUN_EPOCH=<epoch>`
- `NEXT_LAST_RUN_AT=<utc_time>`

你可以把 `NEXT_LAST_RUN_EPOCH` 存到调度系统或外部状态存储，下一次作为 `LAST_RUN_EPOCH` 传回脚本。

## 定时任务（每 1 小时运行一次）

Linux `crontab` 示例：

```cron
0 * * * * export MANAGEMENT_KEY='your_management_key'; export BASE_URL='http://localhost:8317/v0/management'; export THRESHOLD='3'; export RUN_MODE='delete'; bash /path/to/cleanup_invalid_auth_files.sh >> /var/log/cliproxy-auth-sweeper.log 2>&1
```

如果要做增量窗口，请在调度系统里保存上次输出的 `NEXT_LAST_RUN_EPOCH`，并在下次执行前注入为 `LAST_RUN_EPOCH`。

## 接口

- `GET /v0/management/usage`
- `GET /v0/management/auth-files`
- `DELETE /v0/management/auth-files?name=<file.json>`
