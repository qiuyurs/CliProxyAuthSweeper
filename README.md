# CliProxyAuthSweeper

`CliProxyAuthSweeper` 是一个基于 Bash 的 CLIProxyAPI 授权清理工具。

核心特性：

- 默认直接删除失效授权文件（`RUN_MODE=delete`）
- 支持观察模式（`RUN_MODE=observe`，只检测不删除）
- 仅使用环境变量配置，不接收命令行参数
- 不创建业务状态文件
- 不依赖 `jq`
- 控制台输出中文可读运行报告
- 每次运行固定全量扫描

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
- python3（脚本 JSON 解析与计算依赖）

## 快速运行（仅设置密钥，其他使用默认值）

```bash
# 1) 只设置必填密钥；其他变量不设置，脚本将使用默认值
export MANAGEMENT_KEY='your_management_key'

# 2) 下载脚本到当前目录
curl -fsSL -o cleanup_invalid_auth_files.sh https://raw.githubusercontent.com/qiuyurs/CliProxyAuthSweeper/main/scripts/cleanup_invalid_auth_files.sh

# 3) 执行脚本（默认 RUN_MODE=delete，会直接删除失效文件）
bash cleanup_invalid_auth_files.sh
```

## 定时任务（每 1 小时运行一次）

Linux `crontab` 示例：

```cron
0 * * * * bash /path/to/cleanup_invalid_auth_files.sh
```

说明：

- 该示例只执行脚本文件，默认认为环境变量已提前设置完成

## 环境变量

- `MANAGEMENT_KEY`：必填，管理密钥
- `BASE_URL`：可选，默认 `http://localhost:8317/v0/management`
- `THRESHOLD`：可选，默认 `3`
- `RUN_MODE`：可选，`delete|observe`，默认 `delete`
- `ALLOW_NAME_FALLBACK`：可选，`1|0`，默认 `1`
- `TIMEOUT`：可选，默认 `10`
- `INSECURE`：可选，`1|0`，默认 `0`
- `VERBOSE`：可选，`1|0`，默认 `0`
- `PYTHON_BIN`：可选，默认 `python3`（回退 `python`）

```bash
# 示例：按需设置全部变量（非必须）
export MANAGEMENT_KEY='your_management_key'
export BASE_URL='http://localhost:8317/v0/management'
export THRESHOLD='3'
export RUN_MODE='delete'                # delete|observe
export ALLOW_NAME_FALLBACK='1'          # 1 开启 name 回退匹配，0 关闭
export TIMEOUT='10'
export INSECURE='0'                     # 测试环境自签证书可设为 1
export VERBOSE='0'
export PYTHON_BIN='python3'
```
