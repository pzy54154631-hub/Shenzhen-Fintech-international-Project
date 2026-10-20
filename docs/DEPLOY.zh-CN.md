# 将 Corridor Wealth 部署到 Streamlit Community Cloud

[English](DEPLOY.md)

目前没有已上线的网站。运行 `uv run --frozen corridor demo` 即可在本地进入**演示模式**，使用 scripted planner，无需 API key，不调用 API。本地**真实 AI**模式可使用自带 OpenAI key（BYOK），或在服务器配置 key 后输入访问码启用。详见[本地运行说明](#依赖与本地验证)；下方 Cloud 部署步骤为可选项。两种模式的金融数据、设备认证和交易均为合成模拟，内核与网关检查完全相同。

## 创建应用

1. 使用 GitHub 登录 [Streamlit Community Cloud](https://share.streamlit.io/)，从已有仓库创建应用。
2. 选择仓库 `pzy54154631-hub/Shenzhen-Fintech-international-Project`、分支 `main`、入口 `streamlit_app.py`。
3. 打开 **Advanced settings**，选择 **Python 3.11**，按下方示例填写 Secrets。不配置凭据时提供演示模式和 BYOK。
4. 部署后打开应用，检查英文与简体中文界面。仅在部署成功后，向两份公开 README 添加实际网址；如需提供评委访问码，单独放在提交材料中。

仓库、入口、Python 与 Secrets 设置以 [Streamlit 部署说明](https://docs.streamlit.io/deploy/streamlit-community-cloud/deploy-your-app/deploy) 为依据。本说明仅提供可选的部署准备。

## 配置密钥与消费预算

**强烈建议为网站单独建立 OpenAI project 和 project key，并设置月度消费上限与告警。不要使用开发用 key。** 在项目 Limits 设置中编辑月度消费限额，并开启 **Enforce a hard limit**。仅设置告警不会停止调用；硬限额生效可能略有延迟，因此仍需监控用量。操作见 [OpenAI 消费限额说明](https://developers.openai.com/api/docs/guides/spend-limits)。

将[密钥示例](../.streamlit/secrets.toml.example)中的字段复制到 Cloud 的 Secrets 编辑器，再在那里填写真实值：

```toml
LLM_API_KEY = ""
LLM_MODEL = "gpt-6.1-sol"
LLM_API = "responses"
LIVE_ACCESS_CODE = ""
LIVE_DAILY_USD = "5"
LIVE_SESSION_CALLS = 40
```

使用较长且唯一的访问码。服务器设置也可来自环境变量。不要提交 `.streamlit/secrets.toml` 或 `.env`；公开导出器排除两者。操作方式见 [Streamlit 密钥管理](https://docs.streamlit.io/deploy/streamlit-community-cloud/deploy-your-app/secrets-management)。

服务器 key 默认共享全站每日 USD 5 上限，每个浏览器会话最多调用模型 40 次，每会话 2 秒内最多发起 1 次请求。页面显示剩余额度，发出请求前先保守预留费用。额度耗尽时明确提示，并在交易边界切回演示模式；live 失败不会在一笔交易中悄悄替换成 scripted 输出。

预算 journal 位于仓库之外的运行时临时目录，按 UTC 日期分日。浏览器重置不会清空它，但云端运行容器替换或临时存储删除后无法保证保留，因此仍需提供商预算与用量监控。BYOK 由访客自己的提供商账户计费，不计入本站服务器 key 预算。BYOK 仅保存在当前浏览器会话对应的服务器内存中，不写入文件、审计、日志、replay 录制或异常信息。

每个浏览器会话独立持有合成银行、网关、审计与模拟时钟。**重置演示**创建新的合成状态，不补充服务器使用额度；浏览器重新连接可能建立新会话。

## 更换访问码或关闭服务器资助的真实 AI

在 Cloud 应用的 **Settings → Secrets** 中替换 `LIVE_ACCESS_CODE`，保存后重启应用，使现有会话也必须重新输入访问码。新码单独私下分发。要关闭服务器资助的真实 AI，删除 Secrets 与部署环境中的 `LLM_API_KEY`，保存后重启。演示模式仍可使用；访客仍可选择 BYOK。如需使该 key 在所有位置失效，还应在提供商侧撤销它。

## 依赖与本地验证

使用 Python 3.11。从 `uv.lock` 导出精确的运行时版本，不包含开发依赖：

```powershell
uv export --frozen --no-dev --no-hashes --no-annotate --output-file requirements.txt
uv sync --frozen
uv run --frozen streamlit run streamlit_app.py
```

导出文件中的 `-e .` 同时安装本地 `corridor` 包及其 UI 文案资源。Community Cloud [优先读取 `uv.lock`，其次才可能选择 `requirements.txt`](https://docs.streamlit.io/deploy/streamlit-community-cloud/deploy-your-app/app-dependencies)，因此本仓库使用冻结的 uv 项目部署；requirements 文件是供 pip 兼容安装使用的精确运行时依赖导出。锁文件变更后须重新生成；W1 无需新增应用依赖。

根入口使用平台默认监听地址。如需明确限制为本机监听，运行 `uv run --frozen corridor demo`；该命令仍绑定 `127.0.0.1`。测试本地 secrets 时，将示例复制到已忽略的 `.streamlit/secrets.toml`，仅在本地填入凭据，不回显。

本地可通过 `LLM_API_BASE = "http://127.0.0.1:11434/v1"` 与合适的本地 `LLM_MODEL` 配置 OpenAI 兼容服务。财富顾问要求 `LLM_API = "responses"`，且本地适配器支持受限 Responses API 与具名函数工具；只有 chat 接口的 Ollama 服务无法运行这条流程。仅在自己的机器具备兼容适配器与模型时使用；云端的 localhost 是云容器，不是个人电脑。这里只提供配置支持，不宣称已评测某个 Ollama 模型或适配器。BYOK 始终使用 OpenAI 服务。
