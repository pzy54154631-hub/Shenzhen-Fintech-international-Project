# Deploy Corridor Wealth to Streamlit Community Cloud

[简体中文](DEPLOY.zh-CN.md)

No hosted deployment is available. The demo runs locally with `uv run --frozen corridor demo` in **Demo mode**, using a scripted planner without an API key or API calls. Local **Real AI** is available after a user supplies their own OpenAI key (BYOK), or enters the access code when a server key is configured. See [local run instructions](#dependencies-and-local-verification). The Cloud deployment steps below are optional. Financial data, device authentication and transactions remain synthetic in both modes; the kernel and gateway checks are identical.

## Create the app

1. Sign in to [Streamlit Community Cloud](https://share.streamlit.io/) with GitHub and create an app from an existing repository.
2. Select repository `pzy54154631-hub/Shenzhen-Fintech-international-Project`, branch `main`, and entrypoint `streamlit_app.py`.
3. Open **Advanced settings**, choose **Python 3.11**, and paste your deployment secrets using the example below. Leave credentials empty to offer Demo mode and BYOK only.
4. Deploy, open the app, and verify the English and Simplified Chinese interfaces. Only after a deployment is available, add its assigned app URL to both public READMEs. Supply any judges' access code separately in the submission materials.

The repository, entrypoint, Python and secrets controls follow [Streamlit's deployment instructions](https://docs.streamlit.io/deploy/streamlit-community-cloud/deploy-your-app/deploy). These instructions provide optional deployment preparation.

## Configure secrets and spending

**Strongly recommended: create a separate OpenAI project and project key for this website, with a monthly spending cap and alerts. Do not reuse a development key.** In the project's Limits settings, edit the monthly spend limit and enable **Enforce a hard limit**. An alert alone does not stop traffic; enforcement can lag slightly, so also monitor usage. Follow [OpenAI's spend-limit instructions](https://developers.openai.com/api/docs/guides/spend-limits).

Copy the keys from [the secrets example](../.streamlit/secrets.toml.example) into the Cloud Secrets editor, then enter the real values there:

```toml
LLM_API_KEY = ""
LLM_MODEL = "gpt-6.1-sol"
LLM_API = "responses"
LIVE_ACCESS_CODE = ""
LIVE_DAILY_USD = "5"
LIVE_SESSION_CALLS = 40
```

Use a long, unique access code. Server settings can also come from environment variables. Never commit `.streamlit/secrets.toml` or `.env`; both are excluded from the public export. See [Streamlit's secrets management](https://docs.streamlit.io/deploy/streamlit-community-cloud/deploy-your-app/secrets-management).

The server-funded path shares a USD 5 daily limit by default, permits at most 40 model calls per browser session, and allows at most one request every 2 seconds per session. The page displays remaining budget. Reservations conservatively bound requests before transport. When a limit is reached, the app reports it and returns to Demo mode at a transaction boundary; a live error never silently substitutes a scripted response within a transaction.

The budget journal is stored in the runtime temporary directory, outside the repository. Its day boundary is UTC. It survives browser resets but is not durable across replacement of the cloud runtime or deletion of temporary storage. A provider-side budget and usage monitoring are therefore still necessary. BYOK calls use the visitor's provider account and are excluded from the site's server-key budget. BYOK stays in the current browser session's server memory and is not written into files, audits, logs, replay recordings or exception messages.

Each browser session has a separate synthetic bank, gateway, audit and simulated clock. **Reset demo** starts fresh synthetic state; it does not replenish server usage limits. A browser reconnect may create a new session.

## Rotate access or disable server-funded AI

In the Cloud app's **Settings → Secrets**, replace `LIVE_ACCESS_CODE`, save, and reboot the app so existing sessions also require the new code. Distribute the replacement code privately. To disable server-funded Real AI, delete `LLM_API_KEY` from Secrets and any deployment environment, save, and reboot. Demo mode remains available; visitors may still choose BYOK. Revoke the provider key separately if it should no longer work anywhere.

## Dependencies and local verification

Use Python 3.11. Exact runtime versions are exported from `uv.lock`, without development dependencies:

```powershell
uv export --frozen --no-dev --no-hashes --no-annotate --output-file requirements.txt
uv sync --frozen
uv run --frozen streamlit run streamlit_app.py
```

The exported `-e .` installs the local `corridor` package, including its UI message resources. Community Cloud [prioritizes `uv.lock` over `requirements.txt`](https://docs.streamlit.io/deploy/streamlit-community-cloud/deploy-your-app/app-dependencies), so this repository deploys from the frozen uv project; the requirements file is an exact runtime-only export for pip-compatible installations. Regenerate it whenever the lockfile changes. No new application dependency is required for W1.

The root entrypoint uses the platform's default bind address. For an explicitly loopback-only local server, run `uv run --frozen corridor demo`; that command still binds `127.0.0.1`. To test local secrets, copy the example to the ignored `.streamlit/secrets.toml` and supply credentials locally without printing them.

Optional local OpenAI-compatible servers can be selected with `LLM_API_BASE = "http://127.0.0.1:11434/v1"` and an appropriate local `LLM_MODEL`. The wealth advisor requires `LLM_API = "responses"` and a local adapter supporting the bounded Responses API and named function-tool profile; a chat-only Ollama endpoint cannot run this flow. Configure this only on your own machine with a compatible adapter and model. Cloud localhost is the cloud container, not your computer. This option is configuration support, not an assertion that a particular Ollama model or adapter was evaluated. BYOK always uses OpenAI's service.
