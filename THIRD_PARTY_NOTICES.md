# Third-party notices

Generated from installed distribution metadata with `importlib.metadata`, starting
from the runtime requirements in `pyproject.toml` and following their transitive
requirements and requested extras. Environment markers use the generation platform;
this snapshot was generated on Windows with Python 3.11.17.
Development-only and build-only packages are excluded. Other platforms can select
different conditional packages from the same lockfile.

Licence labels are package metadata declarations: `License-Expression`, then licence
classifiers, then a short `License` value. Unavailable or ambiguous declarations
are marked `unknown`. These labels do not replace the licence and notice files
distributed with each package. Third-party components retain their own terms;
Corridor's evaluation-only licence does not change those terms.

Regenerate after `uv sync --frozen` with:

```text
uv run --frozen python scripts/public_notices.py
```

| Runtime dependency | Installed version | Licence metadata | Requirement |
|---|---|---|---|
| aiohappyeyeballs | 2.7.1 | Python Software Foundation License | transitive |
| aiohttp | 3.14.5 | Apache-2.0 AND MIT | transitive |
| aiosignal | 1.4.0 | Apache Software License | transitive |
| altair | 5.5.0 | BSD License | transitive |
| annotated-doc | 0.0.5 | MIT | transitive |
| annotated-types | 0.8.0 | MIT | transitive |
| anyio | 4.15.1 | MIT | transitive |
| attrs | 26.1.0 | MIT | transitive |
| blinker | 1.9.0 | MIT License | transitive |
| boto3 | 1.43.114 | Apache-2.0 | transitive |
| botocore | 1.43.114 | Apache-2.0 | transitive |
| cachetools | 6.2.6 | MIT | transitive |
| certifi | 2026.7.22 | Mozilla Public License 2.0 (MPL 2.0) | transitive |
| cffi | 2.1.1 | MIT-0 | transitive |
| charset-normalizer | 3.5.2 | MIT | transitive |
| click | 8.5.0 | BSD-3-Clause | transitive |
| colorama | 0.4.6 | BSD License | transitive |
| contourpy | 1.3.3 | BSD License | transitive |
| cryptography | 50.0.2 | Apache-2.0 OR BSD-3-Clause | transitive |
| cycler | 0.12.1 | BSD License | transitive |
| distro | 1.9.0 | Apache Software License | transitive |
| fastuuid | 0.14.0 | BSD License | transitive |
| filelock | 3.32.7 | MIT | transitive |
| fonttools | 4.67.0 | MIT | transitive |
| frozenlist | 1.8.0 | Apache-2.0 | transitive |
| fsspec | 2026.9.0 | BSD-3-Clause | transitive |
| gitdb | 4.0.12 | BSD License | transitive |
| GitPython | 3.2.1 | BSD-3-Clause | transitive |
| h11 | 0.16.0 | MIT License | transitive |
| h2 | 4.4.1 | MIT | transitive |
| hf-xet | 1.7.0 | Apache-2.0 | transitive |
| hpack | 4.2.0 | MIT | transitive |
| httpcore | 1.0.9 | BSD-3-Clause | transitive |
| httpx | 0.28.1 | BSD License | direct |
| huggingface_hub | 1.33.0 | Apache Software License | transitive |
| hyperframe | 6.1.0 | MIT License | transitive |
| idna | 3.20 | BSD-3-Clause | transitive |
| importlib_metadata | 8.9.0 | Apache-2.0 | transitive |
| Jinja2 | 3.1.6 | BSD License | transitive |
| jiter | 0.17.0 | MIT | transitive |
| jmespath | 1.1.0 | MIT License | transitive |
| jsonschema | 4.26.0 | MIT | transitive |
| jsonschema-specifications | 2025.9.1 | MIT | transitive |
| kiwisolver | 1.5.1 | BSD License | transitive |
| litellm | 1.105.1 | MIT | direct |
| markdown-it-py | 4.2.0 | MIT License | transitive |
| MarkupSafe | 3.0.4 | BSD-3-Clause | transitive |
| matplotlib | 3.11.2 | Python Software Foundation License | direct |
| mdurl | 0.1.2 | MIT License | transitive |
| multidict | 7.1.0 | Apache-2.0 | transitive |
| narwhals | 2.27.1 | MIT | transitive |
| numpy | 2.4.6 | BSD-3-Clause AND 0BSD AND MIT AND Zlib AND CC0-1.0 | transitive |
| openai | 2.54.0 | Apache Software License | transitive |
| packaging | 25.0 | Apache Software License / BSD License | transitive |
| pandas | 2.3.3 | BSD License | transitive |
| pdfminer.six | 20251230 | MIT | transitive |
| pdfplumber | 0.11.9 | MIT License | direct |
| pillow | 11.3.0 | MIT-CMU | direct |
| propcache | 0.5.4 | Apache-2.0 | transitive |
| protobuf | 6.33.6 | 3-Clause BSD License | transitive |
| pyarrow | 26.0.0 | Apache-2.0 | transitive |
| pycparser | 3.11 | BSD-3-Clause | transitive |
| pydantic | 2.14.1 | MIT | direct |
| pydantic_core | 2.50.1 | MIT | transitive |
| pydantic-settings | 2.16.0 | MIT | transitive |
| pydeck | 0.9.3 | Apache License 2.0 | transitive |
| Pygments | 2.21.0 | BSD-2-Clause | transitive |
| PyNaCl | 1.6.2 | Apache Software License | direct |
| pyparsing | 3.3.3 | MIT | transitive |
| pypdfium2 | 5.14.0 | unknown | transitive |
| python-dateutil | 2.9.0.post0 | Apache Software License / BSD License | transitive |
| python-dotenv | 1.2.4 | BSD-3-Clause | transitive |
| pytz | 2026.5 | MIT License | transitive |
| PyYAML | 6.0.3 | MIT License | direct |
| qrcode | 8.2 | BSD License / Other/Proprietary License | direct |
| referencing | 0.37.0 | MIT | transitive |
| regex | 2026.9.29 | Apache-2.0 AND CNRI-Python | transitive |
| reportlab | 5.0.1 | BSD License | direct |
| requests | 2.34.2 | Apache Software License | transitive |
| rfc8785 | 0.1.4 | Apache Software License | direct |
| rich | 15.0.0 | MIT License | transitive |
| rpds-py | 2026.9.1 | MIT | transitive |
| s3transfer | 0.19.2 | Apache Software License | transitive |
| shellingham | 1.5.4 | ISC License (ISCL) | transitive |
| six | 1.17.0 | MIT License | transitive |
| smmap | 5.0.3 | BSD License | transitive |
| sniffio | 1.3.1 | Apache Software License / MIT License | transitive |
| streamlit | 1.50.0 | Apache Software License | direct |
| tenacity | 9.2.1 | Apache-2.0 | transitive |
| tiktoken | 0.14.0 | unknown | transitive |
| tokenizers | 0.23.3 | Apache Software License | transitive |
| toml | 0.10.2 | MIT License | transitive |
| tornado | 6.5.10 | Apache Software License | transitive |
| tqdm | 4.70.1 | MPL-2.0 AND MIT | transitive |
| typer | 0.27.3 | MIT | direct |
| typing_extensions | 4.16.0 | PSF-2.0 | transitive |
| typing-inspection | 0.4.4 | MIT | transitive |
| tzdata | 2026.5 | Apache-2.0 | direct |
| urllib3 | 2.8.0 | MIT | transitive |
| watchdog | 6.0.0 | Apache Software License | transitive |
| yarl | 1.25.1 | Apache-2.0 | transitive |
| zipp | 4.1.1 | MIT | transitive |
