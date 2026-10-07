# 제3자 구성과 라이선스

프로젝트 자체의 소스는 루트 LICENSE의 Apache-2.0 조건으로 제공합니다. 아래 항목은 고정 의존성의 배포 메타데이터와 보존된 고지에 따른 목록입니다. 각 구성 요소에는 해당 원문의 조건이 적용됩니다. 다운로드한 원본 wheel·모델·Python 배포물의 라이선스와 NOTICE를 함께 보존합니다.

모델은 convaiinnovations/laya-multilingual이며, 모델 카드의 표시 라이선스는 Apache-2.0입니다. 버전·원본 파일은 model-manifest.json에 고정돼 있습니다. Python 3.12.10 배포 ZIP의 LICENSE.txt와 제3자 고지를 유지합니다. 모델이나 런타임이 이 소스 저장소에 포함되어 있다는 의미는 아닙니다.

| 패키지 | 고정 버전 | 배포 메타데이터의 라이선스 | 원본·소스 확인 |
| --- | --- | --- | --- |
| annotated-doc | 0.0.5 | MIT | https://pypi.org/project/annotated-doc/0.0.5/ |
| anyio | 4.15.1 | MIT | https://pypi.org/project/anyio/4.15.1/ |
| certifi | 2026.7.22 | MPL-2.0 | https://pypi.org/project/certifi/2026.7.22/ |
| click | 8.5.0 | BSD-3-Clause | https://pypi.org/project/click/8.5.0/ |
| colorama | 0.4.6 | BSD License | https://pypi.org/project/colorama/0.4.6/ |
| filelock | 4.0.6 | MIT | https://pypi.org/project/filelock/4.0.6/ |
| fsspec | 2026.9.0 | BSD-3-Clause | https://pypi.org/project/fsspec/2026.9.0/ |
| h11 | 0.16.0 | MIT | https://pypi.org/project/h11/0.16.0/ |
| hf-xet | 1.6.0 | Apache-2.0 | https://pypi.org/project/hf-xet/1.6.0/ |
| httpcore | 1.0.9 | BSD-3-Clause | https://pypi.org/project/httpcore/1.0.9/ |
| httpx | 0.28.1 | BSD-3-Clause | https://pypi.org/project/httpx/0.28.1/ |
| huggingface_hub | 1.33.0 | Apache-2.0 | https://pypi.org/project/huggingface_hub/1.33.0/ |
| idna | 3.20 | BSD-3-Clause | https://pypi.org/project/idna/3.20/ |
| Jinja2 | 3.1.6 | BSD License | https://pypi.org/project/Jinja2/3.1.6/ |
| laya | 0.3.22 | Apache-2.0 | https://pypi.org/project/laya/0.3.22/ |
| markdown-it-py | 4.2.0 | MIT License | https://pypi.org/project/markdown-it-py/4.2.0/ |
| MarkupSafe | 3.0.3 | BSD-3-Clause | https://pypi.org/project/MarkupSafe/3.0.3/ |
| mdurl | 0.1.2 | MIT License | https://pypi.org/project/mdurl/0.1.2/ |
| mpmath | 1.3.0 | BSD | https://pypi.org/project/mpmath/1.3.0/ |
| networkx | 3.7 | BSD-3-Clause | https://pypi.org/project/networkx/3.7/ |
| numpy | 2.5.3 | BSD-3-Clause AND 0BSD AND MIT AND Zlib AND CC0-1.0 | https://pypi.org/project/numpy/2.5.3/ |
| packaging | 26.3 | Apache-2.0 OR BSD-2-Clause | https://pypi.org/project/packaging/26.3/ |
| Pygments | 2.21.0 | BSD-2-Clause | https://pypi.org/project/Pygments/2.21.0/ |
| PyYAML | 6.0.3 | MIT | https://pypi.org/project/PyYAML/6.0.3/ |
| regex | 2026.9.29 | Apache-2.0 AND CNRI-Python | https://pypi.org/project/regex/2026.9.29/ |
| rich | 15.0.0 | MIT | https://pypi.org/project/rich/15.0.0/ |
| safetensors | 0.8.0 | Apache Software License | https://pypi.org/project/safetensors/0.8.0/ |
| setuptools | 84.0.0 | MIT | https://pypi.org/project/setuptools/84.0.0/ |
| shellingham | 1.5.4 | ISC License | https://pypi.org/project/shellingham/1.5.4/ |
| sympy | 1.14.0 | BSD | https://pypi.org/project/sympy/1.14.0/ |
| tokenizers | 0.23.2 | Apache Software License | https://pypi.org/project/tokenizers/0.23.2/ |
| torch | 2.14.0 | Apache-2.0 AND Apache-2.0 WITH LLVM-exception AND BSD-2-Clause AND BSD-3-Clause AND BSL-1.0 AND MIT | https://pypi.org/project/torch/2.14.0/ |
| tqdm | 4.70.1 | MPL-2.0 AND MIT | https://pypi.org/project/tqdm/4.70.1/ |
| transformers | 5.17.0 | Apache 2.0 License | https://pypi.org/project/transformers/5.17.0/ |
| typer | 0.27.2 | MIT | https://pypi.org/project/typer/0.27.2/ |
| typing_extensions | 4.16.0 | PSF-2.0 | https://pypi.org/project/typing_extensions/4.16.0/ |

tokenizers 0.23.2의 Windows wheel에서는 별도 라이선스 파일을 찾지 못해, PyPI의 동일 버전 소스 배포물에서 Apache 라이선스를 확보했습니다. 원문은 licenses/tokenizers-LICENSE.txt에 있습니다. 원본 소스 배포물 SHA-256: 7f0f085686b9de0d0079e6f874ae053600db64c5d13049e0bbc0119926d25aac.

MPL 등 파일 단위 조건이 적용되는 구성 요소의 소스는 위에 연결한 동일 버전 원본 배포·프로젝트를 통해 확인할 수 있습니다. 수정한 제3자 구성 요소를 재배포할 때는 해당 수정과 원본 조건을 별도로 관리합니다. 고지·라이선스 파일을 제거하거나 서로 다른 구성의 라이선스를 이 프로젝트의 Apache-2.0으로 일괄 대체하지 않습니다.
