# Test Assets

이 디렉터리는 Git-based CTF 환경에서 빠르게 실습할 수 있도록 만든
샘플 서비스와 익스플로잇을 포함합니다.

## 구조

- `service/` – Flask 기반의 간단한 `/ping` API를 제공하는 취약 웹 서비스.
  `host` 파라미터를 그대로 `ping` 셸 명령에 붙여 넣기 때문에 명령주입이
  가능합니다.
- `exploit/` – 위 취약점을 이용해 `/var/ctf/flag`를 exfiltrate 하는 PoC.

## 사용법 예시

```
# 서비스 실행
./scripts/gitctf.py exec service \
  --service-dir test/service \
  --service-name solo-svc \
  --host-port 5000 \
  --service-port 5000

# 다른 셸에서 익스플로잇 실행 (필요 시 TARGET_HOST/TARGET_PORT 조정)
./scripts/gitctf.py exec exploit \
  --exploit test/exploit \
  --service-dir test/service \
  --service-name solo-svc \
  --service-port 5000
```

필요에 따라 `bug1` 등의 커밋을 만들고 `scripts/config.json`에 해시를
기입하면 end-to-end 테스트를 진행할 수 있습니다.

