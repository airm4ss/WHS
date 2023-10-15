# CVE-2021-32682

## elFinder ZIP 인수 삽입으로 인해 명령 삽입이 발생함

elFinder는 jQuery UI를 사용하여 JavaScript로 작성된 웹용 오픈 소스 파일 관리자이다.

elFinder 2.1.48 및 이전 버전에서 인수 주입 취약점이 발견되었다. 이 취약점으로 인해 공격자는 최소한의 구성으로도 elFinder PHP 커넥터를 호스팅하는 서버에서 임의의 명령을 실행할 수 있다. 이 문제는 버전 2.1.59에서 패치되었다. 인증 없이 커넥터가 노출되지 않도록 주의해야 한다.

참고자료:
* https://blog.sonarsource.com/elfinder-case-study-of-web-file-manager-vulnerability
* https://packetstormsecurity.com/files/164173/elfinder_archive_cmd_injection.rb.txt
* https://xz.aliyun.com/t/10739

## 취약점 환경
elFinder 2.1.48을 시작하려면 아래 명령을 수행한다.

```
docker compose up -d
```

## Vulnerability Reproduce
먼저, 2개의 파일을 준비해야 한다. 아래와 같은 일반 텍스트 파일을 만든다.
<img src="vulhub/make_txt.png">
