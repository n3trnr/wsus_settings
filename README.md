# wsus_settings

사용자 PC와 윈도우 업데이트 서버 인 WSUS 서버를 연결시켜주는 배치 스크립트 파일입니다.

NTP 서버와 시간 싱크하는 기능도 같이 포함되어있으며 

해당 배치스크립트를 적용시 자동업데이트 기능은 비활성화 됩니다.

WSUS 서버 정보는 30번째라인에 reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "WUStatusServer" /d "http://10.1.1.215:8530" /f
에 있는 IP 주소입니다.
