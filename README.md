# monad-debugger

`monad-debugger`는 Monad 네트워크 패킷을 eBPF 기반으로 수집·시각화하기 위한 도구입니다.

## 현재 구성

- `Cargo.toml` – 워크스페이스 정의
- `host/` – 호스트 바이너리(유저 공간 에이전트) 초기 골격
- `ebpf/` – XDP 훅으로 패킷 메타데이터를 포착하는 eBPF 프로그램(PerfEventArray 기반)
- `common/` – eBPF ↔ 사용자 공간 간에 공유하는 패킷 이벤트 구조 정의

호스트 바이너리는 eBPF 프로그램에서 보낸 이벤트를 수신해 후속 분석 파이프라인으로 전달하게 됩니다.
