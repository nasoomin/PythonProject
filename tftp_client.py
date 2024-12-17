import socket
import os
import sys
import time
import argparse

TFTP_PORT = 9999
TIMEOUT = 5  # 타임아웃 시간 (초)
BUFFER_SIZE = 512  # TFTP 데이터 블록 크기

# TFTP 메세지 유형
OPCODES = {
    'RRQ': 1,  # Read Request
    'WRQ': 2,  # Write Request
    'DATA': 3,  # Data
    'ACK': 4,  # Acknowledgment
    'ERROR': 5  # Error
}


# TFTP 패킷 구성 함수
def create_rrq_packet(filename):
    return b'\x00\x01' + filename.encode('ascii') + b'\x00' + b'octet' + b'\x00'


def create_wrq_packet(filename):
    return b'\x00\x02' + filename.encode('ascii') + b'\x00' + b'octet' + b'\x00'


def create_ack_packet(block_num):
    return b'\x00\x04' + block_num.to_bytes(2, 'big')


def create_data_packet(block_num, data):
    return b'\x00\x03' + block_num.to_bytes(2, 'big') + data


def create_error_packet(error_code, error_msg):
    return b'\x00\x05' + error_code.to_bytes(2, 'big') + error_msg.encode('ascii') + b'\x00'


# 서버와 통신하는 함수
def send_request(server_ip, server_port, request_packet):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(TIMEOUT)
        sock.sendto(request_packet, (server_ip, server_port))
        try:
            response, _ = sock.recvfrom(516)  # 최대 516 바이트
            return response
        except socket.timeout:
            print("타임아웃 발생")
            return None


# 파일 다운로드 (GET)
def tftp_get(server_ip, server_port, filename):
    rrq_packet = create_rrq_packet(filename)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(TIMEOUT)
        sock.sendto(rrq_packet, (server_ip, server_port))

        with open(filename, 'wb') as f:
            block_num = 1
            retries = 3  # 타임아웃 재시도 횟수
            while retries > 0:
                try:
                    response, addr = sock.recvfrom(516)
                    opcode = int.from_bytes(response[:2], 'big')
                    recv_block_num = int.from_bytes(response[2:4], 'big')

                    if opcode == OPCODES['DATA'] and recv_block_num == block_num:
                        f.write(response[4:])
                        ack_packet = create_ack_packet(block_num)
                        sock.sendto(ack_packet, addr)

                        if len(response[4:]) < BUFFER_SIZE:
                            print("파일 다운로드 완료")
                            break

                        block_num += 1
                        retries = 3  # 재시도 횟수를 초기화
                    elif opcode == OPCODES['ERROR']:
                        error_code = int.from_bytes(response[2:4], 'big')
                        error_msg = response[4:-1].decode('ascii')
                        print(f"서버 오류 [{error_code}]: {error_msg}")
                        break
                except socket.timeout:
                    print("타임아웃 발생. 재시도 중...")
                    retries -= 1
                    if retries > 0:
                        sock.sendto(rrq_packet, (server_ip, server_port))
                    else:
                        print("재시도 횟수를 초과하여 다운로드를 중단합니다.")
                        break

# 파일 업로드 (PUT)
def tftp_put(server_ip, server_port, filename):
    wrq_packet = create_wrq_packet(filename)
    response = send_request(server_ip, server_port, wrq_packet)

    if not response:
        print("서버 응답 없음.")
        return

    block_num = 1
    with open(filename, 'rb') as f:
        while True:
            data = f.read(BUFFER_SIZE)
            if not data:
                break

            data_packet = create_data_packet(block_num, data)
            send_request(server_ip, server_port, data_packet)
            ack_packet = create_ack_packet(block_num)
            response = send_request(server_ip, server_port, ack_packet)

            if not response:
                print(f"블록 {block_num} 전송 중 타임아웃 발생")
                continue

            block_num += 1

    print("파일 업로드 완료")


# 커맨드라인 인자 처리
def main():
    parser = argparse.ArgumentParser(description="TFTP 클라이언트")
    parser.add_argument("host", help="TFTP 서버 IP 주소")
    parser.add_argument("action", choices=["get", "put"], help="동작: get 또는 put")
    parser.add_argument("filename", help="다운로드 또는 업로드할 파일 이름")
    parser.add_argument("-p", "--port", type=int, default=TFTP_PORT, help="서버 포트 번호 (기본값: 69)")

    args = parser.parse_args()

    server_ip = args.host
    server_port = args.port
    filename = args.filename
    action = args.action

    if action == "get":
        tftp_get(server_ip, server_port, filename)
    elif action == "put":
        tftp_put(server_ip, server_port, filename)


if __name__ == "__main__":
    main()