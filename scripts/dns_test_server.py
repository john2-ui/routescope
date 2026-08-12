#!/usr/bin/env python3
import socket
import struct
import sys
import threading

TARGET_IP = socket.inet_aton(sys.argv[1])
TTL = 60


def make_response(query):
    if len(query) < 12:
        return b""

    offset = 12
    while offset < len(query):
        size = query[offset]
        offset += 1
        if size == 0:
            break
        if size & 0xC0 or offset + size > len(query):
            return b""
        offset += size

    question_end = offset + 4
    if question_end > len(query):
        return b""

    question = query[12:question_end]
    qtype, qclass = struct.unpack("!HH", query[question_end - 4:question_end])

    header = query[:2] + struct.pack("!HHHHH", 0x8180, 1, 0, 0, 0)

    if qtype != 1 or qclass != 1:
        return header + question

    answer = (
        b"\xc0\x0c"
        + struct.pack("!HHIH", 1, 1, TTL, 4)
        + TARGET_IP
    )
    return query[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + question + answer


def read_exact(stream, size):
    data = b""
    while len(data) < size:
        chunk = stream.recv(size - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def serve_udp(sock):
    while True:
        query, address = sock.recvfrom(4096)
        response = make_response(query)
        if response:
            sock.sendto(response, address)


def serve_tcp_client(conn):
    with conn:
        while True:
            length = read_exact(conn, 2)
            if not length:
                return

            query_length = struct.unpack("!H", length)[0]
            query = read_exact(conn, query_length)
            if not query:
                return

            response = make_response(query)
            conn.sendall(struct.pack("!H", len(response)) + response)


def serve_tcp(sock):
    while True:
        conn, _ = sock.accept()
        threading.Thread(
            target=serve_tcp_client,
            args=(conn,),
            daemon=True,
        ).start()


udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
udp_socket.bind(("0.0.0.0", 53))

tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
tcp_socket.bind(("0.0.0.0", 53))
tcp_socket.listen(16)

threading.Thread(target=serve_udp, args=(udp_socket,), daemon=True).start()
threading.Thread(target=serve_tcp, args=(tcp_socket,), daemon=True).start()

print("routescope-dns-server-ready", flush=True)
threading.Event().wait()