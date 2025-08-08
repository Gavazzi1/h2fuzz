import threading
import socket
import ssl
import sys
import os
import subprocess
import time

import scapy.supersocket as supersocket
import scapy.contrib.http2 as h2
import scapy.config
import scapy.packet as packet
from scapy.all import raw

verbose = True
mutex = threading.Lock()

if len(sys.argv) < 4:
    print('usage: h2proxy.py <bind port> <upstream domain> <upstream port>')
    exit(1)

n_crashes = 0
n_reqs_logged = 0

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('', int(sys.argv[1])))
s.listen()


def restart_server_and_connect(ssl_sock, ip_and_port):
    """
    Kills the upstream server and restarts it
    """
    global n_crashes
    print('restarting server')

    # copy last n requests to a new crash file
    os.rename('/last_reqs', '/crash_{}'.format(ncrashes))
    ncrashes += 1
    print('created crash file')

    # kill proxy (or at least try to)
    pid = int(open('/proc_pid', 'r').read())
    print('obtained process pid {}'.format(pid))
    try:
        os.kill(pid, 9)
    except ProcessLookupError:
        pass
    except:
        raise
    print('attempted to kill process')

    # call run.sh to restart proxy and write PID to /proxy_pid
    print('calling run.sh')
    retval = subprocess.call(['/bin/bash', '/run.sh'])
    if retval != 0:
        print('run.sh returned {}'.format(retval))
        pass

    # wait to proxy to start, then reconnect
    print('waiting 1s')
    time.sleep(1)
    for _ in range(5):
        try:
            print('attempting connection again')
            ssl_sock.connect(ip_and_port)
            print('success')
            return
        except ConnectionRefusedError:
            pass
        except: 
            pass

    # restart failed -- abort
    sys.exit('Could not connect to proxy after restarting')


def tls_setup_exchange(dn, port, use_insecure_ciphers=False):
    addr_info = socket.getaddrinfo(dn, port, socket.INADDR_ANY, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    s = socket.socket(addr_info[0][0], addr_info[0][1], addr_info[0][2])
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.settimeout(5)
    if hasattr(socket, 'SO_REUSEPORT'):
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

    ip_and_port = addr_info[0][4]

    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    if use_insecure_ciphers:
        ciphers = ['AES256-GCM-SHA384', 'AES128-GCM-SHA256', 'AES256-SHA256', 'AES128-SHA256', 'CAMELLIA128-SHA256']
    else:
        ciphers = ['ECDHE-ECDSA-AES256-GCM-SHA384', 'ECDHE-RSA-AES256-GCM-SHA384', 'ECDHE-ECDSA-AES128-GCM-SHA256',
                   'ECDHE-RSA-AES128-GCM-SHA256', 'ECDHE-ECDSA-AES256-SHA384', 'ECDHE-RSA-AES256-SHA384',
                   'ECDHE-ECDSA-AES128-SHA256', 'ECDHE-RSA-AES128-SHA256', 'ECDHE-ECDSA-CAMELLIA256-SHA384',
                   'ECDHE-RSA-CAMELLIA256-SHA384', 'ECDHE-ECDSA-CAMELLIA128-SHA256', 'ECDHE-RSA-CAMELLIA128-SHA256',
                   'DHE-RSA-AES256-GCM-SHA384', 'DHE-RSA-AES128-GCM-SHA256', 'DHE-RSA-AES256-SHA256',
                   'DHE-RSA-AES128-SHA256', 'AES256-GCM-SHA384', 'AES128-GCM-SHA256', 'AES256-SHA256', 'AES128-SHA256',
                   'CAMELLIA128-SHA256']
    ssl_ctx.set_ciphers(':'.join(ciphers))
    ssl_ctx.set_alpn_protocols(['h2'])  # h2 is a RFC7540-hardcoded value

    ssl_sock = ssl_ctx.wrap_socket(s, server_hostname=dn)
    with mutex:
        try:
            ssl_sock.connect(ip_and_port)
        except ConnectionRefusedError:
            restart_server_and_connect(ssl_sock, ip_and_port)

    assert ('h2' == ssl_sock.selected_alpn_protocol())
    scapy.config.conf.debug_dissector = True
    ssl_stream_sock = supersocket.SSLStreamSocket(ssl_sock, basecls=h2.H2Frame)
    return ssl_stream_sock


def send_wrapped(sock, data, times):
    #b4 = time.time()
    #sock.send(data)
    #times.append(time.time() - b4)
    sock.send(data)


def recv_wrapped(sock, times):
    #b4 = time.time()
    #data = sock.recv()
    #times.append(time.time() - b4)
    #return data
    return sock.recv()


def write_times(times):
    with mutex:
        fd = open('/h2proxy_times.txt', 'a')
        fd.write(f'{times}\n')
        fd.close()


def initial_h2_exchange(sock, times):
    # SENDING MAGIC
    magic = packet.Raw(h2.H2_CLIENT_CONNECTION_PREFACE)
    if verbose:
        print("-" * 32 + "SENDING" + "-" * 32)
        magic.show()
    send_wrapped(sock, magic, times)

    # SENDING SETTINGS
    own_set = h2.H2Frame() / h2.H2SettingsFrame()
    max_frm_sz = (1 << 24) - 1
    max_hdr_tbl_sz = (1 << 16) - 1
    win_sz = (1 << 31) - 1
    own_set.settings = [
        h2.H2Setting(id=h2.H2Setting.SETTINGS_ENABLE_PUSH, value=0),
        h2.H2Setting(id=h2.H2Setting.SETTINGS_INITIAL_WINDOW_SIZE, value=win_sz),
        h2.H2Setting(id=h2.H2Setting.SETTINGS_HEADER_TABLE_SIZE, value=max_hdr_tbl_sz),
        h2.H2Setting(id=h2.H2Setting.SETTINGS_MAX_FRAME_SIZE, value=max_frm_sz),
    ]

    h2seq = h2.H2Seq()
    h2seq.frames = [own_set]
    for frame in h2seq.frames:
        if verbose:
            print("-" * 32 + "SENDING" + "-" * 32)
            frame.show()
        send_wrapped(sock, frame, times)

    # RECEIVING SETTINGS
    srv_set = recv_wrapped(sock, times)
    if verbose:
        print("-" * 32 + "RECEIVING" + "-" * 32)
        srv_set.show()

    # while loop for waiting until ack is received for client's settings
    new_frame = None
    while isinstance(new_frame, type(None)) or not (
            new_frame.type == h2.H2SettingsFrame.type_id
            and 'A' in new_frame.flags
    ):
        new_frame = recv_wrapped(sock, times)
        if verbose:
            print("-" * 32 + "RECEIVING" + "-" * 32)
            new_frame.show()

    # SENDING ACK for servers's settings
    set_ack = h2.H2Frame(flags={'A'})/h2.H2SettingsFrame()
    send_wrapped(sock, set_ack, times)


def show_maybe_h2(data):
    try:
        pkt = h2.H2Frame(data)
        pkt.show()
    except:
        print(data)


def log_last_request(data):
    """
    Logs the given data in /last_reqs to help with crashing-input detection

    Also clears the file contents if more than 128 requests are stored in it. This helps quicken detection of the
    crashing input and limits the docker container size
    """
    global n_reqs_logged

    with mutex:
        if n_reqs_logged == 128:
            n_reqs_logged = 0
            open_mode = 'wb'
        else:
            open_mode = 'ab'

        with open('/last_reqs', open_mode) as fd:
            fd.write(data)
            n_reqs_logged += 1


def handle_connection(conn):
    data = b''
    times = []
    try:
        #conn.settimeout(5)

        # read data from the client
        conn_data = conn.recv(4096)
        data += conn_data

        if verbose:
            print("-"*32 + "RECEIVING" + "-"*32)
            show_maybe_h2(data)

        # connect to server and send data
        dn = sys.argv[2]
        port = int(sys.argv[3])
        sock = tls_setup_exchange(dn, port)
        initial_h2_exchange(sock, times)
        send_wrapped(sock, data, times)
        
        if verbose:
            print("-"*32 + "SENDING" + "-"*32)
            show_maybe_h2(data)

        # receive data from server or timeout
        serv_data = b''
        while True:
            new_frame = recv_wrapped(sock, times)
            if verbose:
                print("-"*32 + "RECEIVING" + "-"*32)
                new_frame.show()
            serv_data += raw(new_frame)
            if not isinstance(new_frame, type(None)):
                if 'ES' in new_frame.flags or new_frame.type == h2.H2GoAwayFrame.type_id or new_frame.type == h2.H2ResetFrame.type_id:
                    break

        conn.sendall(serv_data)
        conn.close()
        write_times(times)

    except Exception as e:
        conn.close()
        write_times(times)
        if verbose:
            print(data)
            print("h2proxy exception in handle_connection: {}".format(e))

    # log this request in case it crashes the server
    # TODO maybe only log requests that time out, since they won't get a response back?
    log_last_request(data)


if __name__ == '__main__':
    while True:
        try:
            conn, addr = s.accept()
            thread = threading.Thread(target=handle_connection, args=(conn,))
            thread.start()
        except Exception as exception:
            if verbose:
                print("h2proxy exception in accept loop: {}".format(exception))
