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

verbose = False
CONF_DIR = "directory containing certs. can be self-signed"

# global counters and mutexes
n_active_mutex = threading.Lock()
connect_mutex = threading.Lock()
n_crashes = 0
n_reqs_logged = 0
n_active = 0


def send_wrapped(sock, data, times):
    b4 = time.time()
    sock.send(data)
    times.append(time.time() - b4)
    #sock.send(data)


def recv_wrapped(sock, times):
    b4 = time.time()
    data = sock.recv()
    times.append(time.time() - b4)
    return data
    #return sock.recv()


def write_times(times):
    with connect_mutex:
        fd = open('/h2proxy_times.txt', 'a')
        fd.write(f'{times}\n')
        fd.close()


def restart_server():
    """
    Kills the upstream server and restarts it
    """
    global n_crashes
    global n_active

    # loop while we wait for any live threads to finish up
    while True:
        with n_active_mutex:
            if n_active > 0:
                time.sleep(1)
            else:
                break

    # copy last n requests to a new crash file
    os.rename('/last_reqs', '/crash_{}'.format(n_crashes))
    n_crashes += 1

    # kill proxy (or at least try to)
    pid = int(open('/proxy_pid', 'r').read())
    try:
        os.kill(pid, 9)
    except ProcessLookupError:
        pass

    # call run.sh to restart proxy and write PID to /proxy_pid
    retval = subprocess.call(['/run.sh'])
    if retval != 0:
        pass

    time.sleep(1)


def tls_setup_exchange(dn, port, use_insecure_ciphers=False):
    addr_info = socket.getaddrinfo(dn, port, socket.INADDR_ANY, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    s = socket.socket(addr_info[0][0], addr_info[0][1], addr_info[0][2])
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.settimeout(2)
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
    try:
        ssl_sock.connect(ip_and_port)
    except ConnectionRefusedError:
        # signal error to caller so that it can restart the server
        return None, -1

    assert ('h2' == ssl_sock.selected_alpn_protocol())
    scapy.config.conf.debug_dissector = True
    ssl_stream_sock = supersocket.SSLStreamSocket(ssl_sock, basecls=h2.H2Frame)
    return ssl_stream_sock, 0


def client_h2_handshake(sock):
    # RECEIVING MAGIC
    mgc = h2.H2Seq(sock.recv(1024))
    if (not mgc.frames) or mgc.frames[0].load != b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n':
        print('client did not send magic')
        return -1

    # receiving client's ACK
    cl_set = h2.H2Seq(sock.recv(1024))
    if (not cl_set.frames) or cl_set.frames[0] is None or cl_set.frames[0].type != h2.H2SettingsFrame.type_id:
        print('client did not send settings frame')
        return -1

    # send own settings and ACK to client's settings
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
    sock.send(raw(own_set))
    own_ack = h2.H2Frame(flags={'A'})/h2.H2SettingsFrame()
    sock.send(raw(own_ack))

    # REMOVED because FrameShifter doesn't actually send ack
    # receive ACK from client, then handshake is complete
    #cl_ack = h2.H2Seq(sock.recv(1024))
    #if ((not cl_ack.frames) or
    #        isinstance(cl_ack.frames[0], type(None)) or not (
    #        cl_ack.frames[0].type == h2.H2SettingsFrame.type_id
    #        and 'A' in cl_ack.frames[0].flags)):
    #    print('client did not ACK settings')
    #    return -1

    return 0


def server_h2_handshake(sock):
    # SENDING MAGIC
    magic = packet.Raw(h2.H2_CLIENT_CONNECTION_PREFACE)
    if verbose:
        print("-" * 32 + "SENDING" + "-" * 32)
        magic.show()
    sock.send(magic)

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
        try:
            sock.send(frame)
        except:
            return -1

    # RECEIVING SETTINGS
    srv_set = sock.recv()
    if verbose:
        print("-" * 32 + "RECEIVING" + "-" * 32)
        srv_set.show()

    # while loop for waiting until ack is received for client's settings
    new_frame = None
    while isinstance(new_frame, type(None)) or not (
            new_frame.type == h2.H2SettingsFrame.type_id
            and 'A' in new_frame.flags
    ):
        new_frame = sock.recv()
        if verbose:
            print("-" * 32 + "RECEIVING" + "-" * 32)
            new_frame.show()

    # SENDING ACK for servers's settings
    set_ack = h2.H2Frame(flags={'A'})/h2.H2SettingsFrame()
    sock.send(set_ack)
    return 0


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

    with connect_mutex:
        if n_reqs_logged == 128:
            n_reqs_logged = 0
            open_mode = 'wb'
        else:
            open_mode = 'ab'

        with open('/last_reqs', open_mode) as fd:
            fd.write(data)
            n_reqs_logged += 1


def proxy_handshakes(dn, port):
    """
    Connect to the proxy and perform the TLS and HTTP/2 handshakes, aborting and returning errors back to the caller
    if either handshake fails
    """
    sock, err = tls_setup_exchange(dn, port)
    if err != 0:
        return None, err
    err = server_h2_handshake(sock)
    if err != 0:
        return None, err
    return sock, 0


def proxy_robust_connect(dn, port):
    """
    Connect to the proxy at the given domain name and port, perform the TLS and HTTP/2 handshakes, and then
    return the socket for that connection.

    If the handshakes fail in a way that indicates that the proxy is unresponsive or dead, restart the proxy and
    then attempt to connect 10 times before aborting the program.
    """
    global n_active

    with connect_mutex:
        sock, err = proxy_handshakes(dn, port)
        if err == 0:
            with n_active_mutex:
                n_active += 1
            return sock
        else:
            restart_server()

            # try reconnecting 10 times before aborting
            for i in range(10):
                sock, err = proxy_handshakes(dn, port)
                if err != 0:
                    time.sleep(1)
                else:
                    with n_active_mutex:
                        n_active += 1
                    return sock

        # after failing 10 times, abort the program with an error message
        sys.exit('Could not connect to proxy after restarting it')


def handle_connection(conn):
    global n_active

    data = b''
    times = []
    try:
        conn.settimeout(0.5)

        # perform handshake with client
        err = client_h2_handshake(conn)
        if err != 0:
            conn.close()
            return

        # read data from the client
        while True:
            try:
                conn_data = conn.recv(4096)
                data += conn_data
            except:
                break

        if verbose:
            print("-"*32 + "RECEIVING" + "-"*32)
            show_maybe_h2(data)

        # connect to server and send data
        dn = sys.argv[2]
        port = int(sys.argv[3])
        sock = proxy_robust_connect(dn, port)
        sock.send(data)
        
        if verbose:
            print("-"*32 + "SENDING" + "-"*32)
            show_maybe_h2(data)

        # receive data from server or timeout
        serv_data = b''
        good_resp = False  # whether the response has a non-empty dataframe
        while True:
            before = time.time()
            new_frame = sock.recv()
            after = time.time()
            if verbose:
                print("-"*32 + "RECEIVING" + "-"*32)
                new_frame.show()
            serv_data += raw(new_frame)
            if not isinstance(new_frame, type(None)):
                #tdiff = after - before
                #times.append(tdiff)
                #if new_frame.type == h2.H2DataFrame.type_id and new_frame.len > 0 and not new_frame.data.startswith(b'<!DOCTYPE'):
                #    good_resp = True

                if 'ES' in new_frame.flags or new_frame.type == h2.H2GoAwayFrame.type_id or new_frame.type == h2.H2ResetFrame.type_id:
                    break

        conn.sendall(serv_data)
        conn.close()

        #if good_resp:
        #    write_times(times)

    except Exception as e:
        conn.close()
        if verbose:
            print(data)
            print("h2proxy exception in handle_connection: {}".format(e))

    # signal that we're done communicating with the SUT, so it can be reset
    with n_active_mutex:
        n_active -= 1

    # log this request in case it crashes the server
    # TODO maybe only log requests that time out, since they won't get a response back?
    #log_last_request(data)


if __name__ == '__main__':
    if len(sys.argv) < 4:
        print('usage: h2proxy.py <bind port> <upstream domain> <upstream port>')
        exit(1)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    ssl_mode = True
    if ssl_mode:
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

        ciphers = ['ECDHE-ECDSA-AES256-GCM-SHA384', 'ECDHE-RSA-AES256-GCM-SHA384', 'ECDHE-ECDSA-AES128-GCM-SHA256',
                   'ECDHE-RSA-AES128-GCM-SHA256', 'ECDHE-ECDSA-AES256-SHA384', 'ECDHE-RSA-AES256-SHA384',
                   'ECDHE-ECDSA-AES128-SHA256', 'ECDHE-RSA-AES128-SHA256', 'ECDHE-ECDSA-CAMELLIA256-SHA384',
                   'ECDHE-RSA-CAMELLIA256-SHA384', 'ECDHE-ECDSA-CAMELLIA128-SHA256', 'ECDHE-RSA-CAMELLIA128-SHA256',
                   'DHE-RSA-AES256-GCM-SHA384', 'DHE-RSA-AES128-GCM-SHA256', 'DHE-RSA-AES256-SHA256',
                   'DHE-RSA-AES128-SHA256', 'AES256-GCM-SHA384', 'AES128-GCM-SHA256', 'AES256-SHA256', 'AES128-SHA256',
                   'CAMELLIA128-SHA256']
        ssl_ctx.set_ciphers(':'.join(ciphers))
        ssl_ctx.set_alpn_protocols(['h2'])  # h2 is a RFC7540-hardcoded value
        ssl_ctx.load_cert_chain(keyfile=CONF_DIR+'server.key', certfile=CONF_DIR+'server.cert')
        sock = ssl_ctx.wrap_socket(s, server_side=True)
    else:
        sock = s

    sock.bind(('', int(sys.argv[1])))
    sock.listen()

    while True:
        try:
            conn, addr = sock.accept()
            thread = threading.Thread(target=handle_connection, args=(conn,))
            thread.start()
        except Exception as exception:
            if verbose:
                print("h2proxy exception in accept loop: {}".format(exception))
