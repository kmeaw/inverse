package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/sha3"
	"golang.org/x/crypto/ssh"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/chzyer/readline"
)

type Host struct {
	name      string
	keys      []ssh.PublicKey
	hostnames []string
	verified  bool

	sync.Mutex
}

type HostMap struct {
	m    map[string]*Host
	m_fp map[string]*Host
	sync.RWMutex

	partial []byte
	reading bool
}

func genHostId(addr string, user string) string {
	mac := hmac.New(sha3.New224, []byte("SECRET")) // FIXME secret
	mac.Write([]byte(addr))
	return url.PathEscape(user) + "@" + hex.EncodeToString(mac.Sum(nil))
}

func (h *HostMap) Get(name string) *Host {
	h.RLock()
	h.RUnlock()

	return h.m[name]
}

func (h *HostMap) Lookup(user string, pubkey ssh.PublicKey) *Host {
	h.RLock()
	defer h.RUnlock()

	return h.m_fp[url.PathEscape(user)+"/"+string(ssh.MarshalAuthorizedKey(pubkey))]
}

func (h *HostMap) Add(host *Host) {
	h.Lock()
	defer h.Unlock()

	host.Lock()
	defer host.Unlock()

	if h.m == nil {
		h.m = make(map[string]*Host)
	}

	idx := strings.IndexRune(host.name, '@')
	if idx != -1 {
		if h.m_fp == nil {
			h.m_fp = make(map[string]*Host)
		}
		for _, key := range host.keys {
			h.m_fp[host.name[0:idx]+"/"+string(ssh.MarshalAuthorizedKey(key))] = host
		}
	}

	h.m[host.name] = host
	host.verified = true
}

func (h *HostMap) Write(in []byte) (int, error) {
	h.Lock()
	defer h.Unlock()

	h.m = make(map[string]*Host)
	h.m_fp = make(map[string]*Host)
	s := -len(h.partial)

	in = append(append([]byte{}, h.partial...), in...)

	idx := bytes.LastIndexAny(in, "\r\n")
	if idx != -1 && idx != len(in)-1 {
		h.partial = in[idx:]
		in = in[0:idx]
	} else {
		h.partial = nil
	}

	for len(in) > 0 {
		_, hosts, pubkey, comment, rest, err := ssh.ParseKnownHosts(in)
		if err == nil {
		} else if err == io.EOF {
			h.partial = append(h.partial, in...)
			break
		} else {
			return s, err
		}

		s += len(in) - len(rest)
		in = rest

		if len(comment) == 0 {
			comment = genHostId(hosts[0], "root")
		}

		host, ok := h.m[comment]
		if !ok {
			host = &Host{
				name: comment,
				keys: make([]ssh.PublicKey, 0, 1),

				hostnames: make([]string, 0, len(hosts)),
				verified:  true,
			}
			h.m[comment] = host
		}

		host.keys = append(host.keys, pubkey)
		host.hostnames = append(host.hostnames, hosts...)

		idx := strings.IndexRune(comment, '@')
		if idx != -1 {
			h.m_fp[comment[0:idx]+"/"+string(ssh.MarshalAuthorizedKey(pubkey))] = host
		}
	}

	s += len(h.partial)

	if s < 0 {
		return 0, nil
	}

	return s, nil
}

func (h *HostMap) writeToUnlocked(w io.Writer) (s int, err error) {
	var n int

	for comment, host := range h.m {
		for _, k := range host.keys {
			n, err = fmt.Fprintf(w, "%s %s %s\n",
				strings.Join(host.hostnames, ","),
				bytes.TrimSpace(ssh.MarshalAuthorizedKey(k)),
				comment,
			)

			s += n

			if err != nil {
				return
			}
		}
	}

	return
}

func (h *HostMap) WriteTo(w io.Writer) (int, error) {
	h.Lock()
	defer h.Unlock()

	return h.writeToUnlocked(w)
}

func (h *HostMap) Read(out []byte) (int, error) {
	h.Lock()
	defer h.Unlock()

	if len(h.partial) > 0 {
		n := copy(out, h.partial)
		h.partial = h.partial[n:]
		return n, nil
	}

	if h.reading && len(h.partial) == 0 {
		h.reading = false
		return 0, io.EOF
	}

	buf := new(bytes.Buffer)
	n, err := h.writeToUnlocked(buf)
	h.reading = true

	if err != nil {
		return 0, err
	}

	c := copy(out, buf.Bytes())

	if n <= len(out) {
		return c, nil
	}

	h.partial = make([]byte, n-c)
	copy(h.partial, buf.Bytes()[c:])

	return c, nil
}

func (session *Session) handle() {
	session.Lock()
	defer session.Unlock()

	if session.handled {
		log.Printf("Session.handle called twice!\n")
		return
	}
	session.handled = true

	session.forwards.RLock()
	defer session.forwards.RUnlock()

	if _, ok := session.forwards.m[22]; !ok {
		fmt.Fprintf(session.ch, "Uh, oh, you forgot to forward port 22 to your host.\r\n")
		fmt.Fprintf(session.ch, "Please re-run your SSH client with -R 22:localhost:22\r\n")
		session.ch.Close()
	}
}

type channelForwardMsg struct {
	Laddr string
	Port  uint32
}

type channelForwardMsgReply struct {
	Port uint32
}

type forwardedTCPIP struct {
	Addr       string
	Port       uint32
	OriginAddr string
	OriginPort uint32
}

type ptyRequestMsg struct {
	Term     string
	Columns  uint32
	Rows     uint32
	Width    uint32
	Height   uint32
	Modelist string
}

type Session struct {
	server   *ssh.ServerConn
	start    time.Time
	host     *Host
	ch       ssh.Channel
	term     ptyRequestMsg
	pty      bool
	handled  bool
	forwards *Forwards
	cancel   context.CancelFunc
	isReady  bool

	sync.Mutex
}

type Forward struct {
	laddr string
	lport int
	rport uint32
	tcp   *net.TCPListener
}

type Forwards struct {
	m map[uint32]*Forward

	sync.RWMutex
	context context.Context
}

func hostKeyCallback(hosts *HostMap, session *Session) func(hostname string, remote net.Addr, key ssh.PublicKey) error {
	session.Lock()
	defer session.Unlock()

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		session.Lock()
		defer session.Unlock()

		if session.host == nil {
			session.host = hosts.Lookup(session.server.User(), key)
		}

		if session.host != nil {
			session.host.Lock()
			defer session.host.Unlock()

			if session.host.verified {
				for _, k := range session.host.keys {
					if hmac.Equal(k.Marshal(), key.Marshal()) {
						return nil
					}
				}

				session.host.keys = append(session.host.keys, key)
				return nil
			}

			host := hosts.Lookup(session.server.User(), key)
			if host != nil {
				for _, k := range session.host.keys {
					found := false
					for _, k1 := range host.keys {
						if hmac.Equal(k.Marshal(), k1.Marshal()) {
							found = true
							break
						}
					}
					if !found {
						host.keys = append(host.keys, k)
					}
				}

				session.host = host
			}

			return nil
		} else {
			remote_addr := session.server.Conn.RemoteAddr().String()
			session.host = &Host{
				hostnames: []string{remote_addr},
				name:      genHostId(remote_addr, session.server.User()),
				keys:      []ssh.PublicKey{key},
			}
			return nil
		}
	}
}

type InternalConn struct {
	ssh.Channel
}

type InternalAddr struct{}

func (a InternalAddr) Network() string {
	return "internal"
}

func (a InternalAddr) String() string {
	return "ssh"
}

func (c InternalConn) LocalAddr() net.Addr {
	return InternalAddr{}
}

func (c InternalConn) RemoteAddr() net.Addr {
	return InternalAddr{}
}

func (c InternalConn) SetDeadline(t time.Time) error {
	return nil
}

func (c InternalConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c InternalConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func DiscardRequests(label string, reqs <-chan *ssh.Request) {
	for req := range reqs {
		log.Printf("%s: discarding request %#v\n", label, req)
		if req.WantReply {
			req.Reply(false, nil)
		}
	}
}

var ErrVerificationFailed = fmt.Errorf("host key verification failed")

func (session *Session) verify(hosts *HostMap) error {
	// session is locked

	keyTypes := map[string]string{
		"ssh-rsa":          "RSA",
		"ssh-dss":          "DSA",
		"ssh-ed25519":      "ED25519",
		"ecdsa-sha2-nistp": "ECDSA",
	}

	if session.host.verified {
		return nil
	}

	addr := session.server.Conn.RemoteAddr().String()
	addedTypes := make([]string, 0, len(session.host.keys))
	fmt.Fprintf(session.ch, "The authenticity of host '%s' can't be established.\r\n", addr)

	uniqTypes := make(map[string]bool)
	for _, k := range session.host.keys {
		t := keyTypes[k.Type()]
		if t == "" {
			idx := strings.IndexRune(t, '-')
			if idx != -1 {
				t = strings.ToUpper(t[idx+1:])
			} else {
				t = strings.ToUpper(t)
			}
		}
		if !uniqTypes[t] {
			uniqTypes[t] = true
			addedTypes = append(addedTypes, t)
		}
		fmt.Fprintf(session.ch, "%s key fingerprint is %s.\r\n",
			t,
			ssh.FingerprintSHA256(k),
		)
	}

	rl, err := readline.NewEx(&readline.Config{
		Prompt:                 "Are you sure you want to continue connecting (yes/no)? ",
		DisableAutoSaveHistory: true,
		FuncGetWidth: func() int {
			return int(session.term.Width)
		},
		Stdin:       session.ch,
		StdinWriter: session.ch,
		Stdout:      session.ch,
		Stderr:      session.ch.Stderr(),
		FuncIsTerminal: func() bool {
			return session.pty
		},
		FuncMakeRaw: func() error {
			return nil
		},
		FuncExitRaw: func() error {
			return fmt.Errorf("cannot exit raw mode")
		},
		FuncOnWidthChanged: func(cb func()) {
			// FIXME
		},
		ForceUseInteractive: true,
	})
	if err != nil {
		log.Printf("verify: readline: %s\n", err)
		return err
	}
	defer rl.Close()

	for {
		yesno, err := rl.Readline()
		if err != nil {
			if err == readline.ErrInterrupt {
				session.ch.Write([]byte("\r"))
			}
			log.Printf("verify: cannot read confirmation: %s\n", err)
			return err
		}

		if yesno == "yes" {
			break
		} else if yesno == "no" {
			fmt.Fprintf(session.ch, "\rHost key verification failed.\r\n\r\n")
			return ErrVerificationFailed
		} else {
			rl.SetPrompt("Please type 'yes' or 'no': ")
		}
	}
	session.ch.Write([]byte("\r"))
	fmt.Fprintf(session.ch, "\rWarning: Permanently added '%s' (%s) to the list of known hosts.\r\n",
		addr, strings.Join(addedTypes, ","))

	hosts.Add(session.host)

	hosts_file, err := os.OpenFile("known_hosts", os.O_WRONLY|os.O_CREATE, 0600)
	if err == nil {
		_, err = io.Copy(hosts_file, hosts)
	}

	if err != nil {
		fmt.Fprintf(session.ch.Stderr(), "Failed to add the host to the list of known hosts.\r\n")
		log.Printf("write to known_hosts: %s\n", err)
		if hosts_file != nil {
			hosts_file.Close()
		}
		return err
	}

	return nil
}

// FIXME: refactor: (f *Forward) Start(session *Session)
func forwardPort(tcp *net.TCPListener, laddr string, port uint32, session *Session) {
	go func() {
		<-session.forwards.context.Done()
		tcp.Close()
	}()

	for {
		conn, err := tcp.AcceptTCP()
		if err != nil {
			log.Printf("cannot accept connection: %s\n", err)
			if ! strings.Contains(err.Error(), "use of closed network connection") {
				fmt.Fprintf(session, "accept (port %d) failed: %s\r\n", port, err)
			}
			break
		}

		t := conn.RemoteAddr().(*net.TCPAddr)
		log.Printf("Accepted connection from %s, requesting remote port %d...\n", t, port)

		session.Lock()
		ch, reqs, err := session.server.OpenChannel("forwarded-tcpip", ssh.Marshal(forwardedTCPIP{
			Addr:       laddr,
			Port:       port,
			OriginAddr: t.IP.String(),
			OriginPort: uint32(t.Port),
		}))
		session.Unlock()
		if err != nil {
			log.Println(err)
			return
		}

		log.Printf("Connection to SSH:%d has been established.\n", port)

		go DiscardRequests("forwardPort", reqs)

		errChan := make(chan error, 1)
		errChan2 := make(chan error, 1)
		done := make(chan struct{})

		go func() {
			_, err := io.Copy(conn, ch)
			conn.Close()
			ch.Close()
			errChan <- err
		}()

		go func() {
			_, err := io.Copy(ch, conn)
			conn.Close()
			ch.Close()
			errChan2 <- err
		}()

		go func() {
			select {
			case <-session.forwards.context.Done():
				conn.Close()
				ch.Close()
			case <-done:
			}
		}()

		if err = <-errChan; err != nil {
			log.Printf("error during ssh to tcp copy: %s\n", err)
		}
		if err = <-errChan2; err != nil {
			log.Printf("error during tcp to ssh copy: %s\n", err)
		}

		done <- struct{}{}
	}

	tcp.Close()
}

func (forwards *Forwards) Start(session *Session) error {
	forwards.Lock()
	defer forwards.Unlock()

	for _, fwd := range forwards.m {
		err := fwd.Start(session)
		if err != nil {
			return err
		}
	}

	return nil
}

func (forwards *Forwards) Print(session *Session) {
	forwards.RLock()
	defer forwards.RUnlock()

	for _, fwd := range session.forwards.m {
		fwd.Print(session)
	}
}

func (fwd *Forward) Print(session *Session) {
	fmt.Fprintf(session.ch, "TCP:%d -> SSH:%d\r\n", fwd.lport, fwd.rport)
}

func (forward *Forward) Start(session *Session) error {
	tcp, err := net.ListenTCP("tcp", &net.TCPAddr{})
	if err != nil {
		log.Printf("cannot open listening socket: %s\n", err)
		return err
	}

	forward.lport = tcp.Addr().(*net.TCPAddr).Port
	forward.tcp = tcp
	go forwardPort(tcp, forward.laddr, forward.rport, session)

	return nil
}

func (forward *Forward) Stop() error {
	return forward.tcp.Close()
}

func (session *Session) ready(hosts *HostMap) {
	session.Lock()
	defer session.Unlock()

	if session.isReady {
		return
	}

	log.Println("Ready.")

	was_verified := session.host.verified
	if !was_verified && session.ch == nil {
		log.Println("cannot verify remote host: no channels")
		return
	}

	err := session.verify(hosts)
	if err != nil {
		log.Println(err)
		if session.ch != nil {
			session.ch.Close()
		}
		return
	}

	err = session.forwards.Start(session)

	if err != nil {
		log.Println(err)
		if session.ch != nil {
			session.ch.Close()
		}
		return
	}

	if session.ch == nil {
		log.Println("Entering non-interactive mode.")
		return
	}

	if was_verified {
		idx := strings.IndexRune(session.host.name, '@')
		if idx == -1 {
			idx = len(session.host.name)
		}
		fmt.Fprintf(session.ch, "Welcome back, %s!\r\n", session.host.name[0:idx])
	} else {
		fmt.Fprintf(session.ch, "Nice to meet you, %s!\r\n", session.server.User())
	}

	session.forwards.Print(session)

	session.isReady = true
}

func (session *Session) Wait() (err error) {
	session.Lock()
	ch := session.ch
	session.Unlock()

	if ch == nil {
		return
	}

	for buf := []byte{0}; err == nil; _, err = ch.Read(buf) {
		if buf[0] == '\003' {
			// interrupt
			session.ch.Write([]byte("^C\r\n"))
			break
		}
	}

	if err != nil {
		log.Printf("read error: %s\n", err)
	}

	session.Lock()
	session.cancel()
	session.ch.Close()
	session.Unlock()

	return
}

func (session *Session) Write(p []byte) (int, error) {
	session.Lock()
	defer session.Unlock()

	if session.ch == nil {
		return 0, io.ErrClosedPipe
	}

	return session.ch.Write(p)
}

func (session *Session) Close() error {
	session.Lock()
	defer session.Unlock()

	if session.ch == nil {
		return session.server.Close()
	}

	return session.ch.Close()
}

func (session *Session) handlePortForward(hosts *HostMap, msg channelForwardMsg) {
	fwd := &Forward{laddr: msg.Laddr, rport: msg.Port}

	session.Lock()
	session.forwards.Lock()
	session.forwards.m[msg.Port] = fwd
	session.forwards.Unlock()
	session.Unlock()

	log.Printf("-R %s:%d\n", msg.Laddr, msg.Port)

	switch msg.Port {
	case 22:
		session.Lock()
		ch, reqs, err := session.server.OpenChannel("forwarded-tcpip", ssh.Marshal(forwardedTCPIP{
			Addr:       msg.Laddr,
			Port:       msg.Port,
			OriginAddr: "localhost",
			OriginPort: 22,
		}))
		session.Unlock()
		if err != nil {
			log.Println(err)
			session.Close()
			return
		}
		defer ch.Close()

		go DiscardRequests("forwarded-tcpip", reqs)
		session.Lock()
		t := time.Since(session.start)
		if t < time.Second {
			t = time.Second
		}
		session.Unlock()
		clientConfig := &ssh.ClientConfig{
			Timeout:         t,
			User:            "validate-host-key",
			HostKeyCallback: hostKeyCallback(hosts, session),
		}
		conn, _, _, err := ssh.NewClientConn(InternalConn{ch}, "internal", clientConfig)
		if err != nil && !strings.Contains(err.Error(), "unable to authenticate") {
			log.Printf("client error: %s\n", err)
			if conn != nil {
				conn.Close()
			}
			fmt.Fprintf(session, "ssh client: error: %s\n", err)
			session.Close()
		} else if conn != nil {
			conn.Close()
		}

		session.ready(hosts)
		session.Wait()
		return
	}

	if session.isReady {
		err := fwd.Start(session)
		if err == nil {
			fwd.Print(session)
		} else {
			fmt.Fprintf(session, "error: %s\n", err)
		}
	}
}

func (session *Session) handlePortForwardCancel(hosts *HostMap, msg channelForwardMsg) {
	session.Lock()
	session.forwards.Lock()
	fwd := session.forwards.m[msg.Port]
	old_port := fwd.lport
	delete(session.forwards.m, msg.Port)
	session.forwards.Unlock()
	session.Unlock()

	log.Printf("-KR %s:%d\n", msg.Laddr, msg.Port)
	fwd.Stop()
	fmt.Fprintf(session.ch, "TCP:%d -> closed\r\n", old_port)
}

func (session *Session) handleConnRequests(hosts *HostMap, in <-chan *ssh.Request) {
	for req := range in {
		switch req.Type {
		case "tcpip-forward":
			msg := channelForwardMsg{}
			err := ssh.Unmarshal(req.Payload, &msg)
			if err != nil {
				log.Printf("cannot unmarshal channelForwardMsg: %s\n", err)
				req.Reply(false, nil)
				return
			}
			req.Reply(true, ssh.Marshal(channelForwardMsgReply{0}))
			go session.handlePortForward(hosts, msg)
		case "keepalive@openssh.com":
			if req.WantReply {
				req.Reply(false, nil)
			}
		case "cancel-tcpip-forward":
			msg := channelForwardMsg{}
			err := ssh.Unmarshal(req.Payload, &msg)
			if err != nil {
				log.Printf("cannot unmarshal channelForwardMsg: %s\n", err)
				req.Reply(false, nil)
				return
			}
			req.Reply(true, ssh.Marshal(channelForwardMsgReply{0}))
			go session.handlePortForwardCancel(hosts, msg)
		default:
			log.Printf("handleConnRequests: discarding request %#v\n", req)
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}

	log.Println("No more connection requests.")
}

// RFC 4254 Section 6.7.
type ptyWindowChangeMsg struct {
	Columns uint32
	Rows    uint32
	Width   uint32
	Height  uint32
}

func (session *Session) handleWinCh(msg ptyWindowChangeMsg) {
	// session is locked
	session.term.Columns = msg.Columns
	session.term.Rows = msg.Rows
	session.term.Width = msg.Width
	session.term.Height = msg.Height
}

func (session *Session) handleRequests(reqs <-chan *ssh.Request) {
	for req := range reqs {
		switch req.Type {
		case "env":
			if req.WantReply {
				req.Reply(true, nil)
			}
		case "shell":
			log.Println("shell")
			if req.WantReply {
				req.Reply(true, nil)
			}
			session.handle()
		case "exec":
			log.Printf("exec %q\n", req.Payload)
			if req.WantReply {
				req.Reply(true, nil)
			}
			session.handle()
		case "pty-req":
			msg := ptyRequestMsg{}
			err := ssh.Unmarshal(req.Payload, &msg)
			if err != nil {
				log.Printf("cannot unmarshal ptyRequestMsg: %s\n", err)
				if req.WantReply {
					req.Reply(false, nil)
				}
			} else if req.WantReply {
				req.Reply(true, nil)
				session.Lock()
				session.pty = true
				session.term = msg
				session.Unlock()
				log.Printf("pty-req: %#v\n", msg)
			}
		case "window-change":
			session.Lock()
			if session.handleWinCh != nil {
				msg := ptyWindowChangeMsg{}
				err := ssh.Unmarshal(req.Payload, &msg)
				if err != nil {
					log.Printf("cannot unmarshal ptyWindowChangeMsg: %s\n", err)
					if req.WantReply {
						req.Reply(false, nil)
					}
				} else if req.WantReply {
					session.handleWinCh(msg)
					req.Reply(true, nil)
				}
			}
			session.Unlock()
		default:
			log.Printf("Session.handleRequests: discarding request %#v\n", req)
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}

func (session *Session) handleChannel(c ssh.NewChannel) {
	switch c.ChannelType() {
	case "session":
		ch, reqs, err := c.Accept()
		if err != nil {
			log.Printf("cannot accept session: %s\n", err)
			return
		}

		session.Lock()
		session.ch = ch
		session.Unlock()
		go session.handleRequests(reqs)

	default:
		log.Printf("Rejecting channel request, type=%s\n", c.ChannelType())
		c.Reject(ssh.UnknownChannelType, "not implemented")
	}
}

func handleConn(s net.Conn, hosts *HostMap, config ssh.ServerConfig) error {
	server, chans, reqs, err := ssh.NewServerConn(s, &config)
	if err != nil {
		log.Printf("cannot accept SSH connection from %s: %s\n", s.RemoteAddr(), err)
		s.Close()
		return err
	}

	defer server.Close()

	log.Printf("Client connected from %s.\n", s.RemoteAddr())

	host := hosts.Get(server.User())

	session := &Session{
		server: server,
		forwards: &Forwards{
			m: make(map[uint32]*Forward),
		},
		start: time.Now(),
		host:  host,
		term: ptyRequestMsg{
			Term:    "vt100",
			Rows:    24,
			Columns: 80,
		},
	}
	session.forwards.context, session.cancel = context.WithCancel(context.Background())

	go session.handleConnRequests(hosts, reqs)

	for newChannel := range chans {
		go session.handleChannel(newChannel)
	}

	log.Printf("Client disconnected (%s).\n", s.RemoteAddr())

	return nil
}

func listenAndServe(hosts *HostMap, config ssh.ServerConfig) error {
	tcp, err := net.Listen("tcp", ":2200")
	if err != nil {
		return err
	}

	defer tcp.Close()

	for {
		s, err := tcp.Accept()
		if err != nil {
			return err
		}

		go handleConn(s, hosts, config)
	}

	return nil
}

var CONFIG = ssh.Config{
	KeyExchanges: []string{
		"curve25519-sha256@libssh.org",
		"diffie-hellman-group-exchange-sha256",
	},
	Ciphers: []string{
		"chacha20-poly1305@openssh.com",
		"aes256-gcm@openssh.com",
		"aes128-gcm@openssh.com",
		"aes256-ctr",
		"aes192-ctr",
		"aes128-ctr",
	},
	MACs: []string{"hmac-sha2-256"},
}

func main() {
	hosts := &HostMap{}
	hosts_file, err := os.Open("known_hosts")
	if err != nil && !os.IsNotExist(err) {
		panic(err)
	}

	if !os.IsNotExist(err) {
		_, err = io.Copy(hosts, hosts_file)
		if err != nil {
			panic(err)
		}
	}

	hosts_file.Close()

	server_config := ssh.ServerConfig{
		NoClientAuth:  true,
		ServerVersion: "SSH-2.0-inverse",
		Config:        CONFIG,
	}

	k := 0

	dir, err := ioutil.ReadDir(".")
	for _, file := range dir {
		if !file.Mode().IsRegular() {
			continue
		}
		if !strings.HasPrefix(file.Name(), "id_") && !strings.Contains(file.Name(), "ssh_host_") {
			continue
		}
		if strings.HasSuffix(file.Name(), ".pub") {
			continue
		}
		b, err := ioutil.ReadFile(file.Name())
		if err != nil {
			log.Printf("cannot read %s: %s\n", file.Name(), err)
			continue
		}

		private, err := ssh.ParsePrivateKey(b)
		if err != nil {
			log.Printf("cannot parse key %s: %s\n", file.Name(), err)
			continue
		}

		server_config.AddHostKey(private)

		k = k + 1
	}

	if k == 0 {
		panic("ssh: no server keys")
	}

	panic(listenAndServe(hosts, server_config))
}

// vim: ai:ts=8:sw=8:noet:syntax=go
