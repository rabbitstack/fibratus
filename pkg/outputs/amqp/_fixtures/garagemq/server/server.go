package server

import (
	"github.com/rabbitstack/fibratus/pkg/outputs/amqp/_fixtures/garagemq/amqp"
	"github.com/rabbitstack/fibratus/pkg/outputs/amqp/_fixtures/garagemq/auth"
	"github.com/rabbitstack/fibratus/pkg/outputs/amqp/_fixtures/garagemq/config"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	log "github.com/sirupsen/logrus"
)

type ServerState int

// server state statuses
const (
	Stopped ServerState = iota
	Running
	Stopping
)

// Server implements AMQP server
type Server struct {
	host         string
	port         string
	protoVersion string
	listener     *net.TCPListener
	connSeq      uint64
	connLock     sync.Mutex
	statusLock   sync.Mutex
	connections  map[uint64]*Connection
	config       *config.Config
	users        map[string]string
	vhostsLock   sync.Mutex
	vhosts       map[string]*VirtualHost
	status       ServerState
}

// NewServer returns new instance of AMQP Server
func NewServer(host string, port string, protoVersion string, config *config.Config) (server *Server) {
	server = &Server{
		host:         host,
		port:         port,
		connections:  make(map[uint64]*Connection),
		protoVersion: protoVersion,
		config:       config,
		users:        make(map[string]string),
		vhosts:       make(map[string]*VirtualHost),
		connSeq:      0,
	}

	return
}

// Start start main server loop
func (srv *Server) Start() {
	log.WithFields(log.Fields{
		"pid": os.Getpid(),
	}).Info("Server starting")

	go srv.hookSignals()

	srv.initUsers()
	srv.initDefaultVirtualHosts()

	go srv.listen()
	srv.statusLock.Lock()
	srv.status = Running
	srv.statusLock.Unlock()
	select {}
}

// Stop stop server and all vhosts
func (srv *Server) Stop() {
	srv.vhostsLock.Lock()
	defer srv.vhostsLock.Unlock()
	srv.statusLock.Lock()
	srv.status = Stopping
	srv.statusLock.Unlock()

	// stop accept new connections
	srv.listener.Close()

	var wg sync.WaitGroup
	srv.connLock.Lock()
	for _, conn := range srv.connections {
		wg.Add(1)
		go conn.safeClose(&wg)
	}
	srv.connLock.Unlock()
	wg.Wait()
	log.Info("All connections safe closed")

	// stop exchanges and queues
	for _, virtualHost := range srv.vhosts {
		virtualHost.Stop()
	}
	srv.statusLock.Lock()
	srv.status = Stopped
	srv.statusLock.Unlock()
}

func (srv *Server) getVhost(name string) *VirtualHost {
	srv.vhostsLock.Lock()
	defer srv.vhostsLock.Unlock()

	return srv.vhosts[name]
}

func (srv *Server) listen() {
	address := srv.host + ":" + srv.port
	tcpAddr, err := net.ResolveTCPAddr("tcp4", address)
	srv.listener, err = net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		log.WithError(err).WithFields(log.Fields{
			"address": address,
		}).Error("Error on listener start")
		os.Exit(1)
	}

	log.WithFields(log.Fields{
		"address": address,
	}).Info("Server started")

	for {
		conn, err := srv.listener.AcceptTCP()
		if err != nil {
			srv.statusLock.Lock()
			if srv.status != Running {
				srv.statusLock.Unlock()
				return
			}
			srv.statusLock.Unlock()
			srv.stopWithError(err, "accepting connection")
		}
		log.WithFields(log.Fields{
			"from": conn.RemoteAddr().String(),
			"to":   conn.LocalAddr().String(),
		}).Info("accepting connection")

		conn.SetReadBuffer(srv.config.TCP.ReadBufSize)
		conn.SetWriteBuffer(srv.config.TCP.WriteBufSize)
		conn.SetNoDelay(srv.config.TCP.Nodelay)

		srv.acceptConnection(conn)
	}
}

func (srv *Server) stopWithError(err error, msg string) {
	log.WithError(err).Error(msg)
	srv.Stop()
	os.Exit(1)
}

func (srv *Server) acceptConnection(conn *net.TCPConn) {
	srv.connLock.Lock()
	defer srv.connLock.Unlock()

	connection := NewConnection(srv, conn)
	srv.connections[connection.id] = connection
	go connection.handleConnection()
}

func (srv *Server) removeConnection(connID uint64) {
	srv.connLock.Lock()
	defer srv.connLock.Unlock()

	delete(srv.connections, connID)
}

func (srv *Server) checkAuth(saslData auth.SaslData) bool {
	for userName, passwordHash := range srv.users {
		if userName != saslData.Username {
			continue
		}

		return auth.CheckPasswordHash(
			saslData.Password,
			passwordHash,
			srv.config.Security.PasswordCheck == "md5",
		)
	}
	return false
}

func (srv *Server) initUsers() {
	for _, user := range srv.config.Users {
		srv.users[user.Username] = user.Password
	}
}

func (srv *Server) initDefaultVirtualHosts() {
	log.WithFields(log.Fields{
		"vhost": srv.config.Vhost.DefaultPath,
	}).Info("Initialize default vhost")

	log.Info("Initialize host message msgStorage")

	srv.vhostsLock.Lock()
	defer srv.vhostsLock.Unlock()
	srv.vhosts[srv.config.Vhost.DefaultPath] = NewVhost(srv.config.Vhost.DefaultPath, true, srv)
}

func (srv *Server) onSignal(sig os.Signal) {
	switch sig {
	case syscall.SIGTERM, syscall.SIGINT:
		srv.Stop()
		os.Exit(0)
	}
}

// Special method for calling in tests without os.Exit(0)
func (srv *Server) testOnSignal(sig os.Signal) {
	switch sig {
	case syscall.SIGTERM, syscall.SIGINT:
		srv.Stop()
	}
}

func (srv *Server) hookSignals() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for sig := range c {
			log.Infof("Received [%d:%s] signal from OS", sig, sig.String())
			srv.onSignal(sig)
		}
	}()
}

func (srv *Server) getConfirmChannel(meta *amqp.ConfirmMeta) *Channel {
	srv.connLock.Lock()
	defer srv.connLock.Unlock()
	conn := srv.connections[meta.ConnID]
	if conn == nil {
		return nil
	}

	return conn.getChannel(meta.ChanID)
}

func (srv *Server) GetVhost(name string) *VirtualHost {
	return srv.getVhost(name)
}

func (srv *Server) GetVhosts() map[string]*VirtualHost {
	return srv.vhosts
}

func (srv *Server) GetConnections() map[uint64]*Connection {
	return srv.connections
}

func (srv *Server) GetProtoVersion() string {
	return srv.protoVersion
}

func (srv *Server) GetStatus() ServerState {
	return srv.status
}
