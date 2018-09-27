package main

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"

	"time"

	"github.com/Sirupsen/logrus"
	"golang.org/x/net/idna"
)

func acceptConnectionsBuiltinProxy(listeners []*net.TCPListener) {
	for index := range listeners {
		listener := listeners[index]

		proxyToBackend := &httputil.ReverseProxy{}
		proxyToBackend.Director = func(req *http.Request) {
			// TODO: send http request to QUIC backend
			localAddr := req.Context().Value(http.LocalAddrContextKey).(net.Addr)
			targetAddr, err := getTargetAddr(ConnectionID("none"), localAddr)
			if err != nil {
				logrus.Errorf("Can't map local addr to target addr '%v': %v", localAddr, err)
				req.URL = nil
			}
			targetAddrString := targetAddr.String()

			if req.URL == nil {
				req.URL = &url.URL{}
			}
			req.URL.Scheme = "http"
			req.URL.Host = targetAddrString

			if req.Header == nil {
				req.Header = make(http.Header)
			}
			for _, pair := range srvdata.additionalHeadersStringPairs {
				req.Header.Set(pair[0], pair[1])
			}
			clientIP, _, err := net.SplitHostPort(req.RemoteAddr)
			if err == nil {
				for _, realIpHeader := range srvdata.realIPHeaderNamesStrings {
					req.Header.Set(realIpHeader, clientIP)
				}
			}

			if logrus.StandardLogger().Level >= logrus.InfoLevel {
				asciiDomain, err := idna.ToASCII(req.Host)
				if err != nil {
					logrus.Debugf("Can't convert domain to ascii '%v': %v", req.Host, err)
				}
				//domainPresent := DomainPresent(asciiDomain)
				//logrus.Infof("BuiltinProxy from '%v' to http://%v (%v)", clientIP, domainPresent, targetAddrString)
				logrus.Infof("BuiltinProxy from '%v' to http://%v (%v)", clientIP, asciiDomain, targetAddrString)
			}

			if *srvdata.Flags.connectionIdHeader != "" {
				req.Header.Set(*srvdata.Flags.connectionIdHeader, "TODO")
			}

		}

		proxyToBackend.ModifyResponse = func(resp *http.Response) error {
			return nil
		}

		tlsListener := tls.NewListener(tcpKeepAliveListener{TCPListener: listener}, createTlsConfig())

		server := http.Server{}
		server.TLSConfig = createTlsConfig()
		server.Handler = proxyToBackend

		// TODO: h2server
		//h2server := h2quic.Server{
		//	Server: &server,
		//}
		//err = h2server.serveImpl(server.TLSConfig, nil)

		switch keepAliveMode {
		case KEEPALIVE_TRANSPARENT:
			// pass. Do native.
		case KEEPALIVE_NO_BACKEND:
			// copy default transport + disable keepalive
			proxyToBackend.Transport = &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
					DualStack: true,
				}).DialContext,
				MaxIdleConns:          100,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,

				// force disable keepalive
				DisableKeepAlives: true,
			}
		default:
			logrus.Errorf("Unknow keep alive mode for buil-in proxy: %v (%v)", *srvdata.Flags.keepAliveModeS, keepAliveMode)
		}

		server.ReadTimeout = *srvdata.Flags.maxRequestTime

		go func(listener net.Listener) {
			err := server.Serve(listener)
			if err != nil {
				logrus.Infof("Error server connection by build-in proxy for tls listener '%v': %v", listener, err)
			}
		}(tlsListener)
	}
}

// tcpKeepAliveListener sets TCP keep-alive timeouts on accepted
// connections. It's used by ListenAndServe and ListenAndServeTLS so
// dead TCP connections (e.g. closing laptop mid-download) eventually
// go away.
type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return
	}
	//nolint:errcheck
	tc.SetKeepAlive(true)
	//nolint:errcheck
	tc.SetKeepAlivePeriod(*srvdata.Flags.tcpKeepAliveInterval)
	return tc, nil
}
