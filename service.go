package main

import (
	"flag"
	"net"
	"os"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/kardianos/service"
)

// ServiceFlags is presentation of service command line flags
type ServiceFlags struct {
	acmeParallelCount             *int           // ("acme-parallel", 10, "Count of parallel requests for ACME server")
	acmeServerUrl                 *string        // ("acme-server", LETSENCRYPT_PRODUCTION_API_URL, "")
	acmeSslCheckDisable           *bool          // ("acme-sslcheck-disable", false, "Disable check of ACME server certificate")
	additionalHeadersParam        *string        // ("additional-headers", "X-Forwarded-Proto=https", "Additional headers for proxied requests. Separate multiple headers by comma.")
	allowIPRefreshInterval        *time.Duration // ("allow-ips-refresh", time.Hour, "For local, domain and ifconfig.io/ifconfig.me - how often ip addresses will be refreshed. Format https://golang.org/pkg/time/#ParseDuration.")
	allowIPsString                *string        // ("allowed-ips", "auto", "Allowable ip addresses (ipv4,ipv6) separated by comma. It can contain special variables (without quotes): 'auto' - try to auto determine allowable address, the logic may change between versions. 'local' (all autodetected local IP) and 'nat' - detect IP by request to http://ifconfig.io/ip or http://ifconfig.me/ip - it's needed for public ip auto-detection behind NAT.")
	bindToS                       *string        // ("bind-to", ":"+strconv.Itoa(DEFAULT_BIND_PORT), "List of ports, ip addresses or port:ip separated by comma. For example: 1.1.1.1,2.2.2.2,3.3.3.3:443,4.4.4.4. Ports other then 443 may be used only if tcp-connections proxied from port 443 (iptables,nginx,socat and so on) because Let's Encrypt now checks connections using port 443 only.")
	bindHTTPValidationToS         *string        // ("bind-http-validation-to", ":"+strconv.Itoa(DEFAULT_BIND_HTTP_VALIDATION_PORT), "Bind address for http-validation port. List of ports, ip addresses or port:ip separated by comma. Requests to <domain>/.well-known/acme-challenge/ must be redirect to this port for http-01 validation.")
	blockBadDomainDuration        *time.Duration // ("block-bad-domain-duration", time.Hour, "Disable trying to obtain certificate for a domain after error")
	certDir                       *string        // ("cert-dir", "certificates", `Directory for saved cached certificates. Set cert-dir=- to disable saving of certificates.`)
	certJsonSave                  *bool          // ("cert-json", false, "Save JSON information about certificate near the certificate file with same name with .json extension")
	connectionIdHeader            *string        // ("connection-id-header", "", "Header name used for sending connection id to backend in HTTP proxy mode. Default it isn't send.")
	cryptoCurvePreferences        *string        // ("crypto-curves", "", "Names or integer values of CurveID, separated by comma. If empty - default usage. https://golang.org/pkg/crypto/tls/#CurveID")
	daemonFlag                    *bool          // (DAEMON_KEY_NAME, false, "Start as background daemon. Supported in Unix OS only.")
	defaultDomain                 *string        // ("default-domain", "", "Usage when SNI domain isn't available (has zero length). For example client doesn't support SNI. It is used to obtain a certificate only. It isn't force set header HOST in request.")
	dnsTimeout                    *time.Duration //  ("dns-timeout", 5*time.Second, "Timeout for dns request")
	getIPByExternalRequestTimeout *time.Duration //  ("get-ip-by-external-request-timeout", 5*time.Second, "Timeout for request to external service for ip detection. For example when server behind NAT.")
	inMemoryCertCount             *int           // ("in-memory-cnt", 100, "How many certificates should be cached in memory, to preveent parsing from file")
	initOnly                      *bool          // ("init-only", false, "Exit after initialize, generate self keys. Need for auto-test environment.")
	keepAliveModeS                *string        // ("keepalive", KEEPALIVE_NO_BACKEND_STRING, KEEPALIVE_TRANSPARENT_STRING+" - keepalive from user to server if both support else doesn't keepalive. In this mode server side need keep alive time more, then lets-proxy. Now it isn't detect close connection on server side while wait next customer's request. It is not well worked mode."+KEEPALIVE_NO_BACKEND_STRING+" - force doesn't use keepalive connection to backend, but can handle keepalive from user.")
	keepAliveCustomerTimeout      *time.Duration //  ("keepalive-customer-timeout", time.Minute*5, "When keepalive in mode '"+KEEPALIVE_NO_BACKEND_STRING+"' - how long should the connection be maintained. In '"+KEEPALIVE_TRANSPARENT_STRING+"' mode, timeout isn't used and both connections close when either the backend or customer close self connection.")
	logLevel                      *string        // ("loglevel", "debug", "fatal|error|warning|info|debug")
	logOutput                     *string        // ("logout", "-", "Path to logout. Special: '-' (without quotes) - stderr")
	logrotateMaxAge               *int           // ("logrotate-age", 30, "How many days keep old backups")
	logrotateMaxCount             *int           // ("logrotate-count", 30, "How many old backups to keep. 0 for keep infinitely.")
	logrotateMb                   *int           // ("logrotate-mb", 100, "logrotate by size in megabytes. 0 means log rotation on size is off.")
	logrotateTime                 *string        // ("logrotate-time", "", "minutely|hourly|daily|weekly|monthly|yearly|\"\", empty or none means no log rotation by time. Weekly - rotate log at midnight from Sunday to Monday")
	maxRequestTime                *time.Duration //  ("max-request-body-time", time.Hour, "Max time, that customer can send request body.")
	minTLSVersion                 *string        // ("min-tls", "", "Minimum supported TLS version: ssl3,tls10,tls11,tls12. Default is GoLang's default.")
	noLogStderr                   *bool          // ("no-log-stderr", false, "Suppress logging to stderr")
	nonCertDomains                *string        // ("non-cert-domains", "", "Do not obtain certificates for matched domains. Regexpes separated by comma.")
	panicTest                     *bool          // ("panic", false, "throw unhandled panic (and crash program) after initialize logs. It need for test purposes (check redirect stderr work fine).")
	pidFilePath                   *string        // ("pid-file", "lets-proxy.pid", "Write pid of process. When used with --daemon, lock the file to prevent starting daemon more than once.")
	preventIDNDecode              *bool          // ("prevent-idn-decode", false, "Default domain shows in log as 'domain.com' or 'xn--d1acufc.xn--p1ai' ('домен.рф'). When option used it will show as 'domain.com' or 'xn--d1acufc.xn--p1ai', without decode idn domains.")
	privateKeyBits                *int           // ("private-key-len", 2048, "Length of private keys in bits")
	profilerBindAddress           *string        // ("profiler-bind", "127.0.0.1:6060", "Address for get of profiler dump by http.")
	profilerPassword              *string        // ("profiler-password", "", "Password for get access to profiler info. Profiler disable if empty. Usage go tool pprof http://<Addr>/debug/pprof/...?password=<password>. For example: http://127.0.0.1:6060/debug/pprof/heap?password=123 or http://localhost:6060/debug/pprof/?password=123 or go tool pprof 'http://localhost:6060/debug/pprof/profile?seconds=30&password=123'")
	proxyMode                     *string        // ("proxy-mode", PROXYMODE_HTTP_BUILTIN, "Proxy-mode after TLS handled (http|tcp).")
	realIPHeader                  *string        // ("real-ip-header", "X-Real-IP", "The header will contain original IP of remote connection. Multiple headers are separated with a comma.")
	runAs                         *string        // ("runas", "", "Run as a different user. This works only for --daemon, and only for Unix and requires to run from specified user or root. It can be user login or user id. It also changes default work dir to home folder of the user (can be changed by explicit --"+WORKING_DIR_ARG_NAME+"). Run will fail if use this option without --daemon.")
	serviceAction                 *string        // ("service-action", "", "Start, stop, install, uninstall, reinstall")
	serviceName                   *string        // ("service-name", SERVICE_NAME_EXAMPLE, "Service name is required for service actions")
	stateFilePath                 *string        // ("state-file", "state.json", "Filename and path to which we save some state data. For example account key.")
	stdErrToFile                  *string        // ("stderr-to-file", "", "Redirect all stderr output to file by system call. It need for write unhandled panic to log. Empty value (default) mean no redirection. Warning: now it isn't support to redirect log file, becouse logfile rotations. It work for linux with --daemon key and for windows.")
	subdomainsUnionS              *string        // ("subdomains-union", "www", "Comma-separated subdomains for which we try to obtain certificate on a single domain name. For example, if we receive a request to domain.com we try to obtain certificate valid for both www.domain.com and domain.com at same time, and save them in one certificate named domain.com. Changing option on running program will require that new certificates be obtained for added/removed subdomains.")
	targetConnString              *string        // ("target", "www.google.com", "IP, :port or IP:port. Default port is 80. Default IP is the ip address which receives the connection.")
	mapTargetS                    *string        // ("target-map", "", "Remap target for some received ip:port. Format is receiveIP[:receivePort]=targetIP[:targetPort]. Can pass multiple remap rules, separated by comma. Format is --map=1.2.3.10=127.0.0.1,1.2.3.11=127.0.0.2:8999")
	targetConnTimeout             *time.Duration //  ("target-conn-timeout", time.Second, "")
	tcpKeepAliveInterval          *time.Duration //  ("tcp-keepalive-interval", time.Minute, "Interval between send TCP keepalive packages detect dead connections")
	acmeTestServer                *bool          // ("test", false, "Use test Let's Encrypt server instead of <acme-server>")
	timeToRenew                   *time.Duration //  ("time-to-renew", time.Hour*24*30, "Time to end of certificate for background renewal")
	versionPrint                  *bool          // ("version", false, "Print version and exit")
	whiteList                     *string        // ("whitelist-domains", "", `Allow request certificate for the domains without any check by --non-cert-domains. Requires a list all domains including subdomains (for example domain.com,www.domain.com). If domain start with 're:' then it check as regexp, for example: re:(www\.)-example-[0-9]*\.example\.com$. This parameter doesn't reject other domains. To reject other domains use parameter --non-cert-domains. To reject all domains except those in the whitelist use --non-cert-domains=".*"`)
	whiteListFile                 *string        // ("whitelist-domains-file", "", "Same as --whitelist-domains but domains are read from file. One domain per line. File may updated without restarting lets-proxy")
	workingDir                    *string        // (WORKING_DIR_ARG_NAME, "", "Set working directory")
}

// ServiceData is presentation of service status
type ServiceData struct {
	// command line flags
	Flags *ServiceFlags

	// Internal transformations of some flags
	realIPHeaderNames            [][]byte // IP headers, generated by the proxy, included real IP address
	realIPHeaderNamesStrings     []string
	cutHeaders                   [][]byte // internal - all headers, that cut from request (upper case).
	additionalHeaders            []byte   // prepared additional headers
	additionalHeadersStringPairs [][2]string

	whiteListFromParam        []string
	whiteListFromParamRe      []*regexp.Regexp
	acmeService               *acmeStruct
	nonCertDomainsRegexps     []*regexp.Regexp
	paramTargetTcpAddr        *net.TCPAddr
	subdomainPrefixedForUnion []string
	bindTo                    []net.TCPAddr
	bindHttpValidationTo      []net.TCPAddr
	globalConnectionNumber    int64
	targetMap                 map[string]*net.TCPAddr

	// exit management
	exitcode int           // saved exist code
	exited   bool          // exited indicator
	exitch   chan struct{} // exitch notify
	exiterr  error         // error for exist

	exl sync.Mutex // atomic lock
}

// NewServiceData return a ServiceData object
func NewServiceData() *ServiceData {
	sd := &ServiceData{
		exitch: make(chan struct{}),
		exl:    sync.Mutex{},
	}
	sd.flagsParse()
	return sd
}

func (sd *ServiceData) flagsParse() {
	sd.exl.Lock()
	defer sd.exl.Unlock()
	sd.Flags = &ServiceFlags{
		acmeParallelCount:             flag.Int("acme-parallel", 10, "Count of parallel requests for ACME server"),
		acmeServerUrl:                 flag.String("acme-server", LETSENCRYPT_PRODUCTION_API_URL, ""),
		acmeSslCheckDisable:           flag.Bool("acme-sslcheck-disable", false, "Disable check of ACME server certificate"),
		additionalHeadersParam:        flag.String("additional-headers", "X-Forwarded-Proto=https", "Additional headers for proxied requests. Separate multiple headers by comma."),
		allowIPRefreshInterval:        flag.Duration("allow-ips-refresh", time.Hour, "For local, domain and ifconfig.io/ifconfig.me - how often ip addresses will be refreshed. Format https://golang.org/pkg/time/#ParseDuration."),
		allowIPsString:                flag.String("allowed-ips", "auto", "Allowable ip addresses (ipv4,ipv6) separated by comma. It can contain special variables (without quotes): 'auto' - try to auto determine allowable address, the logic may change between versions. 'local' (all autodetected local IP) and 'nat' - detect IP by request to http://ifconfig.io/ip or http://ifconfig.me/ip - it's needed for public ip auto-detection behind NAT."),
		bindToS:                       flag.String("bind-to", ":"+strconv.Itoa(DEFAULT_BIND_PORT), "List of ports, ip addresses or port:ip separated by comma. For example: 1.1.1.1,2.2.2.2,3.3.3.3:443,4.4.4.4. Ports other then 443 may be used only if tcp-connections proxied from port 443 (iptables,nginx,socat and so on) because Let's Encrypt now checks connections using port 443 only."),
		bindHTTPValidationToS:         flag.String("bind-http-validation-to", ":"+strconv.Itoa(DEFAULT_BIND_HTTP_VALIDATION_PORT), "Bind address for http-validation port. List of ports, ip addresses or port:ip separated by comma. Requests to <domain>/.well-known/acme-challenge/ must be redirect to this port for http-01 validation."),
		blockBadDomainDuration:        flag.Duration("block-bad-domain-duration", time.Hour, "Disable trying to obtain certificate for a domain after error"),
		certDir:                       flag.String("cert-dir", "certificates", `Directory for saved cached certificates. Set cert-dir=- to disable saving of certificates.`),
		certJsonSave:                  flag.Bool("cert-json", false, "Save JSON information about certificate near the certificate file with same name with .json extension"),
		connectionIdHeader:            flag.String("connection-id-header", "", "Header name used for sending connection id to backend in HTTP proxy mode. Default it isn't send."),
		cryptoCurvePreferences:        flag.String("crypto-curves", "", "Names or integer values of CurveID, separated by comma. If empty - default usage. https://golang.org/pkg/crypto/tls/#CurveID"),
		daemonFlag:                    flag.Bool(DAEMON_KEY_NAME, false, "Start as background daemon. Supported in Unix OS only."),
		defaultDomain:                 flag.String("default-domain", "", "Usage when SNI domain isn't available (has zero length). For example client doesn't support SNI. It is used to obtain a certificate only. It isn't force set header HOST in request."),
		dnsTimeout:                    flag.Duration("dns-timeout", 5*time.Second, "Timeout for dns request"),
		getIPByExternalRequestTimeout: flag.Duration("get-ip-by-external-request-timeout", 5*time.Second, "Timeout for request to external service for ip detection. For example when server behind NAT."),
		inMemoryCertCount:             flag.Int("in-memory-cnt", 100, "How many certificates should be cached in memory, to preveent parsing from file"),
		initOnly:                      flag.Bool("init-only", false, "Exit after initialize, generate self keys. Need for auto-test environment."),
		keepAliveModeS:                flag.String("keepalive", KEEPALIVE_NO_BACKEND_STRING, KEEPALIVE_TRANSPARENT_STRING+" - keepalive from user to server if both support else doesn't keepalive. In this mode server side need keep alive time more, then lets-proxy. Now it isn't detect close connection on server side while wait next customer's request. It is not well worked mode."+KEEPALIVE_NO_BACKEND_STRING+" - force doesn't use keepalive connection to backend, but can handle keepalive from user."),
		keepAliveCustomerTimeout:      flag.Duration("keepalive-customer-timeout", time.Minute*5, "When keepalive in mode '"+KEEPALIVE_NO_BACKEND_STRING+"' - how long should the connection be maintained. In '"+KEEPALIVE_TRANSPARENT_STRING+"' mode, timeout isn't used and both connections close when either the backend or customer close self connection."),
		logLevel:                      flag.String("loglevel", "debug", "fatal|error|warning|info|debug"),
		logOutput:                     flag.String("logout", "-", "Path to logout. Special: '-' (without quotes) - stderr"),
		logrotateMaxAge:               flag.Int("logrotate-age", 30, "How many days keep old backups"),
		logrotateMaxCount:             flag.Int("logrotate-count", 30, "How many old backups to keep. 0 for keep infinitely."),
		logrotateMb:                   flag.Int("logrotate-mb", 100, "logrotate by size in megabytes. 0 means log rotation on size is off."),
		logrotateTime:                 flag.String("logrotate-time", "", "minutely|hourly|daily|weekly|monthly|yearly|\"\", empty or none means no log rotation by time. Weekly - rotate log at midnight from Sunday to Monday"),
		maxRequestTime:                flag.Duration("max-request-body-time", time.Hour, "Max time, that customer can send request body."),
		minTLSVersion:                 flag.String("min-tls", "", "Minimum supported TLS version: ssl3,tls10,tls11,tls12. Default is GoLang's default."),
		noLogStderr:                   flag.Bool("no-log-stderr", false, "Suppress logging to stderr"),
		nonCertDomains:                flag.String("non-cert-domains", "", "Do not obtain certificates for matched domains. Regexpes separated by comma."),
		panicTest:                     flag.Bool("panic", false, "throw unhandled panic (and crash program) after initialize logs. It need for test purposes (check redirect stderr work fine)."),
		pidFilePath:                   flag.String("pid-file", "lets-proxy.pid", "Write pid of process. When used with --daemon, lock the file to prevent starting daemon more than once."),
		preventIDNDecode:              flag.Bool("prevent-idn-decode", false, "Default domain shows in log as 'domain.com' or 'xn--d1acufc.xn--p1ai' ('домен.рф'). When option used it will show as 'domain.com' or 'xn--d1acufc.xn--p1ai', without decode idn domains."),
		privateKeyBits:                flag.Int("private-key-len", 2048, "Length of private keys in bits"),
		profilerBindAddress:           flag.String("profiler-bind", "127.0.0.1:6060", "Address for get of profiler dump by http."),
		profilerPassword:              flag.String("profiler-password", "", "Password for get access to profiler info. Profiler disable if empty. Usage go tool pprof http://<Addr>/debug/pprof/...?password=<password>. For example: http://127.0.0.1:6060/debug/pprof/heap?password=123 or http://localhost:6060/debug/pprof/?password=123 or go tool pprof 'http://localhost:6060/debug/pprof/profile?seconds=30&password=123'"),
		proxyMode:                     flag.String("proxy-mode", PROXYMODE_HTTP_BUILTIN, "Proxy-mode after TLS handled (http|tcp)."),
		realIPHeader:                  flag.String("real-ip-header", "X-Real-IP", "The header will contain original IP of remote connection. Multiple headers are separated with a comma."),
		runAs:                         flag.String("runas", "", "Run as a different user. This works only for --daemon, and only for Unix and requires to run from specified user or root. It can be user login or user id. It also changes default work dir to home folder of the user (can be changed by explicit --"+WORKING_DIR_ARG_NAME+"). Run will fail if use this option without --daemon."),
		serviceAction:                 flag.String("service-action", "", "Start, stop, install, uninstall, reinstall"),
		serviceName:                   flag.String("service-name", SERVICE_NAME_EXAMPLE, "Service name is required for service actions"),
		stateFilePath:                 flag.String("state-file", "state.json", "Filename and path to which we save some state data. For example account key."),
		stdErrToFile:                  flag.String("stderr-to-file", "", "Redirect all stderr output to file by system call. It need for write unhandled panic to log. Empty value (default) mean no redirection. Warning: now it isn't support to redirect log file, becouse logfile rotations. It work for linux with --daemon key and for windows."),
		subdomainsUnionS:              flag.String("subdomains-union", "www", "Comma-separated subdomains for which we try to obtain certificate on a single domain name. For example, if we receive a request to domain.com we try to obtain certificate valid for both www.domain.com and domain.com at same time, and save them in one certificate named domain.com. Changing option on running program will require that new certificates be obtained for added/removed subdomains."),
		targetConnString:              flag.String("target", "www.google.com", "IP, :port or IP:port. Default port is 80. Default IP is the ip address which receives the connection."),
		mapTargetS:                    flag.String("target-map", "", "Remap target for some received ip:port. Format is receiveIP[:receivePort]=targetIP[:targetPort]. Can pass multiple remap rules, separated by comma. Format is --map=1.2.3.10=127.0.0.1,1.2.3.11=127.0.0.2:8999"),
		targetConnTimeout:             flag.Duration("target-conn-timeout", time.Second, ""),
		tcpKeepAliveInterval:          flag.Duration("tcp-keepalive-interval", time.Minute, "Interval between send TCP keepalive packages detect dead connections"),
		acmeTestServer:                flag.Bool("test", false, "Use test Let's Encrypt server instead of <acme-server>"),
		timeToRenew:                   flag.Duration("time-to-renew", time.Hour*24*30, "Time to end of certificate for background renewal"),
		versionPrint:                  flag.Bool("version", false, "Print version and exit"),
		whiteList:                     flag.String("whitelist-domains", "", `Allow request certificate for the domains without any check by --non-cert-domains. Requires a list all domains including subdomains (for example domain.com,www.domain.com). If domain start with 're:' then it check as regexp, for example: re:(www\.)-example-[0-9]*\.example\.com$. This parameter doesn't reject other domains. To reject other domains use parameter --non-cert-domains. To reject all domains except those in the whitelist use --non-cert-domains=".*"`),
		whiteListFile:                 flag.String("whitelist-domains-file", "", "Same as --whitelist-domains but domains are read from file. One domain per line. File may updated without restarting lets-proxy"),
		workingDir:                    flag.String(WORKING_DIR_ARG_NAME, "", "Set working directory"),
	}
}

// Wait block until service exited and return exit code and error,
// 0 and nil for no error when exit
func (sd *ServiceData) Wait() (int, error) {
	<-sd.exitch
	sd.exl.Lock()
	defer sd.exl.Unlock()
	return sd.exitcode, sd.exiterr
}

// IsClosed return true when service exited
func (sd *ServiceData) IsClosed() bool {
	sd.exl.Lock()
	defer sd.exl.Unlock()
	return sd.exited
}

// ExitCode return code for exit, return 0 if no error
func (sd *ServiceData) ExitCode() int {
	sd.exl.Lock()
	defer sd.exl.Unlock()
	return sd.exitcode
}

// ExitErr return error for exit, return nil if no error
func (sd *ServiceData) ExitErr() error {
	sd.exl.Lock()
	defer sd.exl.Unlock()
	return sd.exiterr
}

// Close terminate service with code and err, do nothing if service already closed
func (sd *ServiceData) Close(code int, err error) {
	sd.exl.Lock()
	defer sd.exl.Unlock()
	if sd.exited == true {
		return
	}

	//
	sd.exited = true
	sd.exitcode = code
	sd.exiterr = err
	close(sd.exitch)
}

// Start handle start request from system daemon
func (*ServiceData) Start(s service.Service) error {
	logrus.Info("Start service")
	var sleepChan = make(chan int, 1)
	return startWork(sleepChan)
}

// Stop handle stop request from system daemon
func (*ServiceData) Stop(s service.Service) error {
	logrus.Info("Stop service")
	go func() {
		time.Sleep(time.Second / 10)
		os.Exit(0)
	}()
	return nil
}
