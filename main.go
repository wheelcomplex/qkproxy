package main

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"bufio"
	"sort"

	"net/textproto"

	"github.com/Sirupsen/logrus"
	"github.com/hashicorp/golang-lru"
	"github.com/kardianos/service"
	"github.com/rekby/panichandler"
	"gopkg.in/natefinch/lumberjack.v2"
)

const (
	LETSENCRYPT_CREATE_CERTIFICATE_TIMEOUT           = time.Minute
	LETSENCRYPT_BACKGROUND_RENEW_CERTIFICATE_TIMEOUT = time.Minute * 5
	LETSENCRYPT_PRODUCTION_API_URL                   = "https://acme-v01.api.letsencrypt.org/directory"
	LETSENCRYPT_STAGING_API_URL                      = "https://acme-staging.api.letsencrypt.org/directory"
	TRY_COUNT                                        = 10
	RETRY_SLEEP                                      = time.Second * 5
	STATE_FILEMODE                                   = 0600
	SERVICE_NAME_EXAMPLE                             = "<service-name>"
	WORKING_DIR_ARG_NAME                             = "working-dir"
	DEFAULT_BIND_PORT                                = 443
	DEFAULT_BIND_HTTP_VALIDATION_PORT                = 80
	DAEMON_KEY_NAME                                  = "daemon"
)

const (
	PROXYMODE_HTTP         = "http"
	PROXYMODE_HTTP_BUILTIN = "http-built-in"
	PROXYMODE_TCP          = "tcp"
)

// constants in var
var (
	VERSION = "unversioned" // need be var becouse it redefine by --ldflags "-X main.VERSION" during autobuild
)

var (
	stdErrFileGlobal *os.File // global variable - for not close file for stderr redirect while app working
)

type stateStruct struct {
	PrivateKey *rsa.PrivateKey
	changed    bool
}

type nullWriter struct{}

type ConnectionID string

func (cid ConnectionID) String() string {
	return string(cid)
}

func (nullWriter) Write(buf []byte) (int, error) {
	return len(buf), nil
}

func HasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

// service data
var srvdata = NewServiceData()

func main() {
	flag.Usage = usage
	flag.Parse()

	if *srvdata.Flags.versionPrint {
		fmt.Println(strings.TrimSpace(VERSION))
		return
	}

	// Set loglevel
	logrus.SetLevel(logrus.WarnLevel)
	logrus.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})
	switch *srvdata.Flags.logLevel {
	case "fatal":
		logrus.SetLevel(logrus.FatalLevel)
	case "error":
		logrus.SetLevel(logrus.ErrorLevel)
	case "warning":
		logrus.SetLevel(logrus.WarnLevel)
	case "info":
		logrus.SetLevel(logrus.InfoLevel)
	case "debug":
		logrus.SetLevel(logrus.DebugLevel)
	default:
		logrus.Errorf("Use default loglevel '%v', becouse unknow level: '%v'", logrus.GetLevel(), *srvdata.Flags.logLevel)
	}

	isDaemon := false

	if *srvdata.Flags.serviceAction == "" {
		if *srvdata.Flags.daemonFlag {
			if !daemonize() {
				return
			}
			isDaemon = true
		} else {
			if *srvdata.Flags.pidFilePath != "" {
				err := ioutil.WriteFile(*srvdata.Flags.pidFilePath, []byte(strconv.Itoa(os.Getpid())), 0600)
				if err != nil {
					logrus.Errorf("Can't write pid file '%v': %v", *srvdata.Flags.pidFilePath, err)
					return
				}
			}
		}
	}

	if *srvdata.Flags.workingDir != "" {
		if !filepath.IsAbs(*srvdata.Flags.workingDir) {
			logrus.Fatalf("Working dir must be absolute filepath instead relative: '%v'", *srvdata.Flags.workingDir)
		}

		err := os.Chdir(*srvdata.Flags.workingDir)
		if err != nil {
			logrus.Error("Can't change working dir: ", err)
		}
	}

	isDaemon = isDaemon || !service.Interactive() && runtime.GOOS == "windows"

	logouts := []io.Writer{}
	if *srvdata.Flags.noLogStderr || isDaemon { // Run as windows-service or unix-daemon
		// don't append os.Stderr to logouts
	} else {
		logouts = append(logouts, os.Stderr)
	}

	var logFileName string
	if *srvdata.Flags.logOutput != "-" {
		logFileName = *srvdata.Flags.logOutput
	}
	if logFileName != "" {
		lr := &lumberjack.Logger{
			Filename:   logFileName,
			MaxSize:    *srvdata.Flags.logrotateMb,
			MaxAge:     *srvdata.Flags.logrotateMaxAge,
			MaxBackups: *srvdata.Flags.logrotateMaxCount,
			LocalTime:  true,
		}
		if *srvdata.Flags.logrotateMb == 0 {
			lr.MaxSize = int(math.MaxInt32) // about 2 Petabytes. Really no reachable in this scenario.
		}
		defer lr.Close()

		_, err := lr.Write([]byte{})
		if err == nil {
			logouts = append(logouts, lr)
			go startTimeLogRotator(lr)
		} else {
			logrus.Errorf("Can't log to file '%v': %v", logFileName, err)
		}
	}

	// setlogout
	switch len(logouts) {
	case 0:
		logrus.SetOutput(nullWriter{})
	case 1:
		logrus.SetOutput(logouts[0])
	default:
		logrus.SetOutput(io.MultiWriter(logouts...))
	}

	logrus.Infof("Use log level: '%v'", logrus.GetLevel())
	logrus.Info("Version: ", VERSION)

	// for unix redirect when daemon child start
	if *srvdata.Flags.stdErrToFile != "" && runtime.GOOS == "windows" {
		fName := filepath.Join(*srvdata.Flags.workingDir, *srvdata.Flags.stdErrToFile)
		var err error
		stdErrFileGlobal, err = os.OpenFile(fName, os.O_APPEND|os.O_CREATE, 0600) // mode 0644 copied from lubmerjeck log
		if err == nil {
			err = panichandler.RedirectStderr(stdErrFileGlobal)
		}
		if err == nil {
			logrus.Infof("Redirect stderr to file '%v'", fName)
		} else {
			logrus.Errorf("Can't redirect stderr to file '%v': %v", fName, err)
		}
		logrus.Debug("Sleep a second - need for complete redirect stderr")
	}

	if *srvdata.Flags.panicTest {
		panic("Test panic by --panic key")
	}

	if *srvdata.Flags.runAs != "" && !*srvdata.Flags.daemonFlag {
		logrus.Fatal("Key --runas used without --daemon key. It isn't supported.")
	}

	prepare()
	if *srvdata.Flags.initOnly {
		return
	}

	// profiler
	if *srvdata.Flags.profilerBindAddress != "" && *srvdata.Flags.profilerPassword != "" {
		go startProfiler()
	} else {
		logrus.Info("Profiler disabled")
	}

	go signalWorker()

	var serviceArguments []string
	if *srvdata.Flags.workingDir == "" {
		wd, _ := os.Getwd()
		serviceArguments = append([]string{"--" + WORKING_DIR_ARG_NAME + "=" + wd}, os.Args[1:]...)
	} else {
		serviceArguments = os.Args[1:]
	}

	// remove --service-action argument
	newServiceArguments := make([]string, 0, len(serviceArguments))
	for _, arg := range serviceArguments {
		if strings.HasPrefix(arg, "--service-action=") {
			continue
		}
		newServiceArguments = append(newServiceArguments, arg)
	}
	serviceArguments = newServiceArguments

	logrus.Debug("Service arguments:", serviceArguments)
	svcConfig := &service.Config{
		Name:        *srvdata.Flags.serviceName,
		Description: "QUIC proxy server",
		Arguments:   serviceArguments,
	}

	s, err := service.New(srvdata, svcConfig)
	if err != nil {
		if runtime.GOOS == "freebsd" && err == service.ErrNoServiceSystemDetected {
			logrus.Info("Service actions don't support for freebsd")
		} else {
			logrus.Error("Can't init service: ", err)
		}
	}
	if err == nil && !service.Interactive() {
		err = s.Run()
		if err != nil {
			logrus.Errorf("Run error: %v", err)
		}
		return
	}

	if *srvdata.Flags.serviceAction != "" && *srvdata.Flags.serviceName == SERVICE_NAME_EXAMPLE {
		logrus.Error("Setup service-name for usage service-action")
		os.Exit(1)
	}

	switch *srvdata.Flags.serviceAction {
	case "":
		logrus.Info("Start from command line ...")

		// Simple start
		var sleepChan = make(chan int, 1)
		err = startWork(sleepChan)
		if err == nil {
			// wait for exit
			code := <-sleepChan
			os.Exit(code)
		} else {
			logrus.Errorf("exit with error: %s", err)
			os.Exit(1)
		}

	case "install":
		err = s.Install()
		if err == nil {
			fmt.Println("Service installed")
		} else {
			fmt.Println("Service install error:", err)
			os.Exit(1)
		}
	case "uninstall":
		err = s.Uninstall()
		if err == nil {
			fmt.Println("Service uninstalled")
		} else {
			fmt.Println("Service uninstall error:", err)
			os.Exit(1)
		}
	case "reinstall":
		// Uninstall
		err = s.Uninstall()
		if err == nil {
			fmt.Println("Service uninstalled")
		} else {
			fmt.Println("Service uninstall error:", err)
		}

		// Install
		err = s.Install()
		if err == nil {
			fmt.Println("Service installed")
		} else {
			fmt.Println("Service install error:", err)
			os.Exit(1)
		}
	case "start":
		err = s.Start()
		if err == nil {
			fmt.Println("Service started")
		} else {
			fmt.Println("Service start error:", err)
			os.Exit(1)
		}
	case "stop":
		err = s.Stop()
		if err == nil {
			fmt.Println("Service stopped")
		} else {
			fmt.Println("Service stopped error")
			os.Exit(1)
		}
	default:
		fmt.Printf("Unknown service action: '%v'\n", *srvdata.Flags.serviceAction)
		os.Exit(1)
	}

}

func certificateGet(clientHello *tls.ClientHelloInfo) (cert *tls.Certificate, err error) {
	ctx, cancelFunc := context.WithTimeout(context.Background(), LETSENCRYPT_CREATE_CERTIFICATE_TIMEOUT)
	defer cancelFunc()

	domain := clientHello.ServerName
	if domain == "" {
		domain = *srvdata.Flags.defaultDomain
	}
	err = domainValidName(domain)
	if err != nil {
		logrus.Infof("Bad domain name '%v': %v", domain, err)
		return nil, errors.New("Bad domain name")
	}

	domain = strings.ToLower(domain)

	var baseDomain = domain
	var domainsToObtain []string

	for _, subdomainPrefix := range srvdata.subdomainPrefixedForUnion {
		if strings.HasPrefix(domain, subdomainPrefix) {
			baseDomain = domain[len(subdomainPrefix):]
			break
		}
	}

	logrus.Debugf("Required certificate for domain %v", DomainPresent(domain))

	if strings.HasSuffix(domain, ACME_DOMAIN_SUFFIX) {
		// force generate new certificate, without caching.
		return srvdata.acmeService.CreateCertificate(ctx, []string{domain}, "")
	}

	now := time.Now()
checkCertInCache:
	for {
		if ctx.Err() != nil {
			logrus.Infof("Can't get certificate for domain %v by cancel context: %v", DomainPresent(domain), ctx.Err())
			return nil, errors.New("Get certificate timeout")
		}

		cert = certificateCacheGet(baseDomain)
		if cert != nil && !stringsContains(cert.Leaf.DNSNames, domain) && !isBaseDomainLocked(baseDomain) {
			cert = nil
		}

		switch {
		case cert != nil && cert.Leaf.NotAfter.Before(now):
			if isBaseDomainLocked(baseDomain) {
				logrus.Infof("Expired certificate got from cache for domain %v. It is locked domain. Use expired cert.", DomainPresent(domain))
				return cert, nil
			} else {
				logrus.Infof("Expired certificate got from cache for domain %v. Obtain new cert.", DomainPresent(domain))
				// pass to obtain new certificate
			}

		case cert != nil:
			// need for background cert renew
			if cert.Leaf.NotAfter.Before(now.Add(*srvdata.Flags.timeToRenew)) {
				go func(domainsToObtain []string, baseDomain string) {
					if skipDomainsCheck(domainsToObtain) {
						return
					}

					if isBaseDomainLocked(baseDomain) {
						skipDomainsAdd([]string(domainsToObtain))
						return
					}

					if obtainDomainsLock(domainsToObtain) {
						defer obtainDomainsUnlock(domainsToObtain)
					} else {
						return
					}

					/* Background renew independent of the request context.*/
					func() {
						backgroundRenewCtx, backgroundRenewCtxCancelFunc := context.WithTimeout(context.Background(), LETSENCRYPT_BACKGROUND_RENEW_CERTIFICATE_TIMEOUT*5)
						defer backgroundRenewCtxCancelFunc()
						cert, err := srvdata.acmeService.CreateCertificate(backgroundRenewCtx, domainsToObtain, "")
						if err == nil {
							logrus.Infof("Background certificate obtained for: %v", cert.Leaf.DNSNames)
							certificateCachePut(baseDomain, cert)
						}
					}()
				}(cert.Leaf.DNSNames, baseDomain)
			}
			return cert, nil
		default:
			// pass to obtain cert
		}

		if skipDomainsCheck([]string{domain}) {
			logrus.Infof("Temporary skip domain: '%v'", domain)
			return nil, errors.New("Domain temporary skipped")
		}

		if domainsToObtain == nil {
			domainsToObtain = make([]string, 1, len(srvdata.subdomainPrefixedForUnion)+1)
			domainsToObtain[0] = baseDomain
			for _, subdomain := range srvdata.subdomainPrefixedForUnion {
				domainsToObtain = append(domainsToObtain, subdomain+baseDomain)
			}
		}

		if isBaseDomainLocked(baseDomain) {
			logrus.Infof("Add domains '%v' to temporary skip domain set, becouse '%v' is locked", domainsToObtain,
				baseDomain)
			skipDomainsAdd(domainsToObtain)
			return nil, errors.New("Domain is locked")
		}

		if obtainDomainsLock(domainsToObtain) {
			break checkCertInCache // create cert
		} else {
			// wait, then cert in cache again
			logrus.Infof("Obtain certificate in process for domain %v, wait a second and check it again", DomainPresent(domain))
			time.Sleep(time.Second)
			continue checkCertInCache
		}
	}
	defer obtainDomainsUnlock(domainsToObtain)

	logrus.Debugf("Obtain certificate for domains: %v", domainsToObtain)

	// check if get cert between check cache and lock to obtain
	cert = certificateCacheGet(baseDomain)
	if cert != nil && now.After(cert.Leaf.NotAfter) {
		logrus.Debugf("Certificate from cache expired. Renew it: %v\n", domainsToObtain)
		cert = nil
	}
	if cert != nil && !stringsContains(cert.Leaf.DNSNames, domain) {
		logrus.Debugf("Certificate from cache doesn't contain domain: %v not in %v\n", domain, cert.Leaf.DNSNames)
		cert = nil
	}

	if cert != nil {
		logrus.Debugf("Certificate to domains obtained from cache. It got between lock check and lock: %v (%v - %v)\n", cert.Leaf.DNSNames, cert.Leaf.NotBefore, cert.Leaf.NotAfter)
		return cert, nil
	}

	sort.Strings(domainsToObtain)
	allowedDomains := make([]string, 0, len(domainsToObtain))
forRegexpCheckDomain:
	for _, checkDomain := range domainsToObtain {
		whiteList := false
		if stringsSortedContains(srvdata.whiteListFromParam, checkDomain) {
			logrus.Debugf("Domain allowed by param whitelist: %v\n", checkDomain)
			whiteList = true
		}
		if !whiteList {
			for _, re := range srvdata.whiteListFromParamRe {
				if re.MatchString(checkDomain) {
					logrus.Debugf("Domain allowed by whitelist param regexp '%v': %v", re, checkDomain)
					whiteList = true
					break
				}
			}
		}
		if !whiteList {
			for _, re := range srvdata.nonCertDomainsRegexps {
				if re.MatchString(checkDomain) {
					logrus.Debugf("Reject obtain cert for domain %v by regexp '%v'", DomainPresent(domain), re.String())
					continue forRegexpCheckDomain
				}
			}
		}
		allowedDomains = append(allowedDomains, checkDomain)
	}

	// add domains from file
	if len(allowedDomains) != len(domainsToObtain) && *srvdata.Flags.whiteListFile != "" {
		logrus.Debug("Check file whitelist")

		func() {
			f, err := os.Open(*srvdata.Flags.whiteListFile)
			if f != nil {
				defer f.Close()
			}
			if err != nil {
				logrus.Error("Can't open white list file '%v': %v\n", *srvdata.Flags.whiteListFile, err)
				return
			}

			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				whiteListDomain := strings.TrimSpace(scanner.Text())
				if HasPrefixFold(whiteListDomain, "re:") {
					sRegexp := whiteListDomain[len("re:"):]
					re, err := regexp.Compile(sRegexp)
					if err == nil {
						for _, checkDomain := range domainsToObtain {
							if !stringsSortedContains(allowedDomains, checkDomain) && re.MatchString(checkDomain) {
								logrus.Debugf("Add domain from file whitelist by regexp '%v': %v", re, checkDomain)
								allowedDomains = stringsSortedAppend(allowedDomains, checkDomain)
							}
						}
					} else {
						logrus.Errorf("Error while compile regexp from whitelist file '%v': %v", sRegexp, err)
					}
				} else {
					if stringsSortedContains(domainsToObtain, whiteListDomain) && !stringsSortedContains(allowedDomains, whiteListDomain) {
						logrus.Debugf("Add domain from file whitelist: %v", whiteListDomain)
						allowedDomains = stringsSortedAppend(allowedDomains, whiteListDomain)
					}
				}
				if len(allowedDomains) == len(domainsToObtain) {
					// don't read file to end if all domain allowed already
					return
				}
			}
		}()
	}

	logrus.Debugf("Allowed domains after white and black list for '%v': '%v'", domainsToObtain, allowedDomains)
	if !stringsContains(allowedDomains, domain) {
		return nil, errors.New("Reject domain by regexp")
	}

	cert, err = srvdata.acmeService.CreateCertificate(ctx, allowedDomains, domain)
	if err == nil {
		certificateCachePut(baseDomain, cert)

		domainsForBlock := []string{}
		for _, checkDomain := range allowedDomains {
			if !stringsContains(cert.Leaf.DNSNames, checkDomain) {
				domainsForBlock = append(domainsForBlock, checkDomain)
			}
		}
		if len(domainsForBlock) > 0 {
			skipDomainsAdd(domainsForBlock)
		}
	} else {
		logrus.Infof("Can't obtain certificate for domains '%v': %v", allowedDomains, err)
		skipDomainsAdd([]string{domain})
		return nil, errors.New("Can't obtain acme certificate")
	}

	return cert, err
}

func createTlsConfig() *tls.Config {
	tlsConfig := &tls.Config{
		GetCertificate: certificateGet,
	}

	// Map of supported curves
	// https://golang.org/pkg/crypto/tls/#CurveID
	var supportedCurvesMap = map[string]tls.CurveID{
		"X25519":    tls.X25519,
		"CURVEP256": tls.CurveP256,
		"CURVEP384": tls.CurveP384,
		"CURVEP521": tls.CurveP521,
	}
	for _, name := range strings.Split(*srvdata.Flags.cryptoCurvePreferences, ",") {
		nameUpper := strings.ToUpper(strings.TrimSpace(name))
		if nameUpper == "" {
			continue
		}

		if val, ok := supportedCurvesMap[nameUpper]; ok {
			tlsConfig.CurvePreferences = append(tlsConfig.CurvePreferences, val)
			continue
		}
		if intVal, err := strconv.ParseUint(nameUpper, 10, 16); err == nil {
			tlsConfig.CurvePreferences = append(tlsConfig.CurvePreferences, tls.CurveID(intVal))
			continue
		}
		logrus.Fatalf("Unknown curve name: '%s'", name)
	}

	switch strings.TrimSpace(*srvdata.Flags.minTLSVersion) {
	case "":
	// pass
	case "ssl3":
		tlsConfig.MinVersion = tls.VersionSSL30
	case "tls10":
		tlsConfig.MinVersion = tls.VersionTLS10
	case "tls11":
		tlsConfig.MinVersion = tls.VersionTLS11
	case "tls12":
		tlsConfig.MinVersion = tls.VersionTLS12
	default:
		logrus.Fatalf("Doesn't know tls version '%v', use default. cid '%v'", *srvdata.Flags.minTLSVersion)
	}
	return tlsConfig
}

func getTargetAddr(cid ConnectionID, in net.Addr) (net.TCPAddr, error) {
	var target net.TCPAddr

	var mappedTarget *net.TCPAddr
	if srvdata.targetMap != nil {
		mappedTarget = srvdata.targetMap[in.String()]
	}
	if mappedTarget == nil {
		target = *srvdata.paramTargetTcpAddr
	} else {
		target = *mappedTarget
		logrus.Debugf("Select target address by target map (cid %v) '%v' -> '%v'", cid, in, target)
	}

	if target.IP == nil || target.IP.IsUnspecified() {
		receiveAddr, ok := in.(*net.TCPAddr)
		if !ok {
			logrus.Errorf("Can't cast incoming addr to tcp addr: '%v'", in)
			return net.TCPAddr{}, errors.New("Can't cast incoming addr to tcp addr")
		}
		target.IP = receiveAddr.IP
	} else {
		target.IP = srvdata.paramTargetTcpAddr.IP
	}

	if target.Port == 0 {
		target.Port = srvdata.paramTargetTcpAddr.Port
	}

	logrus.Debugf("Target address for '%v' (cid '%v'): %v", in, cid, target)
	return target, nil
}

func uniqueAppend(s [][]byte, line []byte) [][]byte {
	for _, item := range s {
		if bytes.EqualFold(line, item) {
			logrus.Debugf("uniqueAppend: item %s already existed in slice", line)
			return s
		}
	}
	logrus.Debugf("uniqueAppend: item %s appended into slice", line)
	return append(s, line)
}

func prepare() {
	var err error

	// Init
	*srvdata.Flags.proxyMode = PROXYMODE_HTTP_BUILTIN
	logrus.Infof("Proxy mode: %v", *srvdata.Flags.proxyMode)

	for _, ignoreDomain := range strings.Split(*srvdata.Flags.nonCertDomains, ",") {
		ignoreDomain = strings.TrimSpace(ignoreDomain)
		if ignoreDomain == "" {
			continue
		}
		ignoreDomainRE, err := regexp.Compile(ignoreDomain)
		if err != nil {
			logrus.Errorf("Bad ignore domain regexp '%v': %v", ignoreDomain, err)
		}
		if ignoreDomainRE != nil {
			srvdata.nonCertDomainsRegexps = append(srvdata.nonCertDomainsRegexps, ignoreDomainRE)
		}
	}
	if logrus.GetLevel() >= logrus.InfoLevel {
		regexps := []string{}
		for _, re := range srvdata.nonCertDomainsRegexps {
			regexps = append(regexps, re.String())
		}
		logrus.Info("Non cert domain regexps: ", "['"+strings.Join(regexps, "', '")+"']")
	}

	// cut wellknown header about client ip
	srvdata.cutHeaders = uniqueAppend(srvdata.cutHeaders, []byte(strings.ToUpper("X-Forwarded-For")))
	srvdata.cutHeaders = uniqueAppend(srvdata.cutHeaders, []byte(strings.ToUpper("X-Real-IP")))

	srvdata.realIPHeaderNames = uniqueAppend(srvdata.realIPHeaderNames, []byte("X-Forwarded-For"))
	srvdata.realIPHeaderNames = uniqueAppend(srvdata.realIPHeaderNames, []byte("X-Real-IP"))

	for _, line := range strings.Split(*srvdata.Flags.realIPHeader, ",") {
		line = strings.TrimSpace(line)
		if line != "" {
			srvdata.realIPHeaderNames = uniqueAppend(srvdata.realIPHeaderNames, []byte(line))
			srvdata.cutHeaders = uniqueAppend(srvdata.cutHeaders, []byte(strings.ToUpper(line)))
			if !strings.EqualFold(line, "X-Forwarded-For") && !strings.EqualFold(line, "X-Real-IP") { // X-Forwarded-For/X-Real-IP - appended auto by reverse proxy
				srvdata.realIPHeaderNamesStrings = append(srvdata.realIPHeaderNamesStrings, textproto.CanonicalMIMEHeaderKey(line))
			}
		}
	}

	for _, addHeader := range strings.Split(*srvdata.Flags.additionalHeadersParam, ",") {
		var headerName, headerVal string

		headerParts := strings.SplitN(addHeader, "=", 2)
		if len(headerParts) > 0 {
			srvdata.cutHeaders = uniqueAppend(srvdata.cutHeaders, []byte(strings.ToUpper(headerParts[0])))
			headerName = headerParts[0]
		}
		buf := &bytes.Buffer{}
		buf.WriteString(headerParts[0])
		buf.WriteByte(':')
		if len(headerParts) == 2 {
			buf.WriteString(headerParts[1])
			headerVal = headerParts[1]
		}
		buf.WriteString("\r\n")
		srvdata.additionalHeaders = append(srvdata.additionalHeaders, buf.Bytes()...)
		srvdata.additionalHeadersStringPairs = append(srvdata.additionalHeadersStringPairs, [2]string{textproto.CanonicalMIMEHeaderKey(headerName), headerVal})
	}

	if *srvdata.Flags.inMemoryCertCount > 0 {
		logrus.Infof("Create memory cache for '%v' certificates", *srvdata.Flags.inMemoryCertCount)
		certMemCache, err = lru.New(*srvdata.Flags.inMemoryCertCount)
		if err != nil {
			logrus.Errorf("Can't create memory cache:", err)
			certMemCache = nil
		}
	} else {
		logrus.Info("Memory cache turned off")
	}
	if *srvdata.Flags.certDir == "-" {
		*srvdata.Flags.certDir = ""
	}

	switch *srvdata.Flags.keepAliveModeS {
	case KEEPALIVE_TRANSPARENT_STRING:
		keepAliveMode = KEEPALIVE_TRANSPARENT
	case KEEPALIVE_NO_BACKEND_STRING:
		keepAliveMode = KEEPALIVE_NO_BACKEND
	default:
		logrus.Errorf("Bad keepalive mode: '%v'. Used '%v' instead.", *srvdata.Flags.keepAliveModeS, KEEPALIVE_TRANSPARENT_STRING)
		keepAliveMode = KEEPALIVE_TRANSPARENT
	}
	logrus.Infof("KeepAlive mode: %v", keepAliveMode)

	workingDir, err := os.Getwd()
	logrus.Infof("Working dir '%v', err: %v", workingDir, err)

	// targetConn
	targetAddrS := *srvdata.Flags.targetConnString
	if !strings.ContainsRune(*srvdata.Flags.targetConnString, ':') || // doesn't contain colon (only ipv4 or domain name)
		len(*srvdata.Flags.targetConnString) > 0 && (*srvdata.Flags.targetConnString)[len(*srvdata.Flags.targetConnString)-1] == ']' { // is ipv6 only, without port
		targetAddrS += ":80"
	}
	srvdata.paramTargetTcpAddr, err = net.ResolveTCPAddr("tcp", targetAddrS)
	if err != nil {
		logrus.Panicf("Can't resolve target addr '%v': %v", *srvdata.Flags.targetConnString, err)
	}
	logrus.Info("Target addr: ", srvdata.paramTargetTcpAddr)

	srvdata.subdomainPrefixedForUnion = strings.Split(*srvdata.Flags.subdomainsUnionS, ",")
	for i := range srvdata.subdomainPrefixedForUnion {
		srvdata.subdomainPrefixedForUnion[i] = srvdata.subdomainPrefixedForUnion[i] + "."
	}
	logrus.Info("Subdomain union: ", srvdata.subdomainPrefixedForUnion)

	for _, whiteListDomain := range strings.Split(*srvdata.Flags.whiteList, ",") {
		whiteListDomain = strings.TrimSpace(whiteListDomain)
		if whiteListDomain == "" {
			continue
		}
		if HasPrefixFold(whiteListDomain, "re:") {
			sRegexp := whiteListDomain[len("re:"):]
			re, err := regexp.Compile(sRegexp)
			if err == nil {
				srvdata.whiteListFromParamRe = append(srvdata.whiteListFromParamRe, re)
			} else {
				logrus.Errorf("Bad regexp in whitelist domain args '%v': %v", sRegexp, err)
			}

		} else {
			srvdata.whiteListFromParam = append(srvdata.whiteListFromParam, whiteListDomain)
		}
	}
	sort.Strings(srvdata.whiteListFromParam)
	logrus.Infof("Domains whitelist: %v", srvdata.whiteListFromParam)
	logrus.Infof("Domains whitelist regexps: %v", srvdata.whiteListFromParamRe)

	// init service
	var state stateStruct
	stateBytes, err := ioutil.ReadFile(*srvdata.Flags.stateFilePath)
	if err == nil {
		err = json.Unmarshal(stateBytes, &state)
		if err != nil {
			logrus.Errorf("Can't parse state file '%v': %v", *srvdata.Flags.stateFilePath, err)
		}
	} else {
		logrus.Errorf("Can't read state file '%v': %v", *srvdata.Flags.stateFilePath, err)
	}

	// bindTo
	if *srvdata.Flags.bindToS == "" {
		srvdata.bindTo = []net.TCPAddr{
			{IP: net.IPv6unspecified, Port: DEFAULT_BIND_PORT},
			{IP: net.IPv4zero, Port: DEFAULT_BIND_PORT},
		}
	} else {
		srvdata.bindTo = parseAddressList(*srvdata.Flags.bindToS, DEFAULT_BIND_PORT)
	}

	if len(srvdata.bindTo) == 0 {
		logrus.Fatal("Nothing address to bind")
	}

	// bindHttpValidationTo
	if *srvdata.Flags.bindHTTPValidationToS == "" {
		srvdata.bindHttpValidationTo = []net.TCPAddr{
			{IP: net.IPv6unspecified, Port: DEFAULT_BIND_HTTP_VALIDATION_PORT},
			{IP: net.IPv4zero, Port: DEFAULT_BIND_HTTP_VALIDATION_PORT},
		}
	} else {
		srvdata.bindHttpValidationTo = parseAddressList(*srvdata.Flags.bindHTTPValidationToS, DEFAULT_BIND_HTTP_VALIDATION_PORT)
	}

	if len(srvdata.bindTo) == 0 {
		logrus.Warningf("It has no bind port for http validation. Can use only tls validation.")
	}

	allowedIps := getAllowIPs()
	logrus.Infof("Allowed IPs on start: %v", allowedIps)

	// targetMap
	if *srvdata.Flags.mapTargetS != "" {
		srvdata.targetMap = make(map[string]*net.TCPAddr, strings.Count(*srvdata.Flags.mapTargetS, ",")+1)
		for _, m := range strings.Split(*srvdata.Flags.mapTargetS, ",") {
			equalIndex := strings.Index(m, "=")
			if equalIndex < 0 {
				logrus.Errorf("Error in target-maps, doesn't contain equal sign: %v", m)
				continue
			}

			receiver := resolveAddr(m[:equalIndex])
			if receiver.IP == nil || receiver.IP.IsUnspecified() {
				logrus.Errorf("In map targets receiver must have IP part, but it can't parsed for IP: %v", m)
				continue
			}
			if receiver.Port == 0 {
				receiver.Port = srvdata.bindTo[0].Port
			}

			target := resolveAddr(m[equalIndex+1:])
			if target.Port == 0 {
				target.Port = srvdata.paramTargetTcpAddr.Port
			}
			srvdata.targetMap[receiver.String()] = target
		}
	}
	if logrus.GetLevel() >= logrus.InfoLevel {
		for k, v := range srvdata.targetMap {
			logrus.Printf("Map target '%v' -> '%v'", k, v)
		}
	}

	srvdata.acmeService = &acmeStruct{}
	srvdata.acmeService.timeToRenew = *srvdata.Flags.timeToRenew
	if *srvdata.Flags.acmeTestServer {
		srvdata.acmeService.serverAddress = LETSENCRYPT_STAGING_API_URL
	} else {
		srvdata.acmeService.serverAddress = *srvdata.Flags.acmeServerUrl
	}

	if *srvdata.Flags.serviceAction == "" {
		if state.PrivateKey == nil {
			logrus.Info("Generate private keys")
			state.PrivateKey, err = rsa.GenerateKey(cryptorand.Reader, *srvdata.Flags.privateKeyBits)
			state.changed = true
			if err != nil {
				logrus.Panic("Can't generate private key")
			}
		} else {
			logrus.Debugf("Skip generate keys - it was read from state")
		}

		saveState(state)
	}

	srvdata.acmeService.privateKey = state.PrivateKey

	srvdata.acmeService.Init()

	skipDomainsStartCleaner()
}

func saveState(state stateStruct) {
	if state.changed {
		logrus.Infof("Saving state to '%v'", *srvdata.Flags.stateFilePath)
	} else {
		logrus.Debug("Skip save state becouse it isn't changed")
		return
	}
	stateBytes, err := json.MarshalIndent(&state, "", "    ")
	if err != nil {
		logrus.Errorf("Can't save state to file '%v': %v", *srvdata.Flags.stateFilePath, err)
		return
	}
	err = ioutil.WriteFile(*srvdata.Flags.stateFilePath+".new", stateBytes, STATE_FILEMODE)
	if err != nil {
		logrus.Errorf("Error while write state bytes to file '%v': %v", *srvdata.Flags.stateFilePath+".new", err)
		return
	}

	if _, err := os.Stat(*srvdata.Flags.stateFilePath); !os.IsNotExist(err) {
		logrus.Infof("Rename current state file '%v' -> '%v'", *srvdata.Flags.stateFilePath, *srvdata.Flags.stateFilePath+".old")

		err = os.Rename(*srvdata.Flags.stateFilePath, *srvdata.Flags.stateFilePath+".old")
		if err != nil {
			logrus.Errorf("Can't rename '%v' to '%v': %v", *srvdata.Flags.stateFilePath, *srvdata.Flags.stateFilePath+".old", err)
		}
	} else {
		logrus.Infof("Create new state file '%v'", *srvdata.Flags.stateFilePath)
	}

	err = os.Rename(*srvdata.Flags.stateFilePath+".new", *srvdata.Flags.stateFilePath)
	if err != nil {
		logrus.Errorf("Can't rename '%v' to '%v': %v", *srvdata.Flags.stateFilePath+".new", *srvdata.Flags.stateFilePath, err)
	}
}

// return err if can't start all listeners
func startListeners(addresses []net.TCPAddr) ([]*net.TCPListener, error) {
	if len(addresses) == 0 {
		err := errors.New("listen address list is empty")
		logrus.Errorf("startListeners: %s", err)
		return nil, err
	}
	listeners := make([]*net.TCPListener, 0, len(srvdata.bindTo))
	for _, bindAddr := range addresses {
		// Start listen
		logrus.Infof("Start listen: %v", bindAddr)

		listener, err := net.ListenTCP("tcp", &bindAddr)
		if err == nil {
			listeners = append(listeners, listener)
		} else {
			logrus.Errorf("Can't start listen on '%v': %v", bindAddr, err)
			return nil, err
		}
	}
	return listeners, nil
}

func startTimeLogRotator(logger *lumberjack.Logger) {
	for {
		now := time.Now()
		var sleepUntil time.Time
		switch *srvdata.Flags.logrotateTime {
		case "", "none":
			return // no rotate by time
		case "minutely":
			sleepUntil = time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute()+1, 0, 0, time.Local)
		case "hourly":
			sleepUntil = time.Date(now.Year(), now.Month(), now.Day(), now.Hour()+1, 0, 0, 0, time.Local)
		case "daily":
			sleepUntil = time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, time.Local)
		case "weekly":
			sleepUntil := now.AddDate(0, 0, -int(now.Weekday())+int(time.Monday))                                   // Set to this week monday
			sleepUntil = time.Date(sleepUntil.Year(), sleepUntil.Month(), sleepUntil.Day(), 0, 0, 0, 0, time.Local) // set to midnight
			if sleepUntil.Before(now) {
				sleepUntil = sleepUntil.AddDate(0, 0, 7)
			}
		case "monthly":
			sleepUntil = time.Date(now.Year(), now.Month()+1, 1, 0, 0, 0, 0, time.Local)
		case "yearly":
			sleepUntil = time.Date(now.Year()+1, 1, 1, 0, 0, 0, 0, time.Local)
		default:
			logrus.Errorf("Doesn't know logrotate time interval: '%v'. Turn off time rotation.", *srvdata.Flags.logrotateTime)
			return
		}

		time.Sleep(sleepUntil.Sub(now))
		logrus.Info("Rotate log:", *srvdata.Flags.logrotateTime)
		//nolint:errcheck
		logger.Rotate()
	}
}

func startWork(closeCh chan int) error {
	listeners, err := startListeners(srvdata.bindTo)
	if err != nil {
		closeCh <- 1
		close(closeCh)
		return err
	}

	listenersHttpValidation, err := startListeners(srvdata.bindHttpValidationTo)
	if err != nil {
		closeCh <- 1
		close(closeCh)
		return err
	}

	acceptConnectionsHttpValidation(listenersHttpValidation)

	if listeners == nil {
		var errText string
		if err != nil {
			errText = err.Error()
		}
		mess := "Can't start listener: " + errText
		logrus.Error(mess)
		return errors.New(mess)
	} else {
		acceptConnectionsBuiltinProxy(listeners)
		return nil
	}
}

func stringsContains(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

func stringsSortedAppend(slice []string, s string) (res []string) {
	/*
		It is not very fast and may be optimized. But it simple and code executed rare.
	*/
	res = append(slice, s)
	sort.Strings(res)
	return res
}

func stringsSortedContains(slice []string, s string) bool {
	index := sort.SearchStrings(slice, s)
	return index < len(slice) && slice[index] == s
}

func isBaseDomainLocked(domain string) bool {
	lockFilePath := filepath.Join(*srvdata.Flags.certDir, domain+".lock")
	_, err := os.Stat(lockFilePath)
	fileExists := !os.IsNotExist(err)
	return fileExists
}

func resolveAddr(s string) *net.TCPAddr {
	tcpAddr, err := net.ResolveTCPAddr("tcp", s)
	if err != nil {
		ipAddr, err := net.ResolveIPAddr("ip", s)
		if err != nil {
			logrus.Debugf("Can't resolce address: %v", s)
			return nil
		}
		tcpAddr = &net.TCPAddr{
			IP: ipAddr.IP,
		}
	}

	if tcpAddr.IP.To4() != nil {
		tcpAddr.IP = tcpAddr.IP.To4()
	}
	return tcpAddr
}

func usage() {
	flag.CommandLine.SetOutput(os.Stdout)

	fmt.Println("Version:", VERSION)
	fmt.Println("Website: https://github.com/rekby/lets-proxy")
	fmt.Println("Developer: timofey@koolin.ru")
	fmt.Println()

	flag.PrintDefaults()

	fmt.Print(`
Lock certificates for domain:
If <certificates> contain file <basedomain>.lock - lets-proxy will not try to obtain/renew certificate.
It will handle certificate with existed crt/key file or return error.
Lock domains need to handle https of some domains with own certificate.
Lets-proxy never rewrite crt/key file for locked domains.
For any of domains in <subdomains-union> - check base domain (not subdomain). For example with default settings
file 'domain.com.lock' will lock 'domain.com' and 'www.domain.com' and file 'www.domain.com.lock' will not work for
domain 'www.domain.com'.

Flush caches:
Lets-proxy flush cache by SIGHUP signal (*nix systems), for flush cache without restart the proxy you can:
   kill -SIGHUP <lets-proxy-pid> or killall -SIGHUP lets-proxy
`)

	flag.CommandLine.SetOutput(os.Stderr)
}
