// +build !windows

package main

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/Sirupsen/logrus"
	"github.com/sevlyar/go-daemon"
)

type User struct {
	Name           string
	HomeDir        string
	UserId         uint32
	DefaultGroupId uint32
}

var (
	daemonContext *daemon.Context // need global var for prevent close (and unlock) pid-file
	osSignals     = make(chan os.Signal, 1)
)

// return true if it is child process
func daemonize() bool {

	daemonContext = &daemon.Context{}

	if *srvdata.Flags.runAs != "" {
		userName := *srvdata.Flags.runAs
		user, err := userLookup(userName)
		if err != nil {
			logrus.Fatalf("Can't lookup runas user '%v': %v", userName, err)
		}

		logrus.Infof("Parse runas '%v' as %v:%v", *srvdata.Flags.runAs, user.UserId, user.DefaultGroupId)
		daemonContext.Credential = &syscall.Credential{
			Uid: user.UserId,
			Gid: user.DefaultGroupId,
		}
		daemonContext.WorkDir = user.HomeDir
	}

	if *srvdata.Flags.workingDir != "" {
		daemonContext.WorkDir = *srvdata.Flags.workingDir
	}
	logrus.Infof("Daemon working dir: %v", daemonContext.WorkDir)

	if *srvdata.Flags.pidFilePath != "" {
		pidPath := *srvdata.Flags.pidFilePath
		if !filepath.IsAbs(pidPath) && daemonContext.WorkDir != "" {
			pidPath = filepath.Join(daemonContext.WorkDir, pidPath)
		}
		daemonContext.PidFileName = pidPath
		logrus.Infof("Pidfile: %v", daemonContext.PidFileName)
	}

	if *srvdata.Flags.stdErrToFile != "" {
		if filepath.IsAbs(*srvdata.Flags.stdErrToFile) {
			daemonContext.LogFileName = *srvdata.Flags.stdErrToFile
		} else {
			daemonContext.LogFileName = filepath.Join(daemonContext.WorkDir, *srvdata.Flags.stdErrToFile)
		}

	}

	child, err := daemonContext.Reborn()
	if err != nil {
		logrus.Fatalf("Can't start daemon process: %v", err)
	}

	if child == nil {
		logrus.Info("Start as daemon child")

		if *srvdata.Flags.runAs != "" && os.Getuid() == 0 {
			logrus.Fatal("Start with uid 0 instead runas")
			logFilePath := *srvdata.Flags.logOutput
			if logFilePath == "" {
				logFilePath = "FATAL_ERROR.txt"
			}
			if !filepath.IsAbs(logFilePath) && daemonContext.WorkDir != "" {
				logFilePath = filepath.Join(daemonContext.WorkDir, logFilePath)
			}
			logFile, _ := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, DEFAULT_FILE_MODE)
			if logFile != nil {
				//nolint:errcheck
				logFile.WriteString("Start with uid 0 instead runas\n")
				logFile.Close()
			}
		}

		return true
	} else {
		logrus.Info("Start as daemons parent")
		return false
	}
}

// "os/user".Lookup need cgo and can't used when binary is cross-compiled.
// use own lookup
func userLookup(login string) (*User, error) {
	var isId bool = false
	_, err := parseUint32(login)
	if err == nil {
		isId = true
	}

	loginBytes := []byte(login)

	passwdFile, err := os.Open("/etc/passwd")
	if passwdFile != nil {
		defer passwdFile.Close()
	}
	if err != nil {
		return nil, err
	}

	splitBytes := []byte(":")
	scanner := bufio.NewScanner(passwdFile)
	var userLine []byte
	var userLineParts [][]byte
	for scanner.Scan() {
		line := scanner.Bytes()
		lineParts := bytes.SplitN(line, splitBytes, 7)
		if len(lineParts) < 6 {
			logrus.Warnf("Short passwd line '%s'", line)
			continue
		}

		if isId && bytes.Equal(lineParts[2], loginBytes) ||
			!isId && bytes.Equal(lineParts[0], loginBytes) {
			userLine = line
			userLineParts = lineParts
			break
		}
	}

	if scanner.Err() != nil {
		return nil, err
	}
	if userLineParts == nil {
		return nil, errors.New("User not found")
	}

	user := User{
		Name:    string(userLineParts[0]),
		HomeDir: string(userLineParts[5]),
	}

	user.UserId, err = parseUint32(string(userLineParts[2]))
	if err != nil {
		logrus.Errorf("Can't parse user id '%s' from passwd line '%s': %v", userLineParts[2], userLine, err)
		return nil, errors.New("Can't parse user id")
	}

	user.DefaultGroupId, err = parseUint32(string(userLineParts[3]))
	if err != nil {
		logrus.Errorf("Can't parse users group id '%s' from passwd line '%s': %v", userLineParts[3], userLine, err)
		return nil, errors.New("Can't parse group id")
	}

	return &user, nil
}

func parseUint32(s string) (uint32, error) {
	res, err := strconv.ParseUint(s, 10, 32)
	if err == nil {
		return uint32(res), nil
	} else {
		return 0, err
	}
}

func signalWorker() {
	signal.Notify(osSignals, syscall.SIGHUP)

	for s := range osSignals {
		switch s {
		case syscall.SIGHUP:
			logrus.Info("Flush cache by SIGHUP")
			certificateCacheFlushMem()
			skipDomainsFlush()
		}
	}
}
