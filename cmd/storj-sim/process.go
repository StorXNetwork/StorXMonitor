// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"storj.io/storj/satellite/newrelic"

	"github.com/zeebo/errs"
	"go.uber.org/zap/zapcore"

	"golang.org/x/sync/errgroup"

	"storj.io/common/processgroup"
	"storj.io/common/sync2"
)

type NewRelicConfig struct {
	NewRelicAPIKey        string
	LogLevel              string
	NewRelicTimeInterval  time.Duration
	NewRelicMaxBufferSize int
	NewRelicMaxRetries    int
}

// Processes contains list of processes.
type Processes struct {
	Output    *PrefixWriter
	Directory string
	List      []*Process

	FailFast       bool
	MaxStartupWait time.Duration
	NewRelicConfig NewRelicConfig
}

const storjSimMaxLineLen = 10000

// NewProcesses returns a group of processes.
func NewProcesses(dir string, failfast bool, newRelicConfig NewRelicConfig) *Processes {
	return &Processes{
		Output:    NewPrefixWriter("sim", storjSimMaxLineLen, os.Stdout),
		Directory: dir,
		List:      nil,

		FailFast:       failfast,
		MaxStartupWait: time.Minute,

		NewRelicConfig: newRelicConfig,
	}
}

// Exec executes a command on all processes.
func (processes *Processes) Exec(ctx context.Context, command string) error {
	defer func() { _ = processes.Output.Flush() }()

	var group *errgroup.Group
	if processes.FailFast {
		group, ctx = errgroup.WithContext(ctx)
	} else {
		group = &errgroup.Group{}
	}
	processes.Start(ctx, group, command)
	return group.Wait()
}

// Start executes all processes using specified errgroup.Group.
func (processes *Processes) Start(ctx context.Context, group *errgroup.Group, command string) {
	for _, p := range processes.List {
		process := p
		group.Go(func() error {
			err := process.Exec(ctx, command)
			if errors.Is(err, context.Canceled) {
				err = nil
			}
			if err != nil {
				err = fmt.Errorf("%v failed: %w", process.Name, err)
			}
			return err
		})
	}
}

// Env returns environment flags for other nodes.
func (processes *Processes) Env() []string {
	var env []string
	for _, process := range processes.List {
		env = append(env, process.Info.Env()...)
	}
	return env
}

// Close closes all the processes and their resources.
func (processes *Processes) Close() error {
	defer func() { _ = processes.Output.Flush() }()

	var errlist errs.Group
	for _, process := range processes.List {
		errlist.Add(process.Close())
	}
	return errlist.Err()
}

// Info represents public information about the process.
type Info struct {
	Name       string
	Executable string
	Address    string
	Directory  string
	ID         string
	Pid        int
	Extra      []EnvVar
}

// EnvVar represents an environment variable like Key=Value.
type EnvVar struct {
	Key   string
	Value string
}

// AddExtra appends an extra environment variable to the process info.
func (info *Info) AddExtra(key, value string) {
	info.Extra = append(info.Extra, EnvVar{Key: key, Value: value})
}

// Env returns process flags.
func (info *Info) Env() []string {
	name := strings.ToUpper(info.Name)

	name = strings.Map(func(r rune) rune {
		switch {
		case '0' <= r && r <= '9':
			return r
		case 'a' <= r && r <= 'z':
			return r
		case 'A' <= r && r <= 'Z':
			return r
		default:
			return '_'
		}
	}, name)

	var env []string
	if info.ID != "" {
		env = append(env, name+"_ID="+info.ID)
	}
	if info.Address != "" {
		env = append(env, name+"_ADDR="+info.Address)
	}
	if info.ID != "" && info.Address != "" {
		env = append(env, name+"_URL="+info.ID+"@"+info.Address)
	}
	if info.Directory != "" {
		env = append(env, name+"_DIR="+info.Directory)
	}
	if info.Pid != 0 {
		env = append(env, name+"_PID="+strconv.Itoa(info.Pid))
	}
	for _, extra := range info.Extra {
		env = append(env, name+"_"+strings.ToUpper(extra.Key)+"="+extra.Value)
	}
	return env
}

// Arguments contains arguments based on the main command.
type Arguments map[string][]string

// Process is a type for monitoring the process.
type Process struct {
	processes *Processes

	Info

	Delay  time.Duration
	Wait   []*sync2.Fence
	Status struct {
		Started sync2.Fence
		Exited  sync2.Fence
	}

	ExecBefore map[string]func(*Process) error
	Arguments  Arguments

	stdout WriterFlusher
	stderr WriterFlusher

	NewRelicConfig NewRelicConfig
}

// New creates a process which can be run in the specified directory.
func (processes *Processes) New(info Info) *Process {
	output := processes.Output.Prefixed(info.Name)

	process := &Process{
		processes: processes,

		Info:       info,
		ExecBefore: map[string]func(*Process) error{},
		Arguments:  Arguments{},

		stdout: output,
		stderr: output,

		NewRelicConfig: processes.NewRelicConfig,
	}

	processes.List = append(processes.List, process)
	return process
}

// WaitForStart ensures that process will wait on dependency before starting.
func (process *Process) WaitForStart(dependency *Process) {
	process.Wait = append(process.Wait, &dependency.Status.Started)
}

// WaitForExited ensures that process will wait on dependency before starting.
func (process *Process) WaitForExited(dependency *Process) {
	process.Wait = append(process.Wait, &dependency.Status.Exited)
}

// newRelicWriter implements io.Writer to send logs to New Relic
type newRelicWriter struct {
	core        *newrelic.LogInterceptor
	processName string
}

func (w *newRelicWriter) Write(p []byte) (n int, err error) {
	line := strings.TrimSpace(string(p))

	// Simple entry - let interceptor handle all parsing
	entry := zapcore.Entry{
		Level:      zapcore.InfoLevel,
		Time:       time.Now(),
		Message:    line,
		Caller:     zapcore.NewEntryCaller(0, "", 0, false),
		LoggerName: w.processName,
	}

	w.core.InterceptLog(entry)
	return len(p), nil
}

// Exec runs the process using the arguments for a given command.
func (process *Process) Exec(ctx context.Context, command string) (err error) {
	defer func() { _ = process.stdout.Flush() }()
	defer func() { _ = process.stderr.Flush() }()

	// ensure that we always release all status fences
	defer process.Status.Started.Release()
	defer process.Status.Exited.Release()

	ctx, cancelProcess := context.WithCancel(ctx)
	defer cancelProcess()

	// wait for dependencies to start
	for _, fence := range process.Wait {
		if !fence.Wait(ctx) {
			return fmt.Errorf("waiting dependencies: %w", ctx.Err())
		}
	}

	// in case we have an explicit delay then sleep
	if process.Delay > 0 {
		if !sync2.Sleep(ctx, process.Delay) {
			return fmt.Errorf("waiting for delay: %w", ctx.Err())
		}
	}

	if exec, ok := process.ExecBefore[command]; ok {
		if err := exec(process); err != nil {
			return fmt.Errorf("executing pre-actions: %w", err)
		}
	}

	executable := process.Executable

	// use executable inside the directory, if it exists
	localExecutable := exe(filepath.Join(process.Directory, executable))
	if _, err := os.Lstat(localExecutable); !os.IsNotExist(err) {
		executable = localExecutable
	}

	if _, ok := process.Arguments[command]; !ok {
		fmt.Fprintf(process.processes.Output, "%s running: %s\n", process.Name, command)
		//TODO: This doesn't look right, but keeping the same behaviour as before.
		return nil
	}

	cmd := exec.CommandContext(ctx, executable, process.Arguments[command]...)
	cmd.Dir = process.processes.Directory
	cmd.Env = append(os.Environ(), "STORJ_LOG_NOTIME=1")

	// Setup New Relic if enabled
	if process.NewRelicConfig.NewRelicAPIKey != "" {
		// Create New Relic interceptor with log level filtering
		newRelicCore := newrelic.NewLogInterceptor(process.NewRelicConfig.NewRelicAPIKey, process.NewRelicConfig.LogLevel, process.NewRelicConfig.NewRelicTimeInterval, process.NewRelicConfig.NewRelicMaxBufferSize, process.NewRelicConfig.NewRelicMaxRetries)
		newRelicWriter := &newRelicWriter{core: newRelicCore, processName: process.Name}

		// Send both to console and New Relic (with level filtering)
		cmd.Stdout = io.MultiWriter(process.stdout, newRelicWriter)
		cmd.Stderr = io.MultiWriter(process.stderr, newRelicWriter)
	} else {
		// Simple output - no New Relic
		cmd.Stdout = process.stdout
		cmd.Stderr = process.stderr
	}

	// ensure that it is part of this process group
	processgroup.Setup(cmd)

	if printCommands {
		fmt.Fprintf(process.processes.Output, "%s running: %v\n", process.Name, strings.Join(cmd.Args, " "))
		defer func() {
			fmt.Fprintf(process.processes.Output, "%s exited (code:%d): %v\n", process.Name, cmd.ProcessState.ExitCode(), err)
		}()
	}

	// start the process
	err = cmd.Start()
	if err != nil {
		return err
	}
	process.Info.Pid = cmd.Process.Pid

	f, err := os.Create(filepath.Join(process.Directory, fmt.Sprintf("%d_%s_pid.txt", process.Info.Pid, time.Now().Format("20240101_120000"))))
	if err != nil {
		return err
	}

	_, err = f.WriteString(strconv.Itoa(process.Info.Pid) + "\n" +
		process.Info.Address + "\n" +
		process.Info.Directory + "\n" +
		process.Info.Name + "\n" +
		process.Info.ID + "\n" +
		process.Info.Executable)
	if err != nil {
		return err
	}

	_ = f.Close()

	if command == "setup" || process.Address == "" {
		// during setup we aren't starting the addresses, so we can release the dependencies immediately
		process.Status.Started.Release()
	} else {
		// release started when we are able to connect to the process address
		go func() {
			defer process.Status.Started.Release()

			err := process.waitForAddress(process.processes.MaxStartupWait)
			if err != nil {
				fmt.Fprintf(process.processes.Output, "failed to wait startup: %v", err)
				cancelProcess()
			}
		}()
	}

	// wait for process completion
	err = cmd.Wait()
	if errors.Is(err, context.Canceled) && ctx.Err() != nil {
		// Ignore error caused by context cancellation.
		err = nil
	}
	// clear the error if the process was killed
	if status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok {
		if status.Signaled() && status.Signal() == os.Kill {
			err = nil
		}
	}

	return err
}

// waitForAddress will monitor starting when we are able to start the process.
func (process *Process) waitForAddress(maxStartupWait time.Duration) error {
	start := time.Now()
	for !process.Status.Started.Released() {
		if tryConnect(process.Info.Address) {
			return nil
		}

		// wait a bit before retrying to reduce load
		time.Sleep(50 * time.Millisecond)

		if time.Since(start) > maxStartupWait {
			return fmt.Errorf("%s did not start in required time %v", process.Name, maxStartupWait)
		}
	}
	return nil
}

// tryConnect will try to connect to the process public address.
func tryConnect(address string) bool {
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return false
	}
	// write empty byte slice to trigger refresh on connection
	_, _ = conn.Write([]byte{})
	// ignoring errors, because we only care about being able to connect
	_ = conn.Close()
	return true
}

// Close closes process resources.
func (process *Process) Close() error { return nil }

func exe(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}
