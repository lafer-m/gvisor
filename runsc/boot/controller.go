// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package boot

import (
	"errors"
	"fmt"
	"os"
	gtime "time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/control/server"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/control"
	controlpb "gvisor.dev/gvisor/pkg/sentry/control/control_go_proto"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/socket/netstack"
	"gvisor.dev/gvisor/pkg/sentry/state"
	"gvisor.dev/gvisor/pkg/sentry/time"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sentry/watchdog"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/urpc"
	"gvisor.dev/gvisor/runsc/boot/pprof"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/specutils"
)

const (
	// ContMgrCheckpoint checkpoints a container.
	ContMgrCheckpoint = "containerManager.Checkpoint"

	// ContMgrCreateSubcontainer creates a sub-container.
	ContMgrCreateSubcontainer = "containerManager.CreateSubcontainer"

	// ContMgrDestroySubcontainer is used to stop a sub-container and free all
	// associated resources in the sandbox.
	ContMgrDestroySubcontainer = "containerManager.DestroySubcontainer"

	// ContMgrEvent gets stats about the container used by "runsc events".
	ContMgrEvent = "containerManager.Event"

	// ContMgrExecuteAsync executes a command in a container.
	ContMgrExecuteAsync = "containerManager.ExecuteAsync"

	// ContMgrProcesses lists processes running in a container.
	ContMgrProcesses = "containerManager.Processes"

	// ContMgrRestore restores a container from a statefile.
	ContMgrRestore = "containerManager.Restore"

	// ContMgrSignal sends a signal to a container.
	ContMgrSignal = "containerManager.Signal"

	// ContMgrStartSubcontainer starts a sub-container inside a running sandbox.
	ContMgrStartSubcontainer = "containerManager.StartSubcontainer"

	// ContMgrWait waits on the init process of the container and returns its
	// ExitStatus.
	ContMgrWait = "containerManager.Wait"

	// ContMgrWaitPID waits on a process with a certain PID in the sandbox and
	// return its ExitStatus.
	ContMgrWaitPID = "containerManager.WaitPID"

	// ContMgrRootContainerStart starts a new sandbox with a root container.
	ContMgrRootContainerStart = "containerManager.StartRoot"
)

const (
	// NetworkCreateLinksAndRoutes creates links and routes in a network stack.
	NetworkCreateLinksAndRoutes = "Network.CreateLinksAndRoutes"

	// NetworkReplaceIptables replace a iptables in a network stack.
	NetworkReplaceIptables = "Network.ReplaceIPTables"

	// DebugStacks collects sandbox stacks for debugging.
	DebugStacks = "debug.Stacks"
)

// Profiling related commands (see pprof.go for more details).
const (
	ProfileCPU   = "Profile.CPU"
	ProfileHeap  = "Profile.Heap"
	ProfileBlock = "Profile.Block"
	ProfileMutex = "Profile.Mutex"
	ProfileTrace = "Profile.Trace"
)

// Logging related commands (see logging.go for more details).
const (
	LoggingChange = "Logging.Change"
)

// Lifecycle related commands (see lifecycle.go for more details).
const (
	LifecyclePause  = "Lifecycle.Pause"
	LifecycleResume = "Lifecycle.Resume"
)

// Filesystem related commands (see fs.go for more details).
const (
	FsCat = "Fs.Cat"
)

// Usage related commands (see usage.go for more details).
const (
	UsageCollect = "Usage.Collect"
	UsageUsageFD = "Usage.UsageFD"
	UsageReduce  = "Usage.Reduce"
)

// Events related commands (see events.go for more details).
const (
	EventsAttachDebugEmitter = "Events.AttachDebugEmitter"
)

// ControlSocketAddr generates an abstract unix socket name for the given ID.
func ControlSocketAddr(id string) string {
	return fmt.Sprintf("\x00runsc-sandbox.%s", id)
}

// controller holds the control server, and is used for communication into the
// sandbox.
type controller struct {
	// srv is the control server.
	srv *server.Server

	// manager holds the containerManager methods.
	manager *containerManager
}

// newController creates a new controller. The caller must call
// controller.srv.StartServing() to start the controller.
func newController(fd int, l *Loader) (*controller, error) {
	ctrl := &controller{}
	var err error
	ctrl.srv, err = server.CreateFromFD(fd)
	if err != nil {
		return nil, err
	}

	ctrl.manager = &containerManager{
		startChan:       make(chan struct{}),
		startResultChan: make(chan error),
		l:               l,
	}
	ctrl.srv.Register(ctrl.manager)

	if eps, ok := l.k.RootNetworkNamespace().Stack().(*netstack.Stack); ok {
		net := &Network{
			Stack: eps.Stack,
		}
		ctrl.srv.Register(net)
	}

	if l.root.conf.Controls.Controls != nil {
		for _, c := range l.root.conf.Controls.Controls.AllowedControls {
			switch c {
			case controlpb.ControlConfig_EVENTS:
				ctrl.srv.Register(&control.Events{})
			case controlpb.ControlConfig_FS:
				ctrl.srv.Register(&control.Fs{Kernel: l.k})
			case controlpb.ControlConfig_LIFECYCLE:
				ctrl.srv.Register(&control.Lifecycle{Kernel: l.k})
			case controlpb.ControlConfig_LOGGING:
				ctrl.srv.Register(&control.Logging{})
			case controlpb.ControlConfig_PROFILE:
				if l.root.conf.ProfileEnable {
					ctrl.srv.Register(control.NewProfile(l.k))
				}
			case controlpb.ControlConfig_USAGE:
				ctrl.srv.Register(&control.Usage{Kernel: l.k})
			case controlpb.ControlConfig_PROC:
				ctrl.srv.Register(&control.Proc{Kernel: l.k})
			case controlpb.ControlConfig_STATE:
				ctrl.srv.Register(&control.State{Kernel: l.k})
			case controlpb.ControlConfig_DEBUG:
				ctrl.srv.Register(&debug{})
			}
		}
	}

	return ctrl, nil
}

// stopRPCTimeout is the time for clients to complete ongoing RPCs.
const stopRPCTimeout = 15 * gtime.Second

func (c *controller) stop() {
	c.srv.Stop(stopRPCTimeout)
}

// containerManager manages sandbox containers.
type containerManager struct {
	// startChan is used to signal when the root container process should
	// be started.
	startChan chan struct{}

	// startResultChan is used to signal when the root container  has
	// started. Any errors encountered during startup will be sent to the
	// channel. A nil value indicates success.
	startResultChan chan error

	// l is the loader that creates containers and sandboxes.
	l *Loader
}

// StartRoot will start the root container process.
func (cm *containerManager) StartRoot(cid *string, _ *struct{}) error {
	log.Debugf("containerManager.StartRoot, cid: %s", *cid)
	// Tell the root container to start and wait for the result.
	cm.startChan <- struct{}{}
	if err := <-cm.startResultChan; err != nil {
		return fmt.Errorf("starting sandbox: %v", err)
	}
	return nil
}

// Processes retrieves information about processes running in the sandbox.
func (cm *containerManager) Processes(cid *string, out *[]*control.Process) error {
	log.Debugf("containerManager.Processes, cid: %s", *cid)
	return control.Processes(cm.l.k, *cid, out)
}

// CreateArgs contains arguments to the Create method.
type CreateArgs struct {
	// CID is the ID of the container to start.
	CID string

	// FilePayload may contain a TTY file for the terminal, if enabled.
	urpc.FilePayload
}

// CreateSubcontainer creates a container within a sandbox.
func (cm *containerManager) CreateSubcontainer(args *CreateArgs, _ *struct{}) error {
	log.Debugf("containerManager.CreateSubcontainer: %s", args.CID)

	if len(args.Files) > 1 {
		return fmt.Errorf("start arguments must have at most 1 files for TTY")
	}
	var tty *fd.FD
	if len(args.Files) == 1 {
		var err error
		tty, err = fd.NewFromFile(args.Files[0])
		if err != nil {
			return fmt.Errorf("error dup'ing TTY file: %w", err)
		}
	}
	return cm.l.createSubcontainer(args.CID, tty)
}

// StartArgs contains arguments to the Start method.
type StartArgs struct {
	// Spec is the spec of the container to start.
	Spec *specs.Spec

	// Config is the runsc-specific configuration for the sandbox.
	Conf *config.Config

	// CID is the ID of the container to start.
	CID string

	// FilePayload contains, in order:
	//   * stdin, stdout, and stderr (optional: if terminal is disabled).
	//   * file descriptors to connect to gofer to serve the root filesystem.
	urpc.FilePayload
}

// StartSubcontainer runs a created container within a sandbox.
func (cm *containerManager) StartSubcontainer(args *StartArgs, _ *struct{}) error {
	// Validate arguments.
	if args == nil {
		return errors.New("start missing arguments")
	}
	log.Debugf("containerManager.StartSubcontainer, cid: %s, args: %+v", args.CID, args)
	if args.Spec == nil {
		return errors.New("start arguments missing spec")
	}
	if args.Conf == nil {
		return errors.New("start arguments missing config")
	}
	if args.CID == "" {
		return errors.New("start argument missing container ID")
	}
	if len(args.Files) < 1 {
		return fmt.Errorf("start arguments must contain at least one file for the container root gofer")
	}

	// All validation passed, logs the spec for debugging.
	specutils.LogSpec(args.Spec)

	goferFiles := args.Files
	var stdios []*fd.FD
	if !args.Spec.Process.Terminal {
		// When not using a terminal, stdios come as the first 3 files in the
		// payload.
		if l := len(args.Files); l < 4 {
			return fmt.Errorf("start arguments (len: %d) must contain stdios and files for the container root gofer", l)
		}
		var err error
		stdios, err = fd.NewFromFiles(goferFiles[:3])
		if err != nil {
			return fmt.Errorf("error dup'ing stdio files: %w", err)
		}
		goferFiles = goferFiles[3:]
	}
	defer func() {
		for _, fd := range stdios {
			_ = fd.Close()
		}
	}()

	goferFDs, err := fd.NewFromFiles(goferFiles)
	if err != nil {
		return fmt.Errorf("error dup'ing gofer files: %w", err)
	}
	defer func() {
		for _, fd := range goferFDs {
			_ = fd.Close()
		}
	}()

	if err := cm.l.startSubcontainer(args.Spec, args.Conf, args.CID, stdios, goferFDs); err != nil {
		log.Debugf("containerManager.StartSubcontainer failed, cid: %s, args: %+v, err: %v", args.CID, args, err)
		return err
	}
	log.Debugf("Container started, cid: %s", args.CID)
	return nil
}

// DestroySubcontainer stops a container if it is still running and cleans up
// its filesystem.
func (cm *containerManager) DestroySubcontainer(cid *string, _ *struct{}) error {
	log.Debugf("containerManager.DestroySubcontainer, cid: %s", *cid)
	return cm.l.destroySubcontainer(*cid)
}

// ExecuteAsync starts running a command on a created or running sandbox. It
// returns the PID of the new process.
func (cm *containerManager) ExecuteAsync(args *control.ExecArgs, pid *int32) error {
	log.Debugf("containerManager.ExecuteAsync, cid: %s, args: %+v", args.ContainerID, args)
	tgid, err := cm.l.executeAsync(args)
	if err != nil {
		log.Debugf("containerManager.ExecuteAsync failed, cid: %s, args: %+v, err: %v", args.ContainerID, args, err)
		return err
	}
	*pid = int32(tgid)
	return nil
}

// Checkpoint pauses a sandbox and saves its state.
func (cm *containerManager) Checkpoint(o *control.SaveOpts, _ *struct{}) error {
	log.Debugf("containerManager.Checkpoint")
	// TODO(gvisor.dev/issues/6243): save/restore not supported w/ hostinet
	if cm.l.root.conf.Network == config.NetworkHost {
		return errors.New("checkpoint not supported when using hostinet")
	}

	state := control.State{
		Kernel:   cm.l.k,
		Watchdog: cm.l.watchdog,
	}
	return state.Save(o, nil)
}

// RestoreOpts contains options related to restoring a container's file system.
type RestoreOpts struct {
	// FilePayload contains the state file to be restored, followed by the
	// platform device file if necessary.
	urpc.FilePayload

	// SandboxID contains the ID of the sandbox.
	SandboxID string
}

// Restore loads a container from a statefile.
// The container's current kernel is destroyed, a restore environment is
// created, and the kernel is recreated with the restore state file. The
// container then sends the signal to start.
func (cm *containerManager) Restore(o *RestoreOpts, _ *struct{}) error {
	log.Debugf("containerManager.Restore")

	var specFile, deviceFile *os.File
	switch numFiles := len(o.Files); numFiles {
	case 2:
		// The device file is donated to the platform.
		// Can't take ownership away from os.File. dup them to get a new FD.
		fd, err := unix.Dup(int(o.Files[1].Fd()))
		if err != nil {
			return fmt.Errorf("failed to dup file: %v", err)
		}
		deviceFile = os.NewFile(uintptr(fd), "platform device")
		fallthrough
	case 1:
		specFile = o.Files[0]
	case 0:
		return fmt.Errorf("at least one file must be passed to Restore")
	default:
		return fmt.Errorf("at most two files may be passed to Restore")
	}

	// Pause the kernel while we build a new one.
	cm.l.k.Pause()

	p, err := createPlatform(cm.l.root.conf, deviceFile)
	if err != nil {
		return fmt.Errorf("creating platform: %v", err)
	}
	k := &kernel.Kernel{
		Platform: p,
	}
	mf, err := createMemoryFile()
	if err != nil {
		return fmt.Errorf("creating memory file: %v", err)
	}
	k.SetMemoryFile(mf)
	networkStack := cm.l.k.RootNetworkNamespace().Stack()
	cm.l.k = k

	// Set up the restore environment.
	ctx := k.SupervisorContext()
	mntr := newContainerMounter(&cm.l.root, cm.l.k, cm.l.mountHints, kernel.VFS2Enabled)
	if kernel.VFS2Enabled {
		ctx, err = mntr.configureRestore(ctx)
		if err != nil {
			return fmt.Errorf("configuring filesystem restore: %v", err)
		}
	} else {
		renv, err := mntr.createRestoreEnvironment(cm.l.root.conf)
		if err != nil {
			return fmt.Errorf("creating RestoreEnvironment: %v", err)
		}
		fs.SetRestoreEnvironment(*renv)
	}

	// Prepare to load from the state file.
	if eps, ok := networkStack.(*netstack.Stack); ok {
		stack.StackFromEnv = eps.Stack // FIXME(b/36201077)
	}
	info, err := specFile.Stat()
	if err != nil {
		return err
	}
	if info.Size() == 0 {
		return fmt.Errorf("file cannot be empty")
	}

	if cm.l.root.conf.ProfileEnable {
		// pprof.Initialize opens /proc/self/maps, so has to be called before
		// installing seccomp filters.
		pprof.Initialize()
	}

	// Seccomp filters have to be applied before parsing the state file.
	if err := cm.l.installSeccompFilters(); err != nil {
		return err
	}

	// Load the state.
	loadOpts := state.LoadOpts{Source: specFile}
	if err := loadOpts.Load(ctx, k, nil, networkStack, time.NewCalibratedClocks(), &vfs.CompleteRestoreOptions{}); err != nil {
		return err
	}

	// Since we have a new kernel we also must make a new watchdog.
	dogOpts := watchdog.DefaultOpts
	dogOpts.TaskTimeoutAction = cm.l.root.conf.WatchdogAction
	dog := watchdog.New(k, dogOpts)

	// Change the loader fields to reflect the changes made when restoring.
	cm.l.k = k
	cm.l.watchdog = dog
	cm.l.root.procArgs = kernel.CreateProcessArgs{}
	cm.l.restore = true

	// Reinitialize the sandbox ID and processes map. Note that it doesn't
	// restore the state of multiple containers, nor exec processes.
	cm.l.sandboxID = o.SandboxID
	cm.l.mu.Lock()
	eid := execID{cid: o.SandboxID}
	cm.l.processes = map[execID]*execProcess{
		eid: {
			tg: cm.l.k.GlobalInit(),
		},
	}
	cm.l.mu.Unlock()

	// Tell the root container to start and wait for the result.
	cm.startChan <- struct{}{}
	if err := <-cm.startResultChan; err != nil {
		return fmt.Errorf("starting sandbox: %v", err)
	}

	return nil
}

// Wait waits for the init process in the given container.
func (cm *containerManager) Wait(cid *string, waitStatus *uint32) error {
	log.Debugf("containerManager.Wait, cid: %s", *cid)
	err := cm.l.waitContainer(*cid, waitStatus)
	log.Debugf("containerManager.Wait returned, cid: %s, waitStatus: %#x, err: %v", *cid, *waitStatus, err)
	return err
}

// WaitPIDArgs are arguments to the WaitPID method.
type WaitPIDArgs struct {
	// PID is the PID in the container's PID namespace.
	PID int32

	// CID is the container ID.
	CID string
}

// WaitPID waits for the process with PID 'pid' in the sandbox.
func (cm *containerManager) WaitPID(args *WaitPIDArgs, waitStatus *uint32) error {
	log.Debugf("containerManager.Wait, cid: %s, pid: %d", args.CID, args.PID)
	err := cm.l.waitPID(kernel.ThreadID(args.PID), args.CID, waitStatus)
	log.Debugf("containerManager.Wait, cid: %s, pid: %d, waitStatus: %#x, err: %v", args.CID, args.PID, *waitStatus, err)
	return err
}

// SignalDeliveryMode enumerates different signal delivery modes.
type SignalDeliveryMode int

const (
	// DeliverToProcess delivers the signal to the container process with
	// the specified PID. If PID is 0, then the container init process is
	// signaled.
	DeliverToProcess SignalDeliveryMode = iota

	// DeliverToAllProcesses delivers the signal to all processes in the
	// container. PID must be 0.
	DeliverToAllProcesses

	// DeliverToForegroundProcessGroup delivers the signal to the
	// foreground process group in the same TTY session as the specified
	// process. If PID is 0, then the signal is delivered to the foreground
	// process group for the TTY for the init process.
	DeliverToForegroundProcessGroup
)

func (s SignalDeliveryMode) String() string {
	switch s {
	case DeliverToProcess:
		return "Process"
	case DeliverToAllProcesses:
		return "All"
	case DeliverToForegroundProcessGroup:
		return "Foreground Process Group"
	}
	return fmt.Sprintf("unknown signal delivery mode: %d", s)
}

// SignalArgs are arguments to the Signal method.
type SignalArgs struct {
	// CID is the container ID.
	CID string

	// Signo is the signal to send to the process.
	Signo int32

	// PID is the process ID in the given container that will be signaled,
	// relative to the root PID namespace, not the container's.
	// If 0, the root container will be signalled.
	PID int32

	// Mode is the signal delivery mode.
	Mode SignalDeliveryMode
}

// Signal sends a signal to one or more processes in a container. If args.PID
// is 0, then the container init process is used. Depending on the
// args.SignalDeliveryMode option, the signal may be sent directly to the
// indicated process, to all processes in the container, or to the foreground
// process group.
func (cm *containerManager) Signal(args *SignalArgs, _ *struct{}) error {
	log.Debugf("containerManager.Signal: cid: %s, PID: %d, signal: %d, mode: %v", args.CID, args.PID, args.Signo, args.Mode)
	return cm.l.signal(args.CID, args.PID, args.Signo, args.Mode)
}
