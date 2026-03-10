// SPDX-License-Identifier: BSD-3-Clause
//go:build aix
// +build aix

package process

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/internal/common"
	"github.com/shirou/gopsutil/v4/net"
)

type MemoryMapsStat struct {
	Path         string `json:"path"`
	Rss          uint64 `json:"rss"`
	Size         uint64 `json:"size"`
	Pss          uint64 `json:"pss"`
	SharedClean  uint64 `json:"sharedClean"`
	SharedDirty  uint64 `json:"sharedDirty"`
	PrivateClean uint64 `json:"privateClean"`
	PrivateDirty uint64 `json:"privateDirty"`
	Referenced   uint64 `json:"referenced"`
	Anonymous    uint64 `json:"anonymous"`
	Swap         uint64 `json:"swap"`
}

type MemoryInfoExStat struct {
	RSS    uint64 `json:"rss"`
	VMS    uint64 `json:"vms"`
	Shared uint64 `json:"shared"`
	Text   uint64 `json:"text"`
	Lib    uint64 `json:"lib"`
	Data   uint64 `json:"data"`
	Dirty  uint64 `json:"dirty"`
}

func pidsWithContext(ctx context.Context) ([]int32, error) {
	return readPidsFromDir(common.HostProcWithContext(ctx))
}

func ProcessesWithContext(ctx context.Context) ([]*Process, error) {
	out := []*Process{}

	pids, err := PidsWithContext(ctx)
	if err != nil {
		return out, err
	}

	for _, pid := range pids {
		p, err := NewProcessWithContext(ctx, pid)
		if err != nil {
			continue
		}
		out = append(out, p)
	}

	return out, nil
}

func (p *Process) PpidWithContext(ctx context.Context) (int32, error) {
	v, err := p.getPsField(ctx, "ppid")
	if err != nil {
		return 0, err
	}
	i, err := strconv.ParseInt(v, 10, 32)
	if err != nil {
		return 0, err
	}
	return int32(i), nil
}

func (p *Process) NameWithContext(ctx context.Context) (string, error) {
	return p.getPsField(ctx, "comm")
}

func (p *Process) TgidWithContext(ctx context.Context) (int32, error) {
	return 0, common.ErrNotImplementedError
}

func (p *Process) ExeWithContext(ctx context.Context) (string, error) {
	// AIX doesn't have a direct way to get the executable path from /proc
	// except if we use the cmdline guess.
	cmdline, err := p.CmdlineSliceWithContext(ctx)
	if err != nil || len(cmdline) == 0 {
		return "", err
	}
	exe := cmdline[0]
	if filepath.IsAbs(exe) {
		return exe, nil
	}
	// Try searching in PATH
	if strings.Contains(exe, "/") {
		cwd, err := p.CwdWithContext(ctx)
		if err == nil {
			return filepath.Join(cwd, exe), nil
		}
	}
	return "", common.ErrNotImplementedError
}

func (p *Process) CmdlineWithContext(ctx context.Context) (string, error) {
	return p.getPsField(ctx, "args")
}

func (p *Process) CmdlineSliceWithContext(ctx context.Context) ([]string, error) {
	cmdline, err := p.CmdlineWithContext(ctx)
	if err != nil {
		return nil, err
	}
	return strings.Fields(cmdline), nil
}

func (p *Process) createTimeWithContext(ctx context.Context) (int64, error) {
	v, err := p.getPsField(ctx, "etimes")
	if err != nil {
		return 0, err
	}
	etimes := common.ParseUptime(v)
	return (time.Now().Unix() - int64(etimes)) * 1000, nil
}

func (p *Process) CwdWithContext(ctx context.Context) (string, error) {
	path := common.HostProcWithContext(ctx, strconv.Itoa(int(p.Pid)), "cwd")
	resolved, err := os.Readlink(path)
	if err != nil {
		// Fallback to checking if the process exists
		if _, statErr := os.Stat(common.HostProcWithContext(ctx, strconv.Itoa(int(p.Pid)))); os.IsNotExist(statErr) {
			return "", ErrorProcessNotRunning
		}
		return "", err
	}
	return resolved, nil
}

func (p *Process) StatusWithContext(ctx context.Context) ([]string, error) {
	v, err := p.getPsField(ctx, "state")
	if err != nil {
		return nil, err
	}
	s := ""
	switch v {
	case "A":
		s = Running
	case "S":
		s = Sleep
	case "T":
		s = Stop
	case "Z":
		s = Zombie
	case "W":
		s = "swapped" // Custom or map to something else?
	case "I":
		s = Idle
	default:
		s = convertStatusChar(v)
	}
	return []string{s}, nil
}

func (p *Process) ForegroundWithContext(ctx context.Context) (bool, error) {
	return false, common.ErrNotImplementedError
}

func (p *Process) UidsWithContext(ctx context.Context) ([]uint32, error) {
	v, err := p.getPsField(ctx, "uid")
	if err != nil {
		return nil, err
	}
	u, err := strconv.ParseUint(v, 10, 32)
	if err != nil {
		return nil, err
	}
	return []uint32{uint32(u)}, nil
}

func (p *Process) GidsWithContext(ctx context.Context) ([]uint32, error) {
	v, err := p.getPsField(ctx, "gid")
	if err != nil {
		return nil, err
	}
	g, err := strconv.ParseUint(v, 10, 32)
	if err != nil {
		return nil, err
	}
	return []uint32{uint32(g)}, nil
}

func (p *Process) GroupsWithContext(ctx context.Context) ([]uint32, error) {
	// On AIX, 'groups' in ps output shows multiple group names/IDs
	v, err := p.getPsField(ctx, "groups")
	if err != nil {
		return nil, err
	}
	fields := strings.Fields(v)
	var ret []uint32
	for _, f := range fields {
		g, err := strconv.ParseUint(f, 10, 32)
		if err == nil {
			ret = append(ret, uint32(g))
		}
	}
	return ret, nil
}

func (p *Process) TerminalWithContext(ctx context.Context) (string, error) {
	return p.getPsField(ctx, "tty")
}

func (p *Process) NiceWithContext(ctx context.Context) (int32, error) {
	v, err := p.getPsField(ctx, "nice")
	if err != nil {
		return 0, err
	}
	i, err := strconv.ParseInt(v, 10, 32)
	if err != nil {
		return 0, err
	}
	return int32(i), nil
}

func (p *Process) IOniceWithContext(ctx context.Context) (int32, error) {
	return 0, common.ErrNotImplementedError
}

func (p *Process) RlimitWithContext(ctx context.Context) ([]RlimitStat, error) {
	return nil, common.ErrNotImplementedError
}

func (p *Process) RlimitUsageWithContext(ctx context.Context, gatherUsed bool) ([]RlimitStat, error) {
	return nil, common.ErrNotImplementedError
}

func (p *Process) IOCountersWithContext(ctx context.Context) (*IOCountersStat, error) {
	return nil, common.ErrNotImplementedError
}

func (p *Process) NumCtxSwitchesWithContext(ctx context.Context) (*NumCtxSwitchesStat, error) {
	return nil, common.ErrNotImplementedError
}

func (p *Process) NumFDsWithContext(ctx context.Context) (int32, error) {
	path := common.HostProcWithContext(ctx, strconv.Itoa(int(p.Pid)), "fd")
	d, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer d.Close()
	fnames, err := d.Readdirnames(-1)
	if err != nil {
		return 0, err
	}
	return int32(len(fnames)), nil
}

func (p *Process) NumThreadsWithContext(ctx context.Context) (int32, error) {
	v, err := p.getPsField(ctx, "thcount")
	if err != nil {
		return 0, err
	}
	i, err := strconv.ParseInt(v, 10, 32)
	if err != nil {
		return 0, err
	}
	return int32(i), nil
}

func (p *Process) ThreadsWithContext(ctx context.Context) (map[int32]*cpu.TimesStat, error) {
	// AIX: ps -mo thid,utime,stime -p PID
	// The -m flag expands the process to show its threads
	out, err := invoke.CommandWithContext(ctx, "ps", "-mo", "thid,utime,stime", "-p", strconv.Itoa(int(p.Pid)))
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) < 2 {
		return nil, fmt.Errorf("unexpected ps output: %s", out)
	}

	ret := make(map[int32]*cpu.TimesStat)
	// Skip header
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		// If the line starts with a '-', it's likely a separator or parent line in some ps formats
		if fields[0] == "-" {
			continue
		}
		tid, _ := strconv.ParseInt(fields[0], 10, 32)
		utime, _ := parsePsTime(fields[1])
		stime, _ := parsePsTime(fields[2])

		ret[int32(tid)] = &cpu.TimesStat{
			User:   utime,
			System: stime,
		}
	}
	return ret, nil
}

func (p *Process) TimesWithContext(ctx context.Context) (*cpu.TimesStat, error) {
	v, err := p.getPsField(ctx, "time")
	if err != nil {
		return nil, err
	}
	t, err := parsePsTime(v)
	if err != nil {
		return nil, err
	}
	return &cpu.TimesStat{
		User: t,
	}, nil
}

func (p *Process) CPUAffinityWithContext(ctx context.Context) ([]int32, error) {
	return nil, common.ErrNotImplementedError
}

func (p *Process) MemoryInfoWithContext(ctx context.Context) (*MemoryInfoStat, error) {
	// Try rssize first (AIX specific), then fallback to rss (POSIX)
	rss, err := p.getPsField(ctx, "rssize")
	if err != nil {
		rss, err = p.getPsField(ctx, "rss")
		if err != nil {
			return nil, err
		}
	}
	vms, err := p.getPsField(ctx, "vsz")
	if err != nil {
		vms, err = p.getPsField(ctx, "vsize")
		if err != nil {
			return nil, err
		}
	}

	rssUint, _ := strconv.ParseUint(rss, 10, 64)
	vmsUint, _ := strconv.ParseUint(vms, 10, 64)

	return &MemoryInfoStat{
		RSS: rssUint * 1024,
		VMS: vmsUint * 1024,
	}, nil
}

func (p *Process) MemoryInfoExWithContext(ctx context.Context) (*MemoryInfoExStat, error) {
	// Use the same logic as MemoryInfo
	mi, err := p.MemoryInfoWithContext(ctx)
	if err != nil {
		return nil, err
	}
	return &MemoryInfoExStat{
		RSS: mi.RSS,
		VMS: mi.VMS,
	}, nil
}

func (p *Process) PageFaultsWithContext(ctx context.Context) (*PageFaultsStat, error) {
	fields, err := p.getPsFields(ctx, []string{"minflt", "majflt"})
	if err != nil {
		return nil, err
	}
	min, _ := strconv.ParseUint(fields["minflt"], 10, 64)
	maj, _ := strconv.ParseUint(fields["majflt"], 10, 64)
	return &PageFaultsStat{
		MinorFaults: min,
		MajorFaults: maj,
	}, nil
}

func (p *Process) ChildrenWithContext(ctx context.Context) ([]*Process, error) {
	pids, err := PidsWithContext(ctx)
	if err != nil {
		return nil, err
	}
	var ret []*Process
	for _, pid := range pids {
		child, err := NewProcessWithContext(ctx, pid)
		if err != nil {
			continue
		}
		ppid, err := child.PpidWithContext(ctx)
		if err != nil {
			continue
		}
		if ppid == p.Pid {
			ret = append(ret, child)
		}
	}
	return ret, nil
}

func (p *Process) OpenFilesWithContext(ctx context.Context) ([]OpenFilesStat, error) {
	path := common.HostProcWithContext(ctx, strconv.Itoa(int(p.Pid)), "fd")
	d, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	fnames, err := d.Readdirnames(-1)
	if err != nil {
		return nil, err
	}
	var ret []OpenFilesStat
	for _, fname := range fnames {
		fd, err := strconv.ParseUint(fname, 10, 64)
		if err != nil {
			continue
		}
		fpath, err := os.Readlink(filepath.Join(path, fname))
		if err != nil {
			continue
		}
		ret = append(ret, OpenFilesStat{
			Fd:   fd,
			Path: fpath,
		})
	}
	return ret, nil
}

func (p *Process) ConnectionsWithContext(ctx context.Context) ([]net.ConnectionStat, error) {
	return nil, common.ErrNotImplementedError
}

func (p *Process) ConnectionsMaxWithContext(ctx context.Context, max int) ([]net.ConnectionStat, error) {
	return nil, common.ErrNotImplementedError
}

func (p *Process) MemoryMapsWithContext(ctx context.Context, grouped bool) (*[]MemoryMapsStat, error) {
	return nil, common.ErrNotImplementedError
}

func (p *Process) EnvironWithContext(ctx context.Context) ([]string, error) {
	return nil, common.ErrNotImplementedError
}

// Internal functions

func (p *Process) getPsField(ctx context.Context, field string) (string, error) {
	out, err := invoke.CommandWithContext(ctx, "ps", "-o", field, "-p", strconv.Itoa(int(p.Pid)))
	if err != nil {
		return "", err
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) < 2 {
		return "", fmt.Errorf("unexpected ps output: %s", out)
	}
	return strings.TrimSpace(lines[1]), nil
}

func (p *Process) getPsFields(ctx context.Context, fields []string) (map[string]string, error) {
	ret := make(map[string]string)
	for _, f := range fields {
		v, err := p.getPsField(ctx, f)
		if err != nil {
			return nil, err
		}
		ret[strings.ToLower(f)] = v
	}
	return ret, nil
}

func parsePsTime(s string) (float64, error) {
	var days, hours, mins, secs float64
	var err error

	if strings.Contains(s, "-") {
		parts := strings.Split(s, "-")
		days, err = strconv.ParseFloat(parts[0], 64)
		if err != nil {
			return 0, err
		}
		s = parts[1]
	}

	parts := strings.Split(s, ":")
	if len(parts) == 3 {
		hours, err = strconv.ParseFloat(parts[0], 64)
		if err != nil {
			return 0, err
		}
		mins, err = strconv.ParseFloat(parts[1], 64)
		if err != nil {
			return 0, err
		}
		secs, err = strconv.ParseFloat(parts[2], 64)
		if err != nil {
			return 0, err
		}
	} else if len(parts) == 2 {
		mins, err = strconv.ParseFloat(parts[0], 64)
		if err != nil {
			return 0, err
		}
		secs, err = strconv.ParseFloat(parts[1], 64)
		if err != nil {
			return 0, err
		}
	} else {
		return 0, fmt.Errorf("invalid time format: %s", s)
	}

	return days*86400 + hours*3600 + mins*60 + secs, nil
}

func readPidsFromDir(path string) ([]int32, error) {
	var ret []int32

	d, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer d.Close()

	fnames, err := d.Readdirnames(-1)
	if err != nil {
		return nil, err
	}
	for _, fname := range fnames {
		if !strictIntPtrn.MatchString(fname) {
			continue
		}
		pid, err := strconv.ParseInt(fname, 10, 32)
		if err != nil {
			continue
		}
		ret = append(ret, int32(pid))
	}

	return ret, nil
}
