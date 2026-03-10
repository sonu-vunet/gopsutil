// SPDX-License-Identifier: BSD-3-Clause
//go:build aix

package process

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockInvoker struct {
	outputs map[string]string
}

func (m *mockInvoker) Command(name string, arg ...string) ([]byte, error) {
	return m.CommandWithContext(context.Background(), name, arg...)
}

func (m *mockInvoker) CommandWithContext(ctx context.Context, name string, arg ...string) ([]byte, error) {
	key := name
	for _, a := range arg {
		key += " " + a
	}
	if out, ok := m.outputs[key]; ok {
		return []byte(out), nil
	}
	return nil, assert.AnError
}

func TestProcess_AIX_Fields(t *testing.T) {
	originalInvoke := invoke
	defer func() { invoke = originalInvoke }()

	mock := &mockInvoker{
		outputs: map[string]string{
			"ps -o ppid -p 1234":    "PPID\n 1\n",
			"ps -o comm -p 1234":    "COMMAND\n testproc\n",
			"ps -o args -p 1234":    "COMMAND\n testproc --arg1\n",
			"ps -o etimes -p 1234":  "ELAPSED\n 3600\n",
			"ps -o state -p 1234":   "ST\n A\n",
			"ps -o uid -p 1234":     "UID\n 1000\n",
			"ps -o gid -p 1234":     "GID\n 1000\n",
			"ps -o tty -p 1234":     "TT\n pts/0\n",
			"ps -o nice -p 1234":    "NI\n 20\n",
			"ps -o thcount -p 1234": "THCNT\n 4\n",
			"ps -o time -p 1234":    "TIME\n 01:02:03\n",
			"ps -o rssize -p 1234":  "RSS\n 1024\n",
			"ps -o vsz -p 1234":     "VSZ\n 2048\n",
		},
	}
	invoke = mock

	p := &Process{Pid: 1234}

	t.Run("Ppid", func(t *testing.T) {
		ppid, err := p.Ppid()
		assert.NoError(t, err)
		assert.Equal(t, int32(1), ppid)
	})

	t.Run("Name", func(t *testing.T) {
		name, err := p.Name()
		assert.NoError(t, err)
		assert.Equal(t, "testproc", name)
	})

	t.Run("Cmdline", func(t *testing.T) {
		cmd, err := p.Cmdline()
		assert.NoError(t, err)
		assert.Equal(t, "testproc --arg1", cmd)
	})

	t.Run("Status", func(t *testing.T) {
		status, err := p.Status()
		assert.NoError(t, err)
		assert.Equal(t, []string{Running}, status)
	})

	t.Run("Uids", func(t *testing.T) {
		uids, err := p.Uids()
		assert.NoError(t, err)
		assert.Equal(t, []uint32{1000}, uids)
	})

	t.Run("Gids", func(t *testing.T) {
		gids, err := p.Gids()
		assert.NoError(t, err)
		assert.Equal(t, []uint32{1000}, gids)
	})

	t.Run("Terminal", func(t *testing.T) {
		term, err := p.Terminal()
		assert.NoError(t, err)
		assert.Equal(t, "pts/0", term)
	})

	t.Run("Nice", func(t *testing.T) {
		nice, err := p.Nice()
		assert.NoError(t, err)
		assert.Equal(t, int32(20), nice)
	})

	t.Run("NumThreads", func(t *testing.T) {
		n, err := p.NumThreads()
		assert.NoError(t, err)
		assert.Equal(t, int32(4), n)
	})

	t.Run("MemoryInfo", func(t *testing.T) {
		m, err := p.MemoryInfo()
		require.NoError(t, err)
		assert.Equal(t, uint64(1024*1024), m.RSS)
		assert.Equal(t, uint64(2048*1024), m.VMS)
	})

	t.Run("Times", func(t *testing.T) {
		times, err := p.Times()
		assert.NoError(t, err)
		assert.Equal(t, &cpu.TimesStat{User: 3723.0}, times)
	})

	t.Run("CreateTime", func(t *testing.T) {
		ctime, err := p.CreateTime()
		assert.NoError(t, err)
		assert.True(t, ctime > 0)
		// Check if it's roughly 1 hour ago (mock etimes is 3600)
		now := time.Now().Unix()
		expected := (now - 3600) * 1000
		assert.InDelta(t, expected, ctime, 2000) // 2 second tolerance
	})

	t.Run("NumFDs_OpenFiles", func(t *testing.T) {
		td := t.TempDir()
		t.Setenv("HOST_PROC", td)

		pidDir := filepath.Join(td, "1234")
		fdDir := filepath.Join(pidDir, "fd")
		err := os.MkdirAll(fdDir, 0755)
		assert.NoError(t, err)

		// Create some dummy fds as symlinks
		f1 := filepath.Join(fdDir, "0")
		f2 := filepath.Join(fdDir, "1")
		target := filepath.Join(td, "target")
		os.WriteFile(target, []byte("test"), 0644)

		os.Symlink(target, f1)
		os.Symlink(target, f2)

		num, err := p.NumFDs()
		assert.NoError(t, err)
		assert.Equal(t, int32(2), num)

		files, err := p.OpenFiles()
		assert.NoError(t, err)
		assert.Len(t, files, 2)
	})

	t.Run("PidsWithContext", func(t *testing.T) {
		td := t.TempDir()
		t.Setenv("HOST_PROC", td)

		// Create some pid dirs
		os.MkdirAll(filepath.Join(td, "1"), 0755)
		os.MkdirAll(filepath.Join(td, "1234"), 0755)
		os.MkdirAll(filepath.Join(td, "not_a_pid"), 0755)

		pids, err := PidsWithContext(context.Background())
		assert.NoError(t, err)
		assert.ElementsMatch(t, []int32{1, 1234}, pids)
	})
}

func TestParsePsTime(t *testing.T) {
	tests := []struct {
		input    string
		expected float64
	}{
		{"01:02:03", 3723},
		{"02:03", 123},
		{"1-01:02:03", 86400 + 3723},
	}

	for _, tt := range tests {
		got, err := parsePsTime(tt.input)
		assert.NoError(t, err)
		assert.Equal(t, tt.expected, got)
	}
}
