//go:build windows

// autoconv-gui is a thin graphical front-end for AutoConvJmsSub on Windows.
// It edits config.yaml (subscription URL + local port), toggles run-at-login,
// and starts/stops the actual converter by launching autoconv.exe (which must
// sit next to this GUI). The GUI itself performs no conversion — it is a
// launcher/config editor, so the core service stays decoupled.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"

	"github.com/lxn/walk"
	//lint:ignore ST1001 declarative DSL is designed to be dot-imported
	. "github.com/lxn/walk/declarative"
	"github.com/lxn/win"
	"golang.org/x/sys/windows/registry"
	"gopkg.in/yaml.v3"
)

// debugLog appends a line to gui-debug.log next to the executable. Because the
// GUI is built with -H windowsgui there is no console, so this file is the only
// way to see what happened during startup.
func debugLog(msg string) {
	f, err := os.OpenFile(filepath.Join(exeDir(), "gui-debug.log"),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = fmt.Fprintln(f, msg)
}

// u16 converts a Go string to a UTF-16 pointer for native Win32 calls.
func u16(s string) *uint16 { p, _ := syscall.UTF16PtrFromString(s); return p }

// fatalBox shows a native Win32 message box. It works even when walk itself
// failed to initialize (unlike walk.MsgBox), so it's safe to call from a
// top-level panic recover.
func fatalBox(caption, text string) {
	win.MessageBox(0, u16(text), u16(caption), win.MB_OK|win.MB_ICONERROR)
}

const (
	appName = "AutoConvJmsSub"
	runKey  = `Software\Microsoft\Windows\CurrentVersion\Run`
)

// exeDir returns the directory holding this GUI executable; config.yaml and
// autoconv.exe are expected alongside it.
func exeDir() string {
	p, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(p)
}

func cfgPath() string     { return filepath.Join(exeDir(), "config.yaml") }
func autoconvExe() string { return filepath.Join(exeDir(), "autoconv.exe") }

// settings is the subset of config.yaml the GUI edits.
type settings struct {
	sub  string // subscriptions.default
	port string // port part of server.addr
	auto bool   // run-at-login (registry)
}

// loadSettings reads the current values from config.yaml. Missing file or keys
// fall back to sensible defaults.
func loadSettings() settings {
	s := settings{port: "25500"}
	data, err := os.ReadFile(cfgPath())
	if err != nil {
		return s
	}
	var raw map[string]any
	if yaml.Unmarshal(data, &raw) != nil {
		return s
	}
	if subs, ok := raw["subscriptions"].(map[string]any); ok {
		if v, ok := subs["default"].(string); ok {
			s.sub = v
		}
	}
	if srv, ok := raw["server"].(map[string]any); ok {
		if addr, ok := srv["addr"].(string); ok {
			if i := strings.LastIndex(addr, ":"); i >= 0 {
				s.port = addr[i+1:]
			}
		}
	}
	return s
}

// saveSettings writes subscription + port back into config.yaml, preserving any
// other keys already present. Note: YAML comments are not preserved on rewrite.
func saveSettings(s settings) error {
	raw := map[string]any{}
	if data, err := os.ReadFile(cfgPath()); err == nil {
		_ = yaml.Unmarshal(data, &raw)
	}

	subs, _ := raw["subscriptions"].(map[string]any)
	if subs == nil {
		subs = map[string]any{}
	}
	subs["default"] = s.sub
	raw["subscriptions"] = subs

	srv, _ := raw["server"].(map[string]any)
	if srv == nil {
		srv = map[string]any{}
	}
	srv["addr"] = "127.0.0.1:" + s.port
	raw["server"] = srv

	out, err := yaml.Marshal(raw)
	if err != nil {
		return err
	}
	return os.WriteFile(cfgPath(), out, 0o600)
}

// getAutostart reports whether a run-at-login entry exists.
func getAutostart() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	_, _, err = k.GetStringValue(appName)
	return err == nil
}

// setAutostart adds or removes the run-at-login entry pointing at autoconv.exe.
func setAutostart(on bool) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if on {
		cmd := fmt.Sprintf(`"%s" -config "%s"`, autoconvExe(), cfgPath())
		return k.SetStringValue(appName, cmd)
	}
	err = k.DeleteValue(appName)
	if err == registry.ErrNotExist {
		return nil
	}
	return err
}

// running holds the launched autoconv.exe process, if any.
var running *exec.Cmd

func startService() error {
	if _, err := os.Stat(autoconvExe()); err != nil {
		return fmt.Errorf("找不到 autoconv.exe（应与本程序同目录）")
	}
	cmd := exec.Command(autoconvExe(), "-config", cfgPath())
	cmd.Dir = exeDir()
	if err := cmd.Start(); err != nil {
		return err
	}
	running = cmd
	return nil
}

func stopService() {
	if running != nil && running.Process != nil {
		_ = running.Process.Kill()
		running = nil
	}
}

func main() {
	// GUI has no console; capture any startup panic to gui-debug.log and a
	// native message box so failures are visible instead of silent.
	defer func() {
		if r := recover(); r != nil {
			debugLog(fmt.Sprintf("PANIC: %v\n%s", r, debug.Stack()))
			fatalBox("AutoConvJmsSub 启动崩溃", fmt.Sprintf("%v\n\n详情见同目录 gui-debug.log", r))
		}
	}()

	debugLog("=== gui start ===")
	s := loadSettings()
	debugLog(fmt.Sprintf("settings loaded: port=%s subLen=%d", s.port, len(s.sub)))
	s.auto = getAutostart()
	debugLog(fmt.Sprintf("autostart=%v", s.auto))

	var mw *walk.MainWindow
	var subEdit, portEdit *walk.LineEdit
	var autoCheck *walk.CheckBox
	var statusLabel *walk.Label

	setStatus := func(text string) {
		if statusLabel != nil {
			_ = statusLabel.SetText(text)
		}
	}

	debugLog("building main window...")
	_, err := MainWindow{
		AssignTo: &mw,
		Title:    "AutoConvJmsSub 配置",
		Size:     Size{Width: 460, Height: 300},
		Layout:   VBox{},
		Children: []Widget{
			Label{Text: "JMS 订阅 URL:"},
			LineEdit{AssignTo: &subEdit, Text: s.sub},
			Label{Text: "本地端口:"},
			LineEdit{AssignTo: &portEdit, Text: s.port},
			CheckBox{AssignTo: &autoCheck, Text: "开机自启（登录时自动启动服务）", Checked: s.auto},
			Composite{
				Layout: HBox{},
				Children: []Widget{
					PushButton{
						Text: "保存并启动",
						OnClicked: func() {
							ns := settings{
								sub:  strings.TrimSpace(subEdit.Text()),
								port: strings.TrimSpace(portEdit.Text()),
								auto: autoCheck.Checked(),
							}
							if ns.port == "" {
								ns.port = "25500"
							}
							if err := saveSettings(ns); err != nil {
								walk.MsgBox(mw, "错误", "保存配置失败：\n"+err.Error(), walk.MsgBoxIconError)
								return
							}
							if err := setAutostart(ns.auto); err != nil {
								walk.MsgBox(mw, "警告", "开机自启设置失败：\n"+err.Error(), walk.MsgBoxIconWarning)
							}
							stopService()
							if err := startService(); err != nil {
								walk.MsgBox(mw, "错误", "启动服务失败：\n"+err.Error(), walk.MsgBoxIconError)
								setStatus("启动失败")
								return
							}
							setStatus("运行中 → http://127.0.0.1:" + ns.port + "/sub")
						},
					},
					PushButton{
						Text: "停止",
						OnClicked: func() {
							stopService()
							setStatus("已停止")
						},
					},
				},
			},
			Label{AssignTo: &statusLabel, Text: "未启动。填写订阅与端口后点“保存并启动”。"},
			Label{Text: "提示：把 autoconv.exe 与本程序放在同一文件夹。"},
		},
	}.Run()
	if err != nil {
		debugLog("window Run error: " + err.Error())
		fatalBox("AutoConvJmsSub 界面创建失败", err.Error()+"\n\n详情见同目录 gui-debug.log")
		return
	}
	debugLog("window closed")

	// Window closed — leave the service running only if autostart is on; otherwise
	// stop it so we don't orphan the process.
	if !getAutostart() {
		stopService()
	}
}
