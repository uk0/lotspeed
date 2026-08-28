package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestEveryCommandIsDispatchable 防的是一个真实发生过的缺陷: abtest.go 写了 809 行
// 实现 + 17 个单测全绿, 但 main.go 的 switch 里没有 case "abtest", 于是整个命令是
// 死代码。Go 不报未使用的**函数** (只报未使用的局部变量和 import), 所以编译和测试
// 都发现不了 —— 单测直接调 cmdABTest, 绕过了 dispatch。
//
// 判据: 每个 func cmdXxx(args []string) error 都必须在 main.go 里被调用一次。
func TestEveryCommandIsDispatchable(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	mainSrc, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	// 只认命令签名 func cmdX(args []string) error —— cmdModel/cmdTune 这类都是它。
	sig := regexp.MustCompile(`func (cmd[A-Z]\w*)\(\w+ \[\]string\) error`)
	var found int
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, mm := range sig.FindAllStringSubmatch(string(b), -1) {
			name := mm[1]
			found++
			if !strings.Contains(string(mainSrc), name+"(os.Args") {
				t.Errorf("%s 在 %s 里定义了但 main.go 的 dispatch 里没有调用点 —— "+
					"这个命令在生产上无法执行 (死代码)", name, f)
			}
		}
	}
	if found < 5 {
		t.Fatalf("只匹配到 %d 个命令函数, 正则大概率失配了", found)
	}
	t.Logf("%d 个命令函数, 全部可 dispatch", found)
}
