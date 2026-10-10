package cli

import (
	"bytes"
	"fmt"
	"io"
	"sort"
	"strings"
)

var commands = []string{
	"pack", "unpack", "verify", "split", "batch", "connect", "usb list", "flash", "info", "loader", "nuke",
	"autoloader create", "autoloader extract", "autoloader verify", "autoloader loaders",
	"qnx6 mkfs", "qnx6 script", "qnx6 fsck", "qnx6 compact", "qnx6 audit", "qnx6 repair-names", "qnx6 read", "qnx6 verify", "qnx6 mount",
	"bar template", "bar update", "bar ids", "bar verify", "bar install",
	"raw dump", "raw nvram", "rcfs read", "rcfs verify", "rcfs extract", "rcfs modify", "rcfs vmdk", "vmdk list",
}

func complete(words []string, out io.Writer) error {
	prefix := ""
	if len(words) > 0 {
		prefix = words[len(words)-1]
		words = words[:len(words)-1]
	}
	set := map[string]bool{}
	if len(words) == 0 {
		for _, c := range commands {
			set[strings.Fields(c)[0]] = true
		}
		for _, c := range []string{"--help", "--version", "--help-complete", "--completion-file", "--completion-file-pwsh"} {
			set[c] = true
		}
	} else {
		name := words[0]
		for _, c := range commands {
			fields := strings.Fields(c)
			if len(fields) == 2 && fields[0] == name && len(words) == 1 {
				set[fields[1]] = true
			}
		}
		if len(words) >= 2 {
			candidate := strings.Join(words[:2], " ")
			for _, c := range commands {
				if c == candidate {
					name = c
					break
				}
			}
		}
		if strings.HasPrefix(prefix, "-") {
			var usage bytes.Buffer
			if err := Run(append(strings.Fields(name), "--help"), io.Discard, &usage, "completion"); err != nil {
				return nil
			}
			for _, line := range strings.Split(usage.String(), "\n") {
				fields := strings.Fields(line)
				if len(fields) > 0 && strings.HasPrefix(fields[0], "-") {
					option := strings.TrimLeft(fields[0], "-")
					set["--"+option] = true
					if len(option) == 1 {
						set["-"+option] = true
					}
				}
			}
		}
	}
	var choices []string
	for s := range set {
		if strings.HasPrefix(s, prefix) {
			choices = append(choices, s)
		}
	}
	sort.Strings(choices)
	for _, s := range choices {
		if _, err := fmt.Fprintln(out, s); err != nil {
			return err
		}
	}
	return nil
}

const bashCompletion = `_bb10mt_complete() {
  local cur="${COMP_WORDS[COMP_CWORD]}"
  local candidates
  candidates="$("${COMP_WORDS[0]}" --complete "${COMP_WORDS[@]:1}")"
  COMPREPLY=()
  while IFS= read -r candidate; do
    COMPREPLY+=("$candidate")
  done < <(compgen -W "$candidates" -- "$cur")
}
complete -o default -F _bb10mt_complete bb10mt bb10mt-go bb10mt.exe bb10mt-go.exe
`
const pwshCompletion = `Register-ArgumentCompleter -Native -CommandName bb10mt,bb10mt-go,bb10mt.exe,bb10mt-go.exe -ScriptBlock {
  param($wordToComplete, $commandAst, $cursorPosition)
  $exe = $commandAst.GetCommandName()
  $words = @($commandAst.CommandElements | Select-Object -Skip 1 | ForEach-Object { $_.Extent.Text })
  if ([string]::IsNullOrEmpty($wordToComplete)) { $words += '' }
  & $exe --complete @words | ForEach-Object {
    [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
  }
}
`
