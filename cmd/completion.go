package cmd

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

var completionCmd = &cobra.Command{
	Use:                   "completion [bash|zsh|fish|powershell]",
	Short:                 "Generate completion script",
	Long:                  "",
	DisableFlagsInUseLine: true,
	ValidArgs:             []string{"bash", "zsh", "fish", "powershell", "clink"},
	Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
	Run: func(cmd *cobra.Command, args []string) {
		switch args[0] {
		case "bash":
			cmd.Root().GenBashCompletion(os.Stdout)
		case "zsh":
			cmd.Root().GenZshCompletion(os.Stdout)
		case "fish":
			cmd.Root().GenFishCompletion(os.Stdout, true)
		case "powershell":
			cmd.Root().GenPowerShellCompletionWithDesc(os.Stdout)
		case "clink":
			genClinkCompletion(os.Stdout)
		}
	},
}

func genClinkCompletion(w io.Writer) {
	fmt.Fprintf(w, `local vssh_autocomplete = clink.generator(1)

local function starts_with(str, start)
	return string.sub(str, 1, string.len(start)) == start
end

local function get_targets(prefix)
	local handle = io.popen("vssh __complete " .. prefix .. " 2> nul")
	local result = handle:read("*a")
	local rc = {handle:close()}
	if rc[3] ~= 0 then
		return {}
	end

	local targets = {}
	for target in string.gmatch(result, "%%S+") do
		if starts_with(target, prefix) then
			table.insert(targets, target)
		end
	end
	return targets
end

function vssh_autocomplete:generate(line_state, match_builder)
	local matchCount = 0
	local prefix = string.match(line_state:getline(), "%%w+$")

	for _, target in ipairs(get_targets(prefix)) do
		match_builder:addmatch(target)
		matchCount = matchCount + 1
	end
	return true --Always stop propagation
end`)
}
