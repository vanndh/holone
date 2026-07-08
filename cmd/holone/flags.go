package main

func normalizeScanArgs(args []string) []string {
	if len(args) == 0 || len(args[0]) == 0 || args[0][0] == '-' {
		return args
	}
	out := append([]string{}, args[1:]...)
	out = append(out, args[0])
	return out
}
