package defang

import "strings"

func URL(raw string) string {
	replacer := strings.NewReplacer(
		"http://", "hxxp://",
		"https://", "hxxps://",
		"HTTP://", "HXXP://",
		"HTTPS://", "HXXPS://",
		".", "[.]",
	)
	return replacer.Replace(raw)
}

func Refang(raw string) string {
	replacer := strings.NewReplacer(
		"hxxps://", "https://",
		"hxxp://", "http://",
		"HXXPS://", "HTTPS://",
		"HXXP://", "HTTP://",
		"[.]", ".",
	)
	return replacer.Replace(raw)
}
