package webui

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var embeddedFiles embed.FS

// DistFS returns the embedded production build of the pgveil Web Console.
func DistFS() (fs.FS, error) {
	return fs.Sub(embeddedFiles, "dist")
}
