package frontend

import (
	"embed"
	"io/fs"
)

// Assets holds the compiled frontend distribution files embedded for Wails.
//
//go:embed all:dist
var Assets embed.FS

// DistFS returns the embedded dist sub-filesystem for the Wails asset server.
func DistFS() (fs.FS, error) {
	return fs.Sub(Assets, "dist")
}
