package web

import "embed"

// Dist - UI fayllari (index.html, style.css, app.js) binary ichiga kiritiladi.
//
//go:embed dist
var Dist embed.FS
