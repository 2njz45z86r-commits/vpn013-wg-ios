// SPDX-License-Identifier: MIT
package ui

import (
	"bytes"
	_ "embed"
	"github.com/lxn/walk"
	"image/png"
)

//go:embed vpn013_wordmark.png
var r013WordmarkPNG []byte

func r013Wordmark() (*walk.Bitmap, error) {
	image, err := png.Decode(bytes.NewReader(r013WordmarkPNG))
	if err != nil {
		return nil, err
	}
	return walk.NewBitmapFromImageForDPI(image, 96)
}
