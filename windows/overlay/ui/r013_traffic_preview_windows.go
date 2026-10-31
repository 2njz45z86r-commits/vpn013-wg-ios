//go:build r013preview

// SPDX-License-Identifier: MIT
package ui

import (
	"image"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/amnezia-vpn/amneziawg-windows-client/r013"
	"github.com/lxn/walk"
)

// BI_RGB window captures have no meaningful alpha channel. Walk forwards that
// unused byte into RGBA; PNG would then discard real native RGB text pixels.
// Normalize alpha before encoding, retaining every captured RGB value exactly.
func r013OpaquePreviewCapture(value *image.RGBA) {
	for offset := 3; offset < len(value.Pix); offset += 4 {
		value.Pix[offset] = 255
	}
}

// Actual native controls receive synthetic counter snapshots in the separately
// tagged fixture. No owner tunnel or network setting is used by this scenario.
func verifyR013TrafficPreview(window *ManageTunnelsWindow, destination string, syncUI func(func()), checks *[]string) (failure string) {
	check := func(ok bool, name string) bool {
		if !ok {
			failure = name
			return false
		}
		*checks = append(*checks, name)
		return true
	}
	var received, sent uint64 = 2_000_000_000, 1_500_000
	shot := r013CurrentSnapshot{name: "Synthetic traffic display", active: true, detail: "Всего: ↓ 2 ГБ · ↑ 1,5 МБ", received: &received, sent: &sent, target: r013.CurrentPingTarget{Identity: "synthetic-traffic-a"}}
	apply := func() { syncUI(func() { c := window.currentCard; c.apply(shot, c.revision.Load()) }) }
	detail := func() string {
		var value string
		syncUI(func() { value = window.currentCard.detail.Text() })
		return value
	}
	syncUI(func() {
		c := window.currentCard
		if c.cancel != nil {
			c.cancel()
		}
		c.trafficSampler.Reset()
	})
	apply()
	if !check(strings.Contains(detail(), "Скорость: ↓ — · ↑ —"), "First snapshot never invents a transfer rate") {
		return
	}
	time.Sleep(600 * time.Millisecond)
	received += 250_000
	sent += 62_500
	apply()
	if !check(strings.Contains(detail(), "Мбит/с") && strings.Contains(detail(), "Кбит/с"), "Native UI uses adaptive megabit and kilobit speed units") {
		return
	}
	if !check(strings.Contains(detail(), "2 ГБ") && strings.Contains(detail(), "1,5 МБ"), "Transferred totals keep independent byte units") {
		return
	}
	syncUI(func() {
		bitmap, err := walk.NewBitmapFromWindow(window)
		if err != nil {
			failure = "Native traffic capture failed"
			return
		}
		defer bitmap.Dispose()
		image, err := bitmap.ToImage()
		if err != nil {
			failure = "Native traffic image conversion failed"
			return
		}
		file, err := os.Create(filepath.Join(filepath.Dir(destination), "r013-traffic-adaptive.png"))
		if err != nil {
			failure = "Native traffic image write failed"
			return
		}
		defer file.Close()
		r013OpaquePreviewCapture(image)
		if png.Encode(file, image) != nil {
			failure = "Native traffic PNG encoding failed"
		}
	})
	if failure != "" {
		return
	}
	shot.received = nil
	shot.sent = nil
	apply()
	if !check(!strings.Contains(detail(), "бит/с"), "Missing counters clear the previous native rate") {
		return
	}
	shot.received = &received
	shot.sent = &sent
	shot.target.Identity = "synthetic-traffic-b"
	apply()
	if !check(strings.Contains(detail(), "Скорость: ↓ — · ↑ —"), "A changed server starts with no stale rate") {
		return
	}
	time.Sleep(600 * time.Millisecond)
	received += 64
	sent += 32
	apply()
	if !check(strings.Contains(detail(), "бит/с") && !strings.Contains(detail(), "Кбит/с") && !strings.Contains(detail(), "Мбит/с"), "Native speed scales down when traffic falls") {
		return
	}
	received = 0
	sent = 0
	apply()
	if !check(strings.Contains(detail(), "Скорость: ↓ — · ↑ —"), "Counter reset never reuses a previous native rate") {
		return
	}
	shot.active = false
	shot.received = nil
	shot.sent = nil
	apply()
	if !check(!strings.Contains(detail(), "бит/с"), "Disconnected native card has no old speed") {
		return
	}
	return
}
