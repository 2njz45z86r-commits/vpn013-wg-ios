// SPDX-License-Identifier: MIT
package r013traffic

import (
	"math"
	"strconv"
	"strings"
)

func Amount(bytes uint64) string {
	return compact(float64(bytes), []string{"Б", "КБ", "МБ", "ГБ", "ТБ", "ПБ", "ЭБ"})
}

func Speed(bytesPerSecond float64) string {
	return compact(bytesPerSecond*8, []string{"бит/с", "Кбит/с", "Мбит/с", "Гбит/с", "Тбит/с", "Пбит/с", "Эбит/с", "Збит/с", "Ибит/с"})
}

func compact(input float64, units []string) string {
	if math.IsNaN(input) || math.IsInf(input, 0) || input < 0 {
		return "—"
	}
	value, index := input, 0
	for value >= 1000 && index+1 < len(units) {
		value /= 1000
		index++
	}
	value = math.Round(value*10) / 10
	if value >= 1000 && index+1 < len(units) {
		value /= 1000
		index++
	}
	text := strings.TrimSuffix(strconv.FormatFloat(value, 'f', 1, 64), ".0")
	return strings.ReplaceAll(text, ".", ",") + " " + units[index]
}

type Rate struct{ Received, Sent float64 }
type Sampler struct {
	identity       string
	time           float64
	received, sent uint64
	previous       bool
	latest         *Rate
}

func (s *Sampler) Reset() { *s = Sampler{} }
func (s *Sampler) Sample(identity string, now float64, received, sent *uint64) *Rate {
	if identity == "" || math.IsNaN(now) || math.IsInf(now, 0) || now < 0 || received == nil || sent == nil {
		s.Reset()
		return nil
	}
	valid := s.previous && s.identity == identity && *received >= s.received && *sent >= s.sent && now > s.time && now-s.time <= 30
	if valid && now-s.time < .25 {
		return s.latest
	}
	var result *Rate
	if valid {
		result = &Rate{float64(*received-s.received) / (now - s.time), float64(*sent-s.sent) / (now - s.time)}
	}
	s.identity, s.time, s.received, s.sent, s.previous, s.latest = identity, now, *received, *sent, true, result
	return result
}
