package masker

import (
	"sort"
	"strings"

	"github.com/promptshieldhq/promptshield-gateway/internal/detector"
	"github.com/rs/zerolog/log"
)

// Mask replaces each entity span with a [TYPE] token.
// Offsets are Unicode character positions (as returned by the Python detector), not bytes.
func Mask(text string, entities []detector.Entity) string {
	if text == "" || len(entities) == 0 {
		return text
	}

	runes := []rune(text)
	runeLen := len(runes)

	valid := make([]detector.Entity, 0, len(entities))
	for _, e := range entities {
		if e.Start >= 0 && e.End <= runeLen && e.Start < e.End {
			valid = append(valid, e)
		} else {
			log.Warn().Str("entity_type", e.Type).Int("start", e.Start).Int("end", e.End).Int("text_rune_len", runeLen).Msg("masker: dropping out-of-bounds span")
		}
	}
	if len(valid) == 0 {
		return text
	}

	sort.Slice(valid, func(i, j int) bool {
		if valid[i].Start != valid[j].Start {
			return valid[i].Start < valid[j].Start
		}
		return valid[i].End > valid[j].End
	})

	var buf strings.Builder
	buf.Grow(len(text))
	pos := 0
	for _, e := range valid {
		if e.Start < pos {
			continue // overlapping span, skip
		}
		buf.WriteString(string(runes[pos:e.Start]))
		buf.WriteByte('[')
		buf.WriteString(e.Type)
		buf.WriteByte(']')
		pos = e.End
	}
	buf.WriteString(string(runes[pos:]))
	return buf.String()
}
