package gmi

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// Line represents a line of a Gemini text response.
type Line interface {
	String() string
}

// A link line.
type LineLink struct {
	URL  string
	Name string
}
type LinePreformattingToggle string // A preformatting toggle line.
type LinePreformattedText string    // A preformatted text line.
type LineHeading1 string            // A first-level heading line.
type LineHeading2 string            // A second-level heading line.
type LineHeading3 string            // A third-level heading line.
type LineListItem string            // An unordered list item line.
type LineQuote string               // A quote line.
type LineText string                // A text line.

func (l LineLink) String() string {
	if l.Name != "" {
		return fmt.Sprintf("=> %s %s", l.URL, l.Name)
	}
	return fmt.Sprintf("=> %s", l.URL)
}
func (l LinePreformattingToggle) String() string {
	return fmt.Sprintf("```%s", string(l))
}
func (l LinePreformattedText) String() string {
	return string(l)
}
func (l LineHeading1) String() string {
	return fmt.Sprintf("# %s", string(l))
}
func (l LineHeading2) String() string {
	return fmt.Sprintf("## %s", string(l))
}
func (l LineHeading3) String() string {
	return fmt.Sprintf("### %s", string(l))
}
func (l LineListItem) String() string {
	return fmt.Sprintf("* %s", string(l))
}
func (l LineQuote) String() string {
	return fmt.Sprintf("> %s", string(l))
}
func (l LineText) String() string {
	return string(l)
}

// Text represents a Gemini text response.
type Text []Line

// Parse parses Gemini text from the provided io.Reader.
func Parse(r io.Reader) Text {
	const spacetab = " \t"
	var t Text
	var pre bool
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "```") {
			pre = !pre
			line = line[3:]
			t = append(t, LinePreformattingToggle(line))
		} else if pre {
			t = append(t, LinePreformattedText(line))
		} else if strings.HasPrefix(line, "=>") {
			line = line[2:]
			line = strings.TrimLeft(line, spacetab)
			split := strings.IndexAny(line, spacetab)
			url := line[:split]
			name := line[split:]
			name = strings.TrimLeft(name, spacetab)
			t = append(t, LineLink{url, name})
		} else if strings.HasPrefix(line, "*") {
			line = line[1:]
			line = strings.TrimLeft(line, spacetab)
			t = append(t, LineListItem(line))
		} else if strings.HasPrefix(line, "###") {
			line = line[3:]
			line = strings.TrimLeft(line, spacetab)
			t = append(t, LineHeading3(line))
		} else if strings.HasPrefix(line, "##") {
			line = line[2:]
			line = strings.TrimLeft(line, spacetab)
			t = append(t, LineHeading2(line))
		} else if strings.HasPrefix(line, "#") {
			line = line[1:]
			line = strings.TrimLeft(line, spacetab)
			t = append(t, LineHeading1(line))
		} else if strings.HasPrefix(line, ">") {
			line = line[1:]
			line = strings.TrimLeft(line, spacetab)
			t = append(t, LineQuote(line))
		} else {
			t = append(t, LineText(line))
		}
	}
	return t
}

// String writes the Gemini text response to a string, and returns it.
func (t Text) String() string {
	var b strings.Builder
	for _, l := range t {
		b.WriteString(l.String())
	}
	return b.String()
}
