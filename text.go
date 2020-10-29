package gemini

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// Line represents a line of a Gemini text response.
type Line interface {
	String() string
	line() // private function to prevent other packages from implementing Line
}

// A link line.
type LineLink struct {
	URL  string
	Name string
}

// A preformatting toggle line.
type LinePreformattingToggle string

// A preformatted text line.
type LinePreformattedText string

// A first-level heading line.
type LineHeading1 string

// A second-level heading line.
type LineHeading2 string

// A third-level heading line.
type LineHeading3 string

// An unordered list item line.
type LineListItem string

// A quote line.
type LineQuote string

// A text line.
type LineText string

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

func (l LineLink) line()                {}
func (l LinePreformattingToggle) line() {}
func (l LinePreformattedText) line()    {}
func (l LineHeading1) line()            {}
func (l LineHeading2) line()            {}
func (l LineHeading3) line()            {}
func (l LineListItem) line()            {}
func (l LineQuote) line()               {}
func (l LineText) line()                {}

// Text represents a Gemini text response.
type Text []Line

// ParseText parses Gemini text from the provided io.Reader.
func ParseText(r io.Reader) Text {
	var t Text
	ParseLines(r, func(line Line) {
		t = append(t, line)
	})
	return t
}

// ParseLines parses Gemini text from the provided io.Reader.
// It calls handler with each line that it parses.
func ParseLines(r io.Reader, handler func(Line)) {
	const spacetab = " \t"
	var pre bool
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		var line Line
		text := scanner.Text()
		if strings.HasPrefix(text, "```") {
			pre = !pre
			text = text[3:]
			line = LinePreformattingToggle(text)
		} else if pre {
			line = LinePreformattedText(text)
		} else if strings.HasPrefix(text, "=>") {
			text = text[2:]
			text = strings.TrimLeft(text, spacetab)
			split := strings.IndexAny(text, spacetab)
			if split == -1 {
				// text is a URL
				line = LineLink{URL: text}
			} else {
				url := text[:split]
				name := text[split:]
				name = strings.TrimLeft(name, spacetab)
				line = LineLink{url, name}
			}
		} else if strings.HasPrefix(text, "*") {
			text = text[1:]
			text = strings.TrimLeft(text, spacetab)
			line = LineListItem(text)
		} else if strings.HasPrefix(text, "###") {
			text = text[3:]
			text = strings.TrimLeft(text, spacetab)
			line = LineHeading3(text)
		} else if strings.HasPrefix(text, "##") {
			text = text[2:]
			text = strings.TrimLeft(text, spacetab)
			line = LineHeading2(text)
		} else if strings.HasPrefix(text, "#") {
			text = text[1:]
			text = strings.TrimLeft(text, spacetab)
			line = LineHeading1(text)
		} else if strings.HasPrefix(text, ">") {
			text = text[1:]
			text = strings.TrimLeft(text, spacetab)
			line = LineQuote(text)
		} else {
			line = LineText(text)
		}
		handler(line)
	}
}

// String writes the Gemini text response to a string and returns it.
func (t Text) String() string {
	var b strings.Builder
	for _, l := range t {
		b.WriteString(l.String())
		b.WriteByte('\n')
	}
	return b.String()
}
