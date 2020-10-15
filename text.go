package gmi

import (
	"bufio"
	"fmt"
	"html"
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
			if split == -1 {
				// line is a URL
				t = append(t, LineLink{URL: line})
			} else {
				url := line[:split]
				name := line[split:]
				name = strings.TrimLeft(name, spacetab)
				t = append(t, LineLink{url, name})
			}
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

// String writes the Gemini text response to a string and returns it.
func (t Text) String() string {
	var b strings.Builder
	for _, l := range t {
		b.WriteString(l.String())
		b.WriteByte('\n')
	}
	return b.String()
}

// HTML returns the Gemini text response as HTML.
func (t Text) HTML() string {
	var b strings.Builder
	var pre bool
	var list bool
	for _, l := range t {
		if _, ok := l.(LineListItem); ok {
			if !list {
				list = true
				fmt.Fprint(&b, "<ul>\n")
			}
		} else if list {
			list = false
			fmt.Fprint(&b, "</ul>\n")
		}
		switch l.(type) {
		case LineLink:
			link := l.(LineLink)
			url := html.EscapeString(link.URL)
			name := html.EscapeString(link.Name)
			if name == "" {
				name = url
			}
			fmt.Fprintf(&b, "<p><a href='%s'>%s</a></p>\n", url, name)
		case LinePreformattingToggle:
			pre = !pre
			if pre {
				fmt.Fprint(&b, "<pre>\n")
			} else {
				fmt.Fprint(&b, "</pre>\n")
			}
		case LinePreformattedText:
			text := string(l.(LinePreformattedText))
			fmt.Fprintf(&b, "%s\n", html.EscapeString(text))
		case LineHeading1:
			text := string(l.(LineHeading1))
			fmt.Fprintf(&b, "<h1>%s</h1>\n", html.EscapeString(text))
		case LineHeading2:
			text := string(l.(LineHeading2))
			fmt.Fprintf(&b, "<h2>%s</h2>\n", html.EscapeString(text))
		case LineHeading3:
			text := string(l.(LineHeading3))
			fmt.Fprintf(&b, "<h3>%s</h3>\n", html.EscapeString(text))
		case LineListItem:
			text := string(l.(LineListItem))
			fmt.Fprintf(&b, "<li>%s</li>\n", html.EscapeString(text))
		case LineQuote:
			text := string(l.(LineQuote))
			fmt.Fprintf(&b, "<blockquote>%s</blockquote>\n", html.EscapeString(text))
		case LineText:
			text := string(l.(LineText))
			if text == "" {
				fmt.Fprint(&b, "<br>\n")
			} else {
				fmt.Fprintf(&b, "<p>%s</p>\n", html.EscapeString(text))
			}
		}
	}
	if pre {
		fmt.Fprint(&b, "</pre>\n")
	}
	if list {
		fmt.Fprint(&b, "</ul>\n")
	}
	return b.String()
}
