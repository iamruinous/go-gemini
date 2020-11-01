// +build ignore

// This example illustrates a gemtext to HTML converter.

package main

import (
	"fmt"
	"html"
	"strings"

	"git.sr.ht/~adnano/go-gemini"
)

func main() {
	text := gemini.Text{
		gemini.LineHeading1("Hello, world!"),
		gemini.LineText("This is a gemini text document."),
	}

	html := textToHTML(text)
	fmt.Print(html)
}

// textToHTML returns the Gemini text response as HTML.
func textToHTML(text gemini.Text) string {
	var b strings.Builder
	var pre bool
	var list bool
	for _, l := range text {
		if _, ok := l.(gemini.LineListItem); ok {
			if !list {
				list = true
				fmt.Fprint(&b, "<ul>\n")
			}
		} else if list {
			list = false
			fmt.Fprint(&b, "</ul>\n")
		}
		switch l := l.(type) {
		case gemini.LineLink:
			url := html.EscapeString(l.URL)
			name := html.EscapeString(l.Name)
			if name == "" {
				name = url
			}
			fmt.Fprintf(&b, "<p><a href='%s'>%s</a></p>\n", url, name)
		case gemini.LinePreformattingToggle:
			pre = !pre
			if pre {
				fmt.Fprint(&b, "<pre>\n")
			} else {
				fmt.Fprint(&b, "</pre>\n")
			}
		case gemini.LinePreformattedText:
			fmt.Fprintf(&b, "%s\n", html.EscapeString(string(l)))
		case gemini.LineHeading1:
			fmt.Fprintf(&b, "<h1>%s</h1>\n", html.EscapeString(string(l)))
		case gemini.LineHeading2:
			fmt.Fprintf(&b, "<h2>%s</h2>\n", html.EscapeString(string(l)))
		case gemini.LineHeading3:
			fmt.Fprintf(&b, "<h3>%s</h3>\n", html.EscapeString(string(l)))
		case gemini.LineListItem:
			fmt.Fprintf(&b, "<li>%s</li>\n", html.EscapeString(string(l)))
		case gemini.LineQuote:
			fmt.Fprintf(&b, "<blockquote>%s</blockquote>\n", html.EscapeString(string(l)))
		case gemini.LineText:
			if l == "" {
				fmt.Fprint(&b, "<br>\n")
			} else {
				fmt.Fprintf(&b, "<p>%s</p>\n", html.EscapeString(string(l)))
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
