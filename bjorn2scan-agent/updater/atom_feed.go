package updater

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"time"
)

// AtomFeed represents a parsed Atom feed
type AtomFeed struct {
	XMLName xml.Name    `xml:"feed"`
	Title   string      `xml:"title"`
	Entries []AtomEntry `xml:"entry"`
}

// AtomEntry represents a single entry (release) in the feed
type AtomEntry struct {
	ID      string    `xml:"id"`
	Title   string    `xml:"title"`
	Updated time.Time `xml:"updated"`
	Link    AtomLink  `xml:"link"`
	Content string    `xml:"content"`
}

// AtomLink represents a link element
type AtomLink struct {
	Href string `xml:"href,attr"`
	Rel  string `xml:"rel,attr"`
	Type string `xml:"type,attr"`
}

// Release represents a parsed release from the feed
type Release struct {
	Version string
	Tag     string
	Date    time.Time
	URL     string
}

// FeedParser handles fetching and parsing Atom feeds
type FeedParser struct {
	feedURL string
	client  *http.Client
}

// NewFeedParser creates a new feed parser
func NewFeedParser(feedURL string) *FeedParser {
	return &FeedParser{
		feedURL: feedURL,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// GetLatestRelease fetches and parses the feed to get the latest release
func (fp *FeedParser) GetLatestRelease(ctx context.Context) (*Release, error) {
	// Fetch feed
	req, err := http.NewRequestWithContext(ctx, "GET", fp.feedURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := fp.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch feed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("feed request failed with status %d", resp.StatusCode)
	}

	// Parse feed
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read feed: %w", err)
	}

	var feed AtomFeed
	if err := xml.Unmarshal(body, &feed); err != nil {
		return nil, fmt.Errorf("failed to parse feed XML: %w", err)
	}

	// Get latest entry (first in the feed)
	if len(feed.Entries) == 0 {
		return nil, fmt.Errorf("no releases found in feed")
	}

	entry := feed.Entries[0]
	tag := entry.Title

	// Strip 'v' prefix if present
	version := tag
	if len(version) > 0 && version[0] == 'v' {
		version = version[1:]
	}

	return &Release{
		Version: version,
		Tag:     tag,
		Date:    entry.Updated,
		URL:     entry.Link.Href,
	}, nil
}

// ListReleases fetches and parses the feed to get all releases
func (fp *FeedParser) ListReleases(ctx context.Context) ([]*Release, error) {
	// Fetch feed
	req, err := http.NewRequestWithContext(ctx, "GET", fp.feedURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := fp.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch feed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("feed request failed with status %d", resp.StatusCode)
	}

	// Parse feed
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read feed: %w", err)
	}

	var feed AtomFeed
	if err := xml.Unmarshal(body, &feed); err != nil {
		return nil, fmt.Errorf("failed to parse feed XML: %w", err)
	}

	// Convert entries to releases
	releases := make([]*Release, 0, len(feed.Entries))
	for _, entry := range feed.Entries {
		tag := entry.Title
		version := tag
		if len(version) > 0 && version[0] == 'v' {
			version = version[1:]
		}

		releases = append(releases, &Release{
			Version: version,
			Tag:     tag,
			Date:    entry.Updated,
			URL:     entry.Link.Href,
		})
	}

	return releases, nil
}
