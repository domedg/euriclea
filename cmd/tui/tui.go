package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	// Tokyo Night Palette
	cyan    = lipgloss.Color("#7dcfff")
	magenta = lipgloss.Color("#bb9af7")
	green   = lipgloss.Color("#9ece6a")
	red     = lipgloss.Color("#f7768e")
	gray    = lipgloss.Color("#565f89")
	bg      = lipgloss.Color("#1a1b26")

	baseStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(cyan).
			Padding(0, 1)

	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(bg).
			Background(cyan).
			Padding(0, 1)

	sidebarStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(cyan).
			Padding(0, 1).
			Width(22)

	detailsStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(magenta).
			Padding(0, 1)

	titleStyle = lipgloss.NewStyle().
			Foreground(cyan).
			Bold(true).
			Underline(true)

	infoStyle = lipgloss.NewStyle().Foreground(gray)
	warnStyle = lipgloss.NewStyle().Foreground(green).Bold(true)
	dangerStyle = lipgloss.NewStyle().Foreground(red).Bold(true)
	suspectStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#e0af68")).Bold(true) // Orange/Yellow
)

const asciiArt = `
 ███████ ██    ██ ██████  ██  ██████ ██      ███████  █████  
 ██      ██    ██ ██   ██ ██ ██      ██      ██      ██   ██ 
 █████   ██    ██ ██████  ██ ██      ██      █████   ███████ 
 ██      ██    ██ ██   ██ ██ ██      ██      ██      ██   ██ 
 ███████  ██████  ██   ██ ██  ██████ ███████ ███████ ██   ██ 
`

type HaikuStats struct {
	Haiku       string
	Delta       uint64
	Count       int
	UniqueIPs   map[string]bool
	LastSeen    time.Time
	LastSrc     string
	LastDst     string
	LastPayload string
	Blacklisted bool
	Suspect     bool
}

type filterState int

const (
	filterAll filterState = iota
	filterBlacklisted
	filterSuspect
)

type model struct {
	table    table.Model
	haikuIds []string // for sorted order
	totalPkts int
	width     int
	height    int
	filter    filterState

	inspectedHaiku   string
	inspectedSrc     string
	inspectedDst     string
	inspectedPayload string
	inspectedDelta   uint64
}

func initialModel() model {
	columns := []table.Column{
		{Title: "Haiku", Width: 20},
		{Title: "Delta", Width: 10},
		{Title: "Pkts", Width: 6},
		{Title: "Unique Src IPs", Width: 25},
		{Title: "Last Seen", Width: 20},
		{Title: "Status", Width: 12},
	}

	t := table.New(
		table.WithColumns(columns),
		table.WithFocused(true),
		table.WithHeight(10),
	)

	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(cyan).
		BorderBottom(true).
		Bold(true).
		Foreground(cyan)
	s.Selected = s.Selected.
		Foreground(bg).
		Background(cyan).
		Bold(true)
	t.SetStyles(s)

	return model{
		table:    t,
		haikuIds: make([]string, 0),
	}
}

func (m model) Init() tea.Cmd {
	return doTick()
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {

	case tea.KeyMsg:
		switch msg.String() {
		case "esc", "q", "ctrl+c":
			return m, tea.Quit
		case "s":
			// Toggle Suspect
			if len(m.table.SelectedRow()) > 0 {
				selectedHaiku := m.table.SelectedRow()[0]
				selectedHaiku = strings.TrimPrefix(selectedHaiku, "[B] ")
				selectedHaiku = strings.TrimPrefix(selectedHaiku, "[S] ")

				statsMutex.Lock()
				if stat, ok := globalStats[selectedHaiku]; ok {
					stat.Suspect = !stat.Suspect
				}
				statsMutex.Unlock()
				m.updateTable()
			}
		case "f":
			// Cycle Filter
			m.filter = (m.filter + 1) % 3
			m.table.SetCursor(0) // Reset cursor to top to avoid out-of-bounds
			m.updateTable()
		case "b":
			// Blacklist selected
			if len(m.table.SelectedRow()) > 0 {
				selectedHaiku := m.table.SelectedRow()[0]
				// Strip prefixes if present
				selectedHaiku = strings.TrimPrefix(selectedHaiku, "[B] ")
				selectedHaiku = strings.TrimPrefix(selectedHaiku, "[S] ")
				
				statsMutex.Lock()
				if stat, ok := globalStats[selectedHaiku]; ok {
					stat.Blacklisted = true
					appendBlacklist(selectedHaiku)
				}
				statsMutex.Unlock()
				m.updateTable()
			}
		case "w":
			// Whitelist selected
			if len(m.table.SelectedRow()) > 0 {
				selectedHaiku := m.table.SelectedRow()[0]
				selectedHaiku = strings.TrimPrefix(selectedHaiku, "[B] ")
				selectedHaiku = strings.TrimPrefix(selectedHaiku, "[S] ")

				statsMutex.Lock()
				if stat, ok := globalStats[selectedHaiku]; ok {
					stat.Blacklisted = false
				}
				statsMutex.Unlock()
				// Riscrivi il file rimuovendo l'entry
				rewriteBlacklist()
				m.updateTable()
			}
		case "enter":
			if len(m.table.SelectedRow()) > 0 {
				selectedHaiku := m.table.SelectedRow()[0]
				selectedHaiku = strings.TrimPrefix(selectedHaiku, "[B] ")
				selectedHaiku = strings.TrimPrefix(selectedHaiku, "[S] ")

				statsMutex.RLock()
				if stat, ok := globalStats[selectedHaiku]; ok {
					m.inspectedHaiku = stat.Haiku
					m.inspectedSrc = stat.LastSrc
					m.inspectedDst = stat.LastDst
					m.inspectedPayload = stat.LastPayload
					m.inspectedDelta = stat.Delta
				}
				statsMutex.RUnlock()
			}
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.table.SetWidth(msg.Width - 26) // 22 sidebar + 4 spacing
		// Header (~7) + Details (~6) + Help (~2) + Margin = ~15
		tableHeight := msg.Height - 15
		if tableHeight < 5 {
			tableHeight = 5
		}
		m.table.SetHeight(tableHeight)

	case TickMsg:
		m.updateTable()
		return m, doTick()
	}

	m.table, cmd = m.table.Update(msg)
	return m, cmd
}

func appendBlacklist(haiku string) {
	f, err := os.OpenFile("blacklist.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		f.WriteString(haiku + "\n")
		f.Close()
	}
}

// rewriteBlacklist riscrive blacklist.txt leggendo lo stato corrente in memoria.
// Va chiamata dopo ogni rimozione dalla blacklist (tasto w).
func rewriteBlacklist() {
	statsMutex.RLock()
	defer statsMutex.RUnlock()

	f, err := os.OpenFile("blacklist.txt", os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	for _, stat := range globalStats {
		if stat.Blacklisted {
			f.WriteString(stat.Haiku + "\n")
		}
	}
}

func (m *model) updateTable() {
	statsMutex.RLock()
	defer statsMutex.RUnlock()

	m.totalPkts = totalPkts
	
	// Rebuild haikuIds based on filter
	m.haikuIds = make([]string, 0)
	for id, stat := range globalStats {
		switch m.filter {
		case filterBlacklisted:
			if stat.Blacklisted {
				m.haikuIds = append(m.haikuIds, id)
			}
		case filterSuspect:
			if stat.Suspect {
				m.haikuIds = append(m.haikuIds, id)
			}
		default:
			m.haikuIds = append(m.haikuIds, id)
		}
	}

	// Sort haikus by LastSeen (descending)
	sort.Slice(m.haikuIds, func(i, j int) bool {
		return globalStats[m.haikuIds[i]].LastSeen.After(globalStats[m.haikuIds[j]].LastSeen)
	})

	var rows []table.Row
	for _, id := range m.haikuIds {
		stat := globalStats[id]
		
		// Create a slice of unique IPs
		var ips []string
		for ip := range stat.UniqueIPs {
			ips = append(ips, ip)
		}
		ipStr := strings.Join(ips, ", ")
		if len(ipStr) > 22 {
			ipStr = ipStr[:19] + "..."
		}

		status := "Active"
		if stat.Blacklisted {
			status = "Blocked"
		} else if stat.Suspect {
			status = "Suspect"
		}

		// Apply prefixes instead of ANSI colors to avoid breaking table alignment
		rowHaiku := stat.Haiku
		if stat.Blacklisted {
			rowHaiku = "[B] " + rowHaiku
		} else if stat.Suspect {
			rowHaiku = "[S] " + rowHaiku
		}

		rows = append(rows, table.Row{
			rowHaiku,
			fmt.Sprintf("%d", stat.Delta),
			fmt.Sprintf("%d", stat.Count),
			ipStr,
			stat.LastSeen.Format("15:04:05.000"),
			status,
		})
	}
	// Salva cursore e ripristinalo dopo il refresh per non far saltare la selezione
	currentCursor := m.table.Cursor()
	m.table.SetRows(rows)
	if currentCursor < len(rows) {
		m.table.SetCursor(currentCursor)
	} else if len(rows) > 0 {
		m.table.SetCursor(len(rows) - 1)
	}
}

func (m model) View() string {
	if m.width == 0 {
		return "Initializing Euriclea..."
	}

	// 1. Header (Altezza: 6-7 righe)
	art := lipgloss.NewStyle().Foreground(cyan).Render(asciiArt)
	header := art

	// 2. Sidebar (Altezza dinamica)
	statsMutex.RLock()
	blacklistedCount := 0
	for _, s := range globalStats {
		if s.Blacklisted {
			blacklistedCount++
		}
	}
	fpCount := len(globalStats)
	statsMutex.RUnlock()

	filterLabel := "ALL"
	switch m.filter {
	case filterBlacklisted:
		filterLabel = "BLOCKED"
	case filterSuspect:
		filterLabel = "SUSPECTS"
	}

	sidebarContent := lipgloss.JoinVertical(lipgloss.Left,
		headerStyle.Render("OVERVIEW"),
		"",
		fmt.Sprintf("Pkts: %s", warnStyle.Render(fmt.Sprintf("%d", m.totalPkts))),
		fmt.Sprintf("Ents: %s", warnStyle.Render(fmt.Sprintf("%d", fpCount))),
		fmt.Sprintf("Blck: %s", dangerStyle.Render(fmt.Sprintf("%d", blacklistedCount))),
		"",
		headerStyle.Render("FILTER"),
		warnStyle.Render("» "+filterLabel),
		"",
		headerStyle.Render("STATUS"),
		warnStyle.Render("● PCAP"),
		warnStyle.Render("● NFQ"),
	)
	sidebar := sidebarStyle.Height(m.table.Height() + 2).Render(sidebarContent)

	// 3. Table
	tableView := baseStyle.Width(m.width - 25).Render(m.table.View())

	// 4. Body
	body := lipgloss.JoinHorizontal(lipgloss.Top, sidebar, " ", tableView)

	// 5. Details (Altezza: ~6 righe)
	var detailsView string
	if m.inspectedHaiku != "" {
		haikuInfo := fmt.Sprintf("IDENT: %s | SKEW: %d", lipgloss.NewStyle().Foreground(magenta).Render(m.inspectedHaiku), m.inspectedDelta)
		flowStr := fmt.Sprintf("%s -> %s", warnStyle.Render(m.inspectedSrc), warnStyle.Render(m.inspectedDst))
		
		payloadStr := "<no payload>"
		if m.inspectedPayload != "" {
			payloadStr = m.inspectedPayload
			if len(payloadStr) > m.width-10 {
				payloadStr = payloadStr[:m.width-13] + "..."
			}
		}
		
		detailsContent := lipgloss.JoinVertical(lipgloss.Left,
			headerStyle.Background(magenta).Render(" INSPECTION "),
			haikuInfo,
			flowStr,
			infoStyle.Render("Payload: ") + payloadStr,
		)
		detailsView = detailsStyle.Width(m.width - 4).Render(detailsContent)
	} else {
		detailsView = detailsStyle.Width(m.width - 4).Render(infoStyle.Render("Press ENTER to snapshot payload"))
	}

	// 6. Help
	helpText := "↑/↓: Nav • Enter: Snap • [f]: Cycle Filter • [s]: Suspect • [b]: Black • [w]: White • [q]: Exit"
	help := infoStyle.MarginLeft(2).Render(helpText)

	return lipgloss.JoinVertical(lipgloss.Left,
		header,
		body,
		detailsView,
		help,
	)
}
