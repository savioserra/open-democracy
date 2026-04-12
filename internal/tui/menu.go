package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

type menuItem struct {
	key  string
	icon string
	name string
	desc string
	// statusFn returns a short coloured string for the right side.
	statusFn func(ProjectState) string
}

type menuModel struct {
	items  []menuItem
	cursor int
	state  ProjectState
	width  int
}

func newMenu(state ProjectState) menuModel {
	return menuModel{
		state: state,
		items: []menuItem{
			{
				key: "quickstart", icon: "▶", name: "Quick Start",
				desc: "Launch demo dashboard in Docker",
				statusFn: func(s ProjectState) string {
					if !s.HasDocker {
						return errStyle.Render("docker not found")
					}
					if s.RunningCount() > 0 {
						return successStyle.Render("● running")
					}
					return dimStyle.Render("ready")
				},
			},
			{
				key: "setup", icon: "⚙", name: "Setup",
				desc: "Configure your organization identity",
				statusFn: func(s ProjectState) string {
					if s.EnvConfigured {
						return successStyle.Render("✓ " + s.OrgName)
					}
					return warnStyle.Render("not configured")
				},
			},
			{
				key: "bootstrap", icon: "🔑", name: "Bootstrap",
				desc: "Generate certificates and crypto",
				statusFn: func(s ProjectState) string {
					if s.CryptoGenerated {
						return successStyle.Render("✓ generated")
					}
					if !s.EnvConfigured {
						return dimStyle.Render("setup first")
					}
					return warnStyle.Render("○ pending")
				},
			},
			{
				key: "start", icon: "△", name: "Start Node",
				desc: "Start federation containers",
				statusFn: func(s ProjectState) string {
					if !s.HasDocker {
						return errStyle.Render("docker not found")
					}
					if !s.EnvConfigured {
						return dimStyle.Render("setup first")
					}
					if s.RunningCount() > 0 {
						return successStyle.Render(fmt.Sprintf("● %d running", s.RunningCount()))
					}
					return dimStyle.Render("stopped")
				},
			},
			{
				key: "stop", icon: "□", name: "Stop Services",
				desc: "Stop all Docker containers",
				statusFn: func(s ProjectState) string {
					if s.RunningCount() > 0 {
						return warnStyle.Render(fmt.Sprintf("%d running", s.RunningCount()))
					}
					return dimStyle.Render("nothing running")
				},
			},
			{
				key: "participants", icon: "👤", name: "Participants",
				desc: "Register users with scope claims",
				statusFn: func(s ProjectState) string {
					n := len(s.Participants)
					if n > 0 {
						return successStyle.Render(fmt.Sprintf("%d registered", n))
					}
					return dimStyle.Render("none")
				},
			},
		},
	}
}

func (m menuModel) update(msg tea.Msg) (menuModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(m.items)-1 {
				m.cursor++
			}
		case "enter":
			return m, func() tea.Msg {
				return menuSelectMsg{key: m.items[m.cursor].key}
			}
		}
	}
	return m, nil
}

func (m menuModel) view() string {
	var sb strings.Builder

	banner := bannerStyle.Render(
		titleStyle.Render("Open Democracy Federation") + "\n" +
			subtitleStyle.Render("Distributed governance CLI"))
	sb.WriteString(banner)
	sb.WriteString("\n\n")

	for i, item := range m.items {
		cursor := "  "
		style := dimStyle
		if i == m.cursor {
			cursor = selectedStyle.Render("→ ")
			style = selectedStyle
		}

		name := style.Render(item.name)
		status := item.statusFn(m.state)

		// Fixed-width columns.
		nameCol := fmt.Sprintf("%-20s", name)
		descCol := dimStyle.Render(fmt.Sprintf("%-40s", item.desc))

		sb.WriteString(fmt.Sprintf("%s%s %s %s\n", cursor, nameCol, descCol, status))
	}

	sb.WriteString("\n")
	sb.WriteString(helpStyle.Render("  ↑/↓ navigate • enter select • q quit"))

	return sb.String()
}

// menuSelectMsg is sent when the user picks a menu item.
type menuSelectMsg struct{ key string }
