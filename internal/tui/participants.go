package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

type participantMode int

const (
	pmList participantMode = iota
	pmAdd
)

type participantsModel struct {
	entries    []ParticipantEntry
	mode       participantMode
	inputs     []textinput.Model
	focusIndex int
	scroll     int
	state      ProjectState
	message    string
	width      int
	height     int
}

func newParticipants(state ProjectState, w, h int) participantsModel {
	return participantsModel{
		entries: state.Participants,
		state:   state,
		width:   w,
		height:  h,
	}
}

func (m participantsModel) update(msg tea.Msg) (participantsModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if m.mode == pmAdd {
			return m.updateAdd(msg)
		}
		return m.updateList(msg)
	}

	// Forward to focused input if adding.
	if m.mode == pmAdd && m.focusIndex < len(m.inputs) {
		var cmd tea.Cmd
		m.inputs[m.focusIndex], cmd = m.inputs[m.focusIndex].Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m participantsModel) updateList(msg tea.KeyMsg) (participantsModel, tea.Cmd) {
	switch msg.String() {
	case "esc":
		return m, func() tea.Msg { return backMsg{} }
	case "a":
		m.mode = pmAdd
		m.message = ""
		m.focusIndex = 0
		m.inputs = m.makeInputs()
		return m, m.inputs[0].Focus()
	case "up", "k":
		if m.scroll > 0 {
			m.scroll--
		}
	case "down", "j":
		maxScroll := len(m.entries) - m.visibleLines()
		if maxScroll < 0 {
			maxScroll = 0
		}
		if m.scroll < maxScroll {
			m.scroll++
		}
	}
	return m, nil
}

func (m participantsModel) updateAdd(msg tea.KeyMsg) (participantsModel, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.mode = pmList
		return m, nil
	case "tab", "down", "enter":
		if m.focusIndex == len(m.inputs)-1 {
			return m.saveEntry()
		}
		m.focusIndex++
		return m, m.focusInputs()
	case "shift+tab", "up":
		if m.focusIndex > 0 {
			m.focusIndex--
		}
		return m, m.focusInputs()
	}

	var cmd tea.Cmd
	m.inputs[m.focusIndex], cmd = m.inputs[m.focusIndex].Update(msg)
	return m, cmd
}

func (m participantsModel) saveEntry() (participantsModel, tea.Cmd) {
	id := strings.TrimSpace(m.inputs[0].Value())
	display := strings.TrimSpace(m.inputs[1].Value())
	scopes := strings.TrimSpace(m.inputs[2].Value())

	if id == "" || scopes == "" {
		m.message = errStyle.Render("User ID and scopes are required")
		return m, nil
	}

	entry := ParticipantEntry{ID: id, Display: display, Scopes: scopes}
	m.entries = append(m.entries, entry)

	// Append to participants.csv.
	csvPath := filepath.Join(m.state.FedDir, "participants.csv")
	line := fmt.Sprintf("%s,%q,%s\n", id, display, scopes)
	f, err := os.OpenFile(csvPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		m.message = errStyle.Render("Write error: " + err.Error())
		return m, nil
	}
	_, writeErr := f.WriteString(line)
	closeErr := f.Close()
	if writeErr != nil {
		m.message = errStyle.Render("Write error: " + writeErr.Error())
		return m, nil
	}
	if closeErr != nil {
		m.message = errStyle.Render("Write error: " + closeErr.Error())
		return m, nil
	}

	m.message = successStyle.Render(fmt.Sprintf("✓ Added %s", id))
	m.mode = pmList
	return m, nil
}

func (m participantsModel) makeInputs() []textinput.Model {
	labels := []string{"User ID", "Display name", "Scope claims"}
	placeholders := []string{"e.g. mayor", "e.g. Mayor João", "e.g. GOV:CITY:ADMIN"}
	prefix := m.state.ScopePrefix
	if prefix != "" {
		placeholders[2] = "e.g. " + prefix + ":ADMIN"
	}

	inputs := make([]textinput.Model, len(labels))
	for i := range inputs {
		ti := textinput.New()
		ti.Placeholder = placeholders[i]
		ti.CharLimit = 200
		ti.Width = 50
		inputs[i] = ti
	}
	return inputs
}

func (m participantsModel) focusInputs() tea.Cmd {
	cmds := make([]tea.Cmd, len(m.inputs))
	for i := range m.inputs {
		if i == m.focusIndex {
			cmds[i] = m.inputs[i].Focus()
		} else {
			m.inputs[i].Blur()
		}
	}
	return tea.Batch(cmds...)
}

func (m participantsModel) visibleLines() int {
	v := m.height - 12
	if v < 5 {
		v = 5
	}
	return v
}

func (m participantsModel) view() string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Render("Participants"))
	sb.WriteString("\n\n")

	if m.mode == pmAdd {
		sb.WriteString(m.viewAdd())
		return sb.String()
	}

	if len(m.entries) == 0 {
		sb.WriteString(dimStyle.Render("  No participants registered yet.\n"))
		sb.WriteString(dimStyle.Render("  Press 'a' to add one, or import a CSV.\n"))
	} else {
		// Header.
		hdr := fmt.Sprintf("  %-15s %-25s %s", "ID", "Name", "Scopes")
		sb.WriteString(dimStyle.Render(hdr) + "\n")
		sb.WriteString(dimStyle.Render("  "+strings.Repeat("─", min(70, m.width-6))) + "\n")

		// Rows.
		vis := m.visibleLines()
		end := m.scroll + vis
		if end > len(m.entries) {
			end = len(m.entries)
		}
		for _, e := range m.entries[m.scroll:end] {
			display := e.Display
			if len(display) > 24 {
				display = display[:21] + "..."
			}
			scopes := e.Scopes
			if len(scopes) > 40 {
				scopes = scopes[:37] + "..."
			}
			sb.WriteString(fmt.Sprintf("  %-15s %-25s %s\n", e.ID, display, dimStyle.Render(scopes)))
		}

		if len(m.entries) > vis {
			sb.WriteString(dimStyle.Render(fmt.Sprintf("\n  Showing %d-%d of %d", m.scroll+1, end, len(m.entries))))
			sb.WriteString("\n")
		}
	}

	if m.message != "" {
		sb.WriteString("\n  " + m.message + "\n")
	}

	sb.WriteString("\n")
	sb.WriteString(helpStyle.Render("  a add • ↑/↓ scroll • esc back"))
	return sb.String()
}

func (m participantsModel) viewAdd() string {
	var sb strings.Builder

	sb.WriteString("  " + selectedStyle.Render("Add Participant") + "\n\n")

	labels := []string{"User ID", "Display name", "Scope claims"}
	hints := []string{
		"Unique identifier (lowercase, no spaces)",
		"Human-readable name",
		"Semicolon-separated scope claims (e.g. GOV:CITY:ADMIN;GOV:CITY:VOTER)",
	}

	for i, input := range m.inputs {
		label := labels[i]
		if i == m.focusIndex {
			label = selectedStyle.Render(label)
		} else {
			label = inputLabelStyle.Render(label)
		}
		sb.WriteString("  " + label + "\n")
		sb.WriteString("  " + input.View() + "\n")
		if i == m.focusIndex {
			sb.WriteString("  " + inputHintStyle.Render(hints[i]) + "\n")
		}
		sb.WriteString("\n")
	}

	if m.message != "" {
		sb.WriteString("  " + m.message + "\n\n")
	}

	sb.WriteString(helpStyle.Render("  tab/enter next • esc cancel"))
	return sb.String()
}
