package tui

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

// setupModel is a multi-step form that writes federation/democracy.toml.
type setupModel struct {
	inputs     []textinput.Model
	labels     []string
	hints      []string
	focusIndex int
	state      ProjectState
	saved      bool
	err        error
	width      int
}

func newSetup(state ProjectState, width int) setupModel {
	cfg := defaultNodeConfig()
	if state.ConfigConfigured {
		cfg = state.Config
	}
	cfg = cfg.withDefaults()

	labels := []string{
		"Organization name",
		"Display name",
		"Scope prefix",
		"Organization domain",
		"Gateway port",
		"Gateway default user",
		"CA admin user",
		"CA admin password",
	}
	hints := []string{
		"Lowercase, no spaces (e.g. city-porto-alegre)",
		"Human-readable (e.g. City of Porto Alegre)",
		"Root scope hierarchy (e.g. GOV:CITY_PORTO_ALEGRE)",
		"Runtime domain injected into docker compose (e.g. shyylol.od.local)",
		"HTTP port for the dashboard (default 8080)",
		"Participant ID used when requests omit X-User (default savio)",
		"Fabric CA registrar username",
		"Fabric CA registrar password",
	}
	defaults := []string{
		firstNonEmpty(strings.TrimSpace(cfg.Organization.Name), state.OrgName),
		firstNonEmpty(strings.TrimSpace(cfg.Organization.DisplayName), state.OrgDisplay),
		firstNonEmpty(strings.TrimSpace(cfg.Organization.ScopePrefix), state.ScopePrefix),
		cfg.Domain(),
		strconv.Itoa(cfg.Gateway.Port),
		cfg.Gateway.DefaultUser,
		cfg.CA.AdminUser,
		cfg.CA.AdminPass,
	}

	inputs := make([]textinput.Model, len(labels))
	for i := range inputs {
		ti := textinput.New()
		ti.Placeholder = hints[i]
		ti.CharLimit = 120
		ti.Width = 50
		ti.SetValue(defaults[i])
		if i == len(labels)-1 {
			ti.EchoMode = textinput.EchoPassword
			ti.EchoCharacter = '*'
		}
		if i == 0 {
			ti.Focus()
		}
		inputs[i] = ti
	}

	return setupModel{
		inputs: inputs,
		labels: labels,
		hints:  hints,
		state:  state,
		width:  width,
	}
}

func (m setupModel) update(msg tea.Msg) (setupModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			return m, func() tea.Msg { return backMsg{} }

		case "tab", "down", "enter":
			if m.focusIndex == len(m.inputs)-1 {
				// Last field — save.
				return m.save()
			}
			m.focusIndex++
			return m, m.focusCmd()

		case "shift+tab", "up":
			if m.focusIndex > 0 {
				m.focusIndex--
			}
			return m, m.focusCmd()
		}
	}

	// Update the focused input.
	var cmd tea.Cmd
	m.inputs[m.focusIndex], cmd = m.inputs[m.focusIndex].Update(msg)
	return m, cmd
}

func (m setupModel) save() (setupModel, tea.Cmd) {
	updated, err := saveNodeConfig(m.state, SetupValues{
		OrgName:            m.inputs[0].Value(),
		OrgDisplay:         m.inputs[1].Value(),
		ScopePrefix:        m.inputs[2].Value(),
		Domain:             m.inputs[3].Value(),
		GatewayPort:        m.inputs[4].Value(),
		GatewayDefaultUser: m.inputs[5].Value(),
		CAAdminUser:        m.inputs[6].Value(),
		CAAdminPass:        m.inputs[7].Value(),
	})
	if err != nil {
		m.err = err
		return m, nil
	}

	m.state = updated
	m.saved = true
	return m, func() tea.Msg {
		return refreshStateMsg{}
	}
}

func (m setupModel) focusCmd() tea.Cmd {
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

func (m setupModel) view() string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Render("Setup — Organization Configuration"))
	sb.WriteString("\n\n")

	if m.saved {
		sb.WriteString(successStyle.Render("  ✓ Configuration saved to federation/democracy.toml"))
		sb.WriteString("\n\n")
		sb.WriteString(dimStyle.Render("  MSP ID:  ") + m.state.MspID)
		sb.WriteString("\n")
		sb.WriteString(dimStyle.Render("  Domain:  ") + m.state.Domain)
		sb.WriteString("\n\n")
		sb.WriteString(helpStyle.Render("  Press esc to go back"))
		return sb.String()
	}

	for i, input := range m.inputs {
		label := m.labels[i]
		if i == m.focusIndex {
			label = selectedStyle.Render(label)
		} else {
			label = inputLabelStyle.Render(label)
		}
		sb.WriteString("  " + label + "\n")
		sb.WriteString("  " + input.View() + "\n")
		if i == m.focusIndex {
			sb.WriteString("  " + inputHintStyle.Render(m.hints[i]) + "\n")
		}
		sb.WriteString("\n")
	}

	if m.err != nil {
		sb.WriteString("  " + errStyle.Render("Error: "+m.err.Error()) + "\n\n")
	}

	step := fmt.Sprintf("  Field %d/%d", m.focusIndex+1, len(m.inputs))
	sb.WriteString(helpStyle.Render(step + " • tab/enter next • esc cancel"))
	return sb.String()
}

// toPascalCase converts "my-org-name" to "MyOrgName".
func toPascalCase(s string) string {
	parts := strings.FieldsFunc(s, func(r rune) bool {
		return r == '-' || r == '_' || r == ' '
	})
	var sb strings.Builder
	for _, p := range parts {
		if len(p) == 0 {
			continue
		}
		sb.WriteString(strings.ToUpper(p[:1]))
		if len(p) > 1 {
			sb.WriteString(strings.ToLower(p[1:]))
		}
	}
	return sb.String()
}

// Messages.
type backMsg struct{}
type refreshStateMsg struct{}
