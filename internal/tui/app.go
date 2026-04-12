package tui

import (
	tea "github.com/charmbracelet/bubbletea"
)

type screen int

const (
	screenMenu screen = iota
	screenSetup
	screenRunner
	screenParticipants
)

// App is the root bubbletea model.
type App struct {
	screen       screen
	state        ProjectState
	width        int
	height       int
	menu         menuModel
	setup        setupModel
	runner       runnerModel
	participants participantsModel
}

// New creates the root TUI model.
func New() App {
	state := DetectState()
	return App{
		screen: screenMenu,
		state:  state,
		menu:   newMenu(state),
	}
}

func (m App) Init() tea.Cmd {
	return nil
}

func (m App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	// Global messages handled at the app level.
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.menu.width = msg.Width
		m.runner.width = msg.Width
		m.runner.height = msg.Height
		m.participants.width = msg.Width
		m.participants.height = msg.Height
		return m, nil

	case tea.KeyMsg:
		// Global quit.
		if msg.String() == "q" && m.screen == screenMenu {
			return m, tea.Quit
		}
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}

	case refreshStateMsg:
		m.state = DetectState()
		m.menu.state = m.state
		return m, nil

	case backMsg:
		m.state = DetectState()
		m.menu = newMenu(m.state)
		m.menu.width = m.width
		m.screen = screenMenu
		return m, nil

	case menuSelectMsg:
		return m.handleMenuSelect(msg.key)

	case startRunnerMsg:
		m.runner = newRunner(msg.title, msg.tasks, m.state)
		m.runner.width = m.width
		m.runner.height = m.height
		m.screen = screenRunner
		return m, m.runner.init()
	}

	// Delegate to current screen.
	switch m.screen {
	case screenMenu:
		var cmd tea.Cmd
		m.menu, cmd = m.menu.update(msg)
		return m, cmd

	case screenSetup:
		var cmd tea.Cmd
		m.setup, cmd = m.setup.update(msg)
		return m, cmd

	case screenRunner:
		var cmd tea.Cmd
		m.runner, cmd = m.runner.update(msg)
		return m, cmd

	case screenParticipants:
		var cmd tea.Cmd
		m.participants, cmd = m.participants.update(msg)
		return m, cmd
	}

	return m, nil
}

func (m App) View() string {
	switch m.screen {
	case screenMenu:
		return "\n" + m.menu.view() + "\n"
	case screenSetup:
		return "\n" + m.setup.view() + "\n"
	case screenRunner:
		return "\n" + m.runner.view() + "\n"
	case screenParticipants:
		return "\n" + m.participants.view() + "\n"
	}
	return ""
}

func (m App) handleMenuSelect(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "quickstart":
		if !m.state.HasDocker {
			return m, nil
		}
		return m, func() tea.Msg {
			return startRunnerMsg{
				title: "Quick Start — Demo Dashboard",
				tasks: demoTasks(m.state),
			}
		}

	case "setup":
		m.setup = newSetup(m.state, m.width)
		m.screen = screenSetup
		return m, nil

	case "bootstrap":
		if !m.state.EnvConfigured {
			return m, nil // need setup first
		}
		if !m.state.HasOpenSSL {
			return m, nil
		}
		return m, func() tea.Msg {
			return startRunnerMsg{
				title: "Bootstrap Node — Generating Certificates",
				tasks: bootstrapTasks(m.state),
			}
		}

	case "start":
		if !m.state.HasDocker || !m.state.EnvConfigured {
			return m, nil
		}
		return m, func() tea.Msg {
			return startRunnerMsg{
				title: "Start Federation Node",
				tasks: startNodeTasks(m.state),
			}
		}

	case "stop":
		if !m.state.HasDocker {
			return m, nil
		}
		return m, func() tea.Msg {
			return startRunnerMsg{
				title: "Stop Services",
				tasks: stopTasks(m.state),
			}
		}

	case "participants":
		m.participants = newParticipants(m.state, m.width, m.height)
		m.screen = screenParticipants
		return m, nil
	}

	return m, nil
}
