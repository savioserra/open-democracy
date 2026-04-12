package tui

import "github.com/charmbracelet/lipgloss"

// Color palette — professional, readable over SSH.
var (
	colorPrimary = lipgloss.Color("99")  // purple
	colorSuccess = lipgloss.Color("42")  // green
	colorMuted   = lipgloss.Color("241") // gray
	colorWarn    = lipgloss.Color("214") // orange
	colorError   = lipgloss.Color("196") // red
	colorWhite   = lipgloss.Color("252") // off-white
)

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorPrimary)

	subtitleStyle = lipgloss.NewStyle().
			Foreground(colorMuted)

	selectedStyle = lipgloss.NewStyle().
			Foreground(colorPrimary).
			Bold(true)

	dimStyle = lipgloss.NewStyle().
			Foreground(colorMuted)

	successStyle = lipgloss.NewStyle().Foreground(colorSuccess)
	warnStyle    = lipgloss.NewStyle().Foreground(colorWarn)
	errStyle     = lipgloss.NewStyle().Foreground(colorError)

	helpStyle = lipgloss.NewStyle().
			Foreground(colorMuted)

	bannerStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorPrimary).
			Padding(0, 2).
			Align(lipgloss.Center)

	inputLabelStyle = lipgloss.NewStyle().
			Foreground(colorWhite).
			Bold(true)

	inputHintStyle = lipgloss.NewStyle().
			Foreground(colorMuted).
			Italic(true)
)
