package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
)

// task is a single unit of work the runner executes sequentially.
type task struct {
	label string
	fn    func(ProjectState) (string, error)
}

// runnerModel executes a list of tasks, showing progress and output.
type runnerModel struct {
	title   string
	tasks   []task
	current int
	results []taskResult
	output  strings.Builder
	done    bool
	failed  bool
	spinner spinner.Model
	state   ProjectState
	width   int
	height  int
}

type taskResult struct {
	index  int
	label  string
	output string
	err    error
}

// startRunnerMsg configures and switches to the runner screen.
type startRunnerMsg struct {
	title string
	tasks []task
}

// taskDoneMsg is emitted when a single task completes.
type taskDoneMsg struct{ result taskResult }

func newRunner(title string, tasks []task, state ProjectState) runnerModel {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = selectedStyle
	return runnerModel{
		title:   title,
		tasks:   tasks,
		state:   state,
		spinner: s,
	}
}

func (m runnerModel) init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, m.runNext())
}

func (m runnerModel) runNext() tea.Cmd {
	if m.current >= len(m.tasks) {
		return nil
	}
	idx := m.current
	t := m.tasks[idx]
	state := m.state
	return func() tea.Msg {
		out, err := t.fn(state)
		return taskDoneMsg{result: taskResult{
			index:  idx,
			label:  t.label,
			output: out,
			err:    err,
		}}
	}
}

func (m runnerModel) update(msg tea.Msg) (runnerModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "esc" || (m.done && msg.String() == "enter") {
			return m, func() tea.Msg { return backMsg{} }
		}

	case taskDoneMsg:
		r := msg.result
		m.results = append(m.results, r)
		if r.output != "" {
			m.output.WriteString(r.output)
			if !strings.HasSuffix(r.output, "\n") {
				m.output.WriteString("\n")
			}
		}
		if r.err != nil {
			m.output.WriteString(errStyle.Render("Error: "+r.err.Error()) + "\n")
			m.done = true
			m.failed = true
			return m, nil
		}
		m.current++
		if m.current >= len(m.tasks) {
			m.done = true
			return m, nil
		}
		return m, m.runNext()

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m runnerModel) view() string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Render(m.title))
	sb.WriteString("\n\n")

	// Task list with status icons.
	for i, t := range m.tasks {
		var icon string
		switch {
		case i < m.current:
			if i < len(m.results) && m.results[i].err != nil {
				icon = errStyle.Render("✗")
			} else {
				icon = successStyle.Render("✓")
			}
		case i == m.current && !m.done:
			icon = m.spinner.View()
		default:
			icon = dimStyle.Render("○")
		}
		label := t.label
		if i == m.current && !m.done {
			label = selectedStyle.Render(label)
		} else if i < m.current {
			label = dimStyle.Render(label)
		} else {
			label = dimStyle.Render(label)
		}
		sb.WriteString(fmt.Sprintf("  %s %s\n", icon, label))
	}
	sb.WriteString("\n")

	// Output window.
	out := m.output.String()
	if out != "" {
		divider := dimStyle.Render(strings.Repeat("─", min(60, m.width-4)))
		sb.WriteString("  " + divider + "\n")
		// Show last N lines.
		lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
		maxLines := 15
		if m.height > 30 {
			maxLines = m.height - 20
		}
		start := 0
		if len(lines) > maxLines {
			start = len(lines) - maxLines
		}
		for _, line := range lines[start:] {
			sb.WriteString("  " + line + "\n")
		}
		sb.WriteString("\n")
	}

	// Footer.
	if m.done {
		if m.failed {
			sb.WriteString("  " + errStyle.Render("Failed.") + "\n")
		} else {
			sb.WriteString("  " + successStyle.Render("Done!") + "\n")
		}
		sb.WriteString(helpStyle.Render("  Press esc or enter to go back"))
	} else {
		sb.WriteString(helpStyle.Render("  Running... press esc to cancel"))
	}

	return sb.String()
}
