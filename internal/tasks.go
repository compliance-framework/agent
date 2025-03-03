package internal

type Step struct {
	Title       string
	SubjectId   string
	Description string
}

type Activity struct {
	Title       string
	SubjectId   string
	Description string
	Type        string
	Steps       []Step
	Tools       []string
}

type Task struct {
	Title       string
	SubjectId   string
	Description string
	Activities  []Activity
}

func (t *Task) AddActivity(activities ...Activity) {
	t.Activities = append(t.Activities, activities...)
}

func (a *Activity) AddStep(steps ...Step) {
	a.Steps = append(a.Steps, steps...)
}
