package internal

import "github.com/compliance-framework/agent/runner/proto"

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

func (t *Task) ToProtoStep() *proto.Task {
	activities := make([]*proto.Activity, len(t.Activities))

	for i, a := range t.Activities {
		activities[i] = a.ToProtoActivity()
	}

	// TODO We can't do anything with the activities yet, as we need to create them somewhere and associate them
	// with the task rather than embed them.

	return &proto.Task{
		//Activities:  activities,
		Uuid:        "",
		Type:        0,
		Title:       t.Title,
		Description: &t.Description,
		Subjects: []*proto.AssessmentSubject{
			{
				IncludeSubjects: []*proto.SelectSubjectById{
					{
						SubjectUuid: t.SubjectId,
					},
				},
			},
		},
		ResponsibleRoles: nil,
		Remarks:          nil,
	}
}

func (a *Activity) AddStep(steps ...Step) {
	a.Steps = append(a.Steps, steps...)
}

func (a *Activity) ToProtoActivity() *proto.Activity {
	steps := make([]*proto.Step, len(a.Steps))

	for i, s := range a.Steps {
		steps[i] = s.ToProtoStep()
	}

	return &proto.Activity{
		Title:       a.Title,
		SubjectId:   a.SubjectId,
		Description: a.Description,
		Type:        a.Type,
		Steps:       steps,
		Tools:       a.Tools,
	}
}

func (s *Step) ToProtoStep() *proto.Step {
	return &proto.Step{
		Title:       s.Title,
		SubjectId:   s.SubjectId,
		Description: s.Description,
	}
}
