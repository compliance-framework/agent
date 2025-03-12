package main

import (
	"fmt"
	oscal "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
)

func oscal_result_full() {
	res := oscal.Result{
		AssessmentLog: &oscal.AssessmentLog{
			Entries: []oscal.AssessmentLogEntry{
				{
					LoggedBy: &[]oscal.LoggedBy{
						{
							PartyUuid: "",
							RoleId:    "",
						},
					},
					RelatedTasks: &[]oscal.RelatedTask{
						{
							IdentifiedSubject: &oscal.IdentifiedSubject{
								Subjects: []oscal.AssessmentSubject{
									{
										ExcludeSubjects: &[]oscal.SelectSubjectById{
											{
												SubjectUuid: "",
											},
										},
										IncludeSubjects: &[]oscal.SelectSubjectById{
											{
												SubjectUuid: "",
											},
										},
									},
								},
							},
							ResponsibleParties: &[]oscal.ResponsibleParty{
								{
									PartyUuids: nil,
									RoleId:     "",
								},
							},
							Subjects: &[]oscal.AssessmentSubject{
								{
									ExcludeSubjects: &[]oscal.SelectSubjectById{
										{
											SubjectUuid: "",
										},
									},
									IncludeSubjects: &[]oscal.SelectSubjectById{
										{
											SubjectUuid: "",
										},
									},
								},
							},
							TaskUuid: "",
						},
					},
					UUID: "",
				},
			},
		},
		Attestations: &[]oscal.AttestationStatements{
			{
				Parts: []oscal.AssessmentPart{
					{
						Parts: nil,
					},
				},
				ResponsibleParties: &[]oscal.ResponsibleParty{
					{
						PartyUuids: nil,
						RoleId:     "",
					},
				},
			},
		},
		Findings: &[]oscal.Finding{
			{
				ImplementationStatementUuid: "",
				Origins: &[]oscal.Origin{
					{
						Actors: []oscal.OriginActor{
							{
								ActorUuid: "",
								RoleId:    "",
							},
						},
						RelatedTasks: &[]oscal.RelatedTask{
							{
								IdentifiedSubject: &oscal.IdentifiedSubject{
									SubjectPlaceholderUuid: "",
									Subjects: []oscal.AssessmentSubject{
										{
											ExcludeSubjects: &[]oscal.SelectSubjectById{
												{
													SubjectUuid: "",
												},
											},
											IncludeSubjects: &[]oscal.SelectSubjectById{
												{
													SubjectUuid: "",
												},
											},
										},
									},
								},
								ResponsibleParties: &[]oscal.ResponsibleParty{
									{
										PartyUuids: nil,
										RoleId:     "",
									},
								},
								Subjects: &[]oscal.AssessmentSubject{
									{
										ExcludeSubjects: &[]oscal.SelectSubjectById{
											{
												SubjectUuid: "",
											},
										},
										IncludeSubjects: &[]oscal.SelectSubjectById{
											{
												SubjectUuid: "",
											},
										},
									},
								},
								TaskUuid: "",
							},
						},
					},
				},
				RelatedObservations: &[]oscal.RelatedObservation{
					{
						ObservationUuid: "",
					},
				},
				RelatedRisks: &[]oscal.AssociatedRisk{
					{
						RiskUuid: "",
					},
				},
				Target: oscal.FindingTarget{
					TargetId: "",
				},
				UUID: "",
			},
		},
		LocalDefinitions: &oscal.LocalDefinitions{
			Activities: &[]oscal.Activity{
				{
					RelatedControls: &oscal.ReviewedControls{
						ControlObjectiveSelections: &[]oscal.ReferencedControlObjectives{
							{
								ExcludeObjectives: &[]oscal.SelectObjectiveById{
									{
										ObjectiveId: "",
									},
								},
								IncludeObjectives: &[]oscal.SelectObjectiveById{
									{
										ObjectiveId: "",
									},
								},
							},
						},
						ControlSelections: []oscal.AssessedControls{
							{
								ExcludeControls: &[]oscal.AssessedControlsSelectControlById{
									{
										ControlId:    "",
										StatementIds: nil,
									},
								},
								IncludeControls: &[]oscal.AssessedControlsSelectControlById{
									{
										ControlId:    "",
										StatementIds: nil,
									},
								},
							},
						},
					},
					ResponsibleRoles: &[]oscal.ResponsibleRole{
						{
							PartyUuids: nil,
							RoleId:     "",
						},
					},
					Steps: &[]oscal.Step{
						{
							ResponsibleRoles: &[]oscal.ResponsibleRole{
								{
									PartyUuids: nil,
									RoleId:     "",
								},
							},
							ReviewedControls: &oscal.ReviewedControls{
								ControlObjectiveSelections: &[]oscal.ReferencedControlObjectives{
									{
										ExcludeObjectives: &[]oscal.SelectObjectiveById{
											{
												ObjectiveId: "",
											},
										},
										IncludeObjectives: &[]oscal.SelectObjectiveById{
											{
												ObjectiveId: "",
											},
										},
									},
								},
								ControlSelections: []oscal.AssessedControls{
									{
										ExcludeControls: &[]oscal.AssessedControlsSelectControlById{
											{
												ControlId:    "",
												StatementIds: nil,
											},
										},
										IncludeControls: &[]oscal.AssessedControlsSelectControlById{
											{
												ControlId:    "",
												StatementIds: nil,
											},
										},
									},
								},
							},
						},
					},
				},
			},
			Components: &[]oscal.SystemComponent{
				{
					ResponsibleRoles: &[]oscal.ResponsibleRole{
						{
							PartyUuids: nil,
							RoleId:     "",
						},
					},
					UUID: "",
				},
			},
			InventoryItems: &[]oscal.InventoryItem{
				{
					ImplementedComponents: &[]oscal.ImplementedComponent{
						{
							ComponentUuid: "",
							ResponsibleParties: &[]oscal.ResponsibleParty{
								{
									PartyUuids: nil,
									RoleId:     "",
								},
							},
						},
					},
					ResponsibleParties: &[]oscal.ResponsibleParty{
						{
							PartyUuids: nil,
							RoleId:     "",
						},
					},
					UUID: "",
				},
			},
			ObjectivesAndMethods: &[]oscal.LocalObjective{
				{
					ControlId: "",
					Parts: []oscal.Part{
						{
							Parts: nil,
						},
					},
				},
			},
			Users: &[]oscal.SystemUser{
				{
					AuthorizedPrivileges: &[]oscal.AuthorizedPrivilege{
						{
							Description:        "",
							FunctionsPerformed: nil,
							Title:              "",
						},
					},
					RoleIds: nil,
					UUID:    "",
				},
			},
		},
		Observations: &[]oscal.Observation{
			{
				Origins: &[]oscal.Origin{
					{
						Actors: []oscal.OriginActor{
							{
								ActorUuid: "",
								RoleId:    "",
							},
						},
						RelatedTasks: &[]oscal.RelatedTask{
							{
								IdentifiedSubject: &oscal.IdentifiedSubject{
									SubjectPlaceholderUuid: "",
									Subjects: []oscal.AssessmentSubject{
										{
											ExcludeSubjects: &[]oscal.SelectSubjectById{
												{
													SubjectUuid: "",
												},
											},
											IncludeSubjects: &[]oscal.SelectSubjectById{
												{
													SubjectUuid: "",
												},
											},
										},
									},
								},
								ResponsibleParties: &[]oscal.ResponsibleParty{
									{
										PartyUuids: nil,
										RoleId:     "",
									},
								},
								Subjects: &[]oscal.AssessmentSubject{
									{
										ExcludeSubjects: &[]oscal.SelectSubjectById{
											{
												SubjectUuid: "",
											},
										},
										IncludeSubjects: &[]oscal.SelectSubjectById{
											{
												SubjectUuid: "",
											},
										},
									},
								},
								TaskUuid: "",
							},
						},
					},
				},
				Subjects: &[]oscal.SubjectReference{
					{
						SubjectUuid: "",
					},
				},
				UUID: "",
			},
		},
		ReviewedControls: oscal.ReviewedControls{
			ControlObjectiveSelections: &[]oscal.ReferencedControlObjectives{
				{
					ExcludeObjectives: &[]oscal.SelectObjectiveById{
						{
							ObjectiveId: "",
						},
					},
					IncludeObjectives: &[]oscal.SelectObjectiveById{
						{
							ObjectiveId: "",
						},
					},
				},
			},
			ControlSelections: []oscal.AssessedControls{
				{
					ExcludeControls: &[]oscal.AssessedControlsSelectControlById{
						{
							ControlId:    "",
							StatementIds: nil,
						},
					},
					IncludeControls: &[]oscal.AssessedControlsSelectControlById{
						{
							ControlId:    "",
							StatementIds: nil,
						},
					},
				},
			},
		},
		Risks: &[]oscal.Risk{
			{
				Characterizations: &[]oscal.Characterization{
					{
						Facets: []oscal.Facet{
							{
								System: "",
								Value:  "",
							},
						},
						Origin: oscal.Origin{
							Actors: []oscal.OriginActor{
								{
									ActorUuid: "",
									RoleId:    "",
								},
							},
							RelatedTasks: &[]oscal.RelatedTask{
								{
									IdentifiedSubject: &oscal.IdentifiedSubject{
										SubjectPlaceholderUuid: "",
										Subjects: []oscal.AssessmentSubject{
											{
												ExcludeSubjects: &[]oscal.SelectSubjectById{
													{
														SubjectUuid: "",
													},
												},
												IncludeSubjects: &[]oscal.SelectSubjectById{
													{
														SubjectUuid: "",
													},
												},
											},
										},
									},
									ResponsibleParties: &[]oscal.ResponsibleParty{
										{
											PartyUuids: nil,
											RoleId:     "",
										},
									},
									Subjects: &[]oscal.AssessmentSubject{
										{
											ExcludeSubjects: &[]oscal.SelectSubjectById{
												{
													SubjectUuid: "",
												},
											},
											IncludeSubjects: &[]oscal.SelectSubjectById{
												{
													SubjectUuid: "",
												},
											},
										},
									},
									TaskUuid: "",
								},
							},
						},
					},
				},
				MitigatingFactors: &[]oscal.MitigatingFactor{
					{
						ImplementationUuid: "",
						Subjects: &[]oscal.SubjectReference{
							{
								SubjectUuid: "",
							},
						},
					},
				},
				Origins: &[]oscal.Origin{
					{
						Actors: []oscal.OriginActor{
							{
								ActorUuid: "",
								RoleId:    "",
							},
						},
						RelatedTasks: &[]oscal.RelatedTask{
							{
								IdentifiedSubject: &oscal.IdentifiedSubject{
									SubjectPlaceholderUuid: "",
									Subjects: []oscal.AssessmentSubject{
										{
											ExcludeSubjects: &[]oscal.SelectSubjectById{
												{
													SubjectUuid: "",
												},
											},
											IncludeSubjects: &[]oscal.SelectSubjectById{
												{
													SubjectUuid: "",
												},
											},
										},
									},
								},
								ResponsibleParties: &[]oscal.ResponsibleParty{
									{
										PartyUuids: nil,
										RoleId:     "",
									},
								},
								Subjects: &[]oscal.AssessmentSubject{
									{
										ExcludeSubjects: &[]oscal.SelectSubjectById{
											{
												SubjectUuid: "",
											},
										},
										IncludeSubjects: &[]oscal.SelectSubjectById{
											{
												SubjectUuid: "",
											},
										},
									},
								},
								TaskUuid: "",
							},
						},
					},
				},
				RelatedObservations: &[]oscal.RelatedObservation{
					{
						ObservationUuid: "",
					},
				},
				Remediations: &[]oscal.Response{
					{
						Origins: &[]oscal.Origin{
							{
								Actors: []oscal.OriginActor{
									{
										ActorUuid: "",
										RoleId:    "",
									},
								},
								RelatedTasks: &[]oscal.RelatedTask{
									{
										IdentifiedSubject: &oscal.IdentifiedSubject{
											SubjectPlaceholderUuid: "",
											Subjects: []oscal.AssessmentSubject{
												{
													ExcludeSubjects: &[]oscal.SelectSubjectById{
														{
															SubjectUuid: "",
														},
													},
													IncludeSubjects: &[]oscal.SelectSubjectById{
														{
															SubjectUuid: "",
														},
													},
												},
											},
										},
										ResponsibleParties: &[]oscal.ResponsibleParty{
											{
												PartyUuids: nil,
												RoleId:     "",
											},
										},
										Subjects: &[]oscal.AssessmentSubject{
											{
												ExcludeSubjects: &[]oscal.SelectSubjectById{
													{
														SubjectUuid: "",
													},
												},
												IncludeSubjects: &[]oscal.SelectSubjectById{
													{
														SubjectUuid: "",
													},
												},
											},
										},
										TaskUuid: "",
									},
								},
							},
						},
						RequiredAssets: &[]oscal.RequiredAsset{
							{
								Subjects: &[]oscal.SubjectReference{
									{
										SubjectUuid: "",
									},
								},
							},
						},
						Tasks: &[]oscal.Task{
							{
								AssociatedActivities: &[]oscal.AssociatedActivity{
									{
										ActivityUuid: "",
										ResponsibleRoles: &[]oscal.ResponsibleRole{
											{
												PartyUuids: nil,
												RoleId:     "",
											},
										},
										Subjects: []oscal.AssessmentSubject{
											{
												ExcludeSubjects: &[]oscal.SelectSubjectById{
													{
														SubjectUuid: "",
													},
												},
												IncludeSubjects: &[]oscal.SelectSubjectById{
													{
														SubjectUuid: "",
													},
												},
											},
										},
									},
								},
								Dependencies: &[]oscal.TaskDependency{
									{
										TaskUuid: "",
									},
								},
								ResponsibleRoles: &[]oscal.ResponsibleRole{
									{
										PartyUuids: nil,
										RoleId:     "",
									},
								},
								Subjects: &[]oscal.AssessmentSubject{
									{
										ExcludeSubjects: &[]oscal.SelectSubjectById{
											{
												SubjectUuid: "",
											},
										},
										IncludeSubjects: &[]oscal.SelectSubjectById{
											{
												SubjectUuid: "",
											},
										},
									},
								},
							},
						},
					},
				},
				RiskLog: &oscal.RiskLog{
					Entries: []oscal.RiskLogEntry{
						{
							LoggedBy: &[]oscal.LoggedBy{
								{
									PartyUuid: "",
									RoleId:    "",
								},
							},
							RelatedResponses: &[]oscal.RiskResponseReference{
								{
									RelatedTasks: &[]oscal.RelatedTask{
										{
											IdentifiedSubject: &oscal.IdentifiedSubject{
												SubjectPlaceholderUuid: "",
												Subjects: []oscal.AssessmentSubject{
													{
														ExcludeSubjects: &[]oscal.SelectSubjectById{
															{
																SubjectUuid: "",
															},
														},
														IncludeSubjects: &[]oscal.SelectSubjectById{
															{
																SubjectUuid: "",
															},
														},
													},
												},
											},
											ResponsibleParties: &[]oscal.ResponsibleParty{
												{
													PartyUuids: nil,
													RoleId:     "",
												},
											},
											Subjects: &[]oscal.AssessmentSubject{
												{
													ExcludeSubjects: &[]oscal.SelectSubjectById{
														{
															SubjectUuid: "",
														},
													},
													IncludeSubjects: &[]oscal.SelectSubjectById{
														{
															SubjectUuid: "",
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
				ThreatIds: &[]oscal.ThreatId{
					{
						Href:   "",
						ID:     "",
						System: "",
					},
				},
			},
		},
	}
	fmt.Println(res)
}
