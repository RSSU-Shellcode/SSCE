.code64

push {{.Reg.rax}}

{{if .Switch.A}}
lea {{.Reg.rax}}, [{{.Reg.rbx}} + {{.BYTE.A}}]
{{end}}

{{if .Switch.B}}
lea {{.Reg.rax}}, [{{.Reg.rbx}} + {{.WORD.A}}]
{{end}}

{{if .Switch.C}}
lea {{.Reg.rax}}, [{{.Reg.rbx}} + {{.DWORD.A}}]
{{end}}

{{if .Switch.D}}
lea {{.Reg.rax}}, [{{.Reg.rbx}} + {{.QWORD.A}}]
{{end}}

pop {{.Reg.rax}}
