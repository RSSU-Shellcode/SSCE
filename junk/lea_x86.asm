.code32

push {{.Reg.eax}}

{{if .Switch.A}}
lea {{.Reg.eax}}, [{{.Reg.ebx}} + {{.BYTE.A}}]
{{end}}

{{if .Switch.B}}
lea {{.Reg.eax}}, [{{.Reg.ebx}} + {{.WORD.A}}]
{{end}}

{{if .Switch.C}}
lea {{.Reg.eax}}, [{{.Reg.ebx}} + {{.DWORD.A}}]
{{end}}

pop {{.Reg.eax}}
