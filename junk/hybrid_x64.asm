.code64

push {{.Reg.rax}}

{{if .Switch.A}}
mov {{.Reg.rax}}, {{.Reg.rbx}}
{{end}}

{{if .Switch.B}}
xor {{.Reg.rax}}, {{.Reg.rcx}}
{{end}}

{{if .Switch.C}}
xor {{.Reg.rax}}, {{.DWORD.D}}
{{end}}

{{if .Switch.D}}
mov {{.Reg.rax}}, {{.WORD.E}}
{{end}}

{{if .Switch.E}}
ror {{.Reg.rax}}, {{.Less32.A}}
xor {{.Reg.rax}}, {{.Reg.rdi}}
rol {{.Reg.rax}}, {{.Less32.B}}
{{end}}

pop {{.Reg.rax}}

